// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/KeyActivationFlow.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // signingCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // OperationPhase enum
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Plugin/PluginTypes.h> // PINResult
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

// Result for a path that never reached the seam (capability gate, cancel, open
// failure, or an undelivered prompt): the key was not activated, and any
// transport-PIN bring-up state that led here is carried through unchanged.
CredentialOpResult nonSeamResult(CredentialOutcome outcome, std::optional<bool> pinActivated)
{
    CredentialOpResult result;
    result.outcome = outcome;
    result.keyActivated = false;
    result.pinActivated = pinActivated;
    return result;
}

// Map the LM PINResult onto the wire-facing CredentialOpResult. keyActivated is
// true only on Ok; every other LM outcome — including KeyActivationFailed, where
// VERIFY succeeded but the card-side ACTIVATE step failed — is preserved verbatim
// (its wire ErrorCode mapping is a later task's job). retriesLeft rides the
// payload and describes the PIN that was presented — here the SIGN PIN, the only
// PIN this flow prompts.
CredentialOpResult mapSeamResult(const LibreSCRS::Plugin::PINResult& pin, std::optional<bool> pinActivated)
{
    CredentialOpResult result;
    result.outcome = toCredentialOutcome(pin.outcome);
    result.retriesLeft = pin.retriesLeft;
    result.blocked = pin.blocked;
    result.keyActivated = (result.outcome == CredentialOutcome::Ok);
    result.pinActivated = pinActivated;
    return result;
}

} // namespace

CredentialOpResult runKeyActivation(KeyActivationFlowDeps deps)
{
    // Ground-truth card-reach: set true immediately BEFORE the seam call, so the
    // post-mutation cache-invalidation rule keys off whether the card was actually
    // contacted — NOT off the outcome the seam happened to return. An attempt that
    // reached the card drops this card's snapshot + identity/cert reads (never the
    // secret cache); a capability short-circuit, open failure, or cancel leaves them
    // intact.
    bool reachedCard = false;
    const CredentialOpResult result = [&]() -> CredentialOpResult {
        // Audit the request once. The SIGN-PIN consent prompt below records the
        // requester when it is reached, but the capability short-circuit returns
        // before any prompt, so without this line a not-activatable request would
        // leave no journald trace.
        log::infof("signing-key activation requested: requester={} reader=\"{}\" card={} credential={}",
                   deps.requester.empty() ? "unknown" : deps.requester, deps.reader, deps.cardKey, deps.record.id);

        // Capability gate, BEFORE any session or prompt: a card that cannot activate
        // its signing key answers Unsupported without ever raising a PIN dialog
        // (prompt-before-capability is forbidden).
        if (!deps.record.keyActivatable) {
            return nonSeamResult(CredentialOutcome::Unsupported, deps.pinActivated);
        }

        if (deps.token.isCancelled()) {
            return nonSeamResult(CredentialOutcome::UserCancelled, deps.pinActivated);
        }

        // Open the held (reused) session and install the channel credential provider,
        // shared with the read flows via FlowPrelude: the plugin invokes it on a
        // secure-channel cache miss (CAN-once for PACE cards) inside activateSigningKey.
        // The SIGN PIN is NOT served through this provider — it is prompted below and
        // handed to the seam explicitly (the frozen seam takes it as an argument).
        auto opened = FlowPrelude::openSession(deps.holder, deps.token);
        if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
            return nonSeamResult(CredentialOutcome::UserCancelled, deps.pinActivated);
        }
        if (opened.status != FlowPrelude::OpenStatus::Ok) {
            // No ErrorCode rides a CredentialOpResult; classify the open failure onto
            // the outcome vocabulary. A lost/absent card is CardRemoved; anything else
            // is the unclassified-failure outcome (mapped to CommunicationError on the
            // wire by the outcome->code overload).
            const auto outcome = (opened.code == ErrorCode::CardRemoved) ? CredentialOutcome::CardRemoved
                                                                         : CredentialOutcome::Unspecified;
            return nonSeamResult(outcome, deps.pinActivated);
        }
        auto session = std::move(opened.session);
        // Activation drives the signing key, so route across the signing-capable
        // subset (PKI + PinManagement); the seam applies lazy fallback across it.
        // The snapshot's listing plugin goes FIRST: the addressed record belongs
        // to that plugin's listing, so another candidate must not intercept the
        // activation.
        auto signCands = prioritizeCandidate(signingCandidates(opened.candidates), deps.listPluginId);

        // Set true by the provider iff a channel prompt (CAN) fails because the
        // prompter UI broke / was absent; wired for parity with the read flows. On
        // this path a broken channel prompt surfaces as the seam's own failure
        // outcome, so the flag is not separately consumed here.
        auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
        const auto providerGuard = FlowPrelude::installScopedReadProvider(
            session, FlowPrelude::makeReadCredentialProvider(deps.cache, deps.prompter, deps.serializer, deps.phaseSink,
                                                             deps.cardKey, deps.requester, deps.artifact, deps.token,
                                                             prompterFailed));

        if (deps.token.isCancelled()) {
            return nonSeamResult(CredentialOutcome::UserCancelled, deps.pinActivated);
        }

        // Prompt the operational SIGN PIN once, through the single agent-wide prompt
        // slot. It is a consent secret: uncached, prompted every time, and never
        // crosses as an fd — it lives only as a Secure::String within this scope.
        deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        PromptOptions opts;
        opts.requester = deps.requester;
        opts.artifact = deps.artifact;
        if (const auto mn = deps.record.minLength; mn && *mn > 0) {
            opts.minLength = static_cast<std::uint32_t>(*mn);
        }
        if (const auto mx = deps.record.maxLength; mx && *mx > 0) {
            opts.maxLength = static_cast<std::uint32_t>(*mx);
        }
        SerializingPrompter gated{deps.serializer, deps.prompter, deps.token};
        const auto prompt = gated.requestPin(opts);
        if (prompt.status == PromptStatus::Cancelled) {
            return nonSeamResult(CredentialOutcome::UserCancelled, deps.pinActivated);
        }
        if (prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) {
            // The prompter did not deliver the required secret (UI broke / absent).
            // On the agent path the provider IS the prompter, so this is MissingFields.
            return nonSeamResult(CredentialOutcome::MissingFields, deps.pinActivated);
        }

        // SIGN PIN collected: arm the watchdog and verify+activate on the card.
        deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
        reachedCard = true; // ground truth: the card is now being contacted
        const auto pin = deps.credentials.activateSigningKey(*session, signCands, *prompt.secret);
        // A card pulled mid-activation: the seam's return is unreliable. Report
        // transport loss (mirroring CredentialListFlow's post-list isDead check);
        // keyActivated stays false and the pinActivated continuation is carried
        // through unchanged. reachedCard stays true, so the possibly-partial
        // activation still drops the stale snapshot below.
        if (session->isDead()) {
            CredentialOpResult removed;
            removed.outcome = CredentialOutcome::CardRemoved;
            removed.keyActivated = false;
            removed.pinActivated = deps.pinActivated;
            return removed;
        }
        return mapSeamResult(pin, deps.pinActivated);
    }();

    // Invalidate on card-reach ground truth, not on the outcome classifier: any
    // seam contact (including a mid-op CardRemoved) drops this card's snapshot +
    // identity/cert reads; the CAN/MRZ secret cache is deliberately never touched.
    if (reachedCard) {
        deps.snapshotCache.invalidate(deps.cardKey);
        deps.cardReadCache.invalidate(deps.cardKey);
    }
    return result;
}

} // namespace LibreSCRS::Agent::Operations
