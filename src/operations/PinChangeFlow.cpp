// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/PinChangeFlow.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // filterByCapability, CandidateList
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h> // gate the change modal through the single prompt slot
#include <LibreSCRS/Agent/OperationPhase.h>                 // OperationPhase
#include <LibreSCRS/Plugin/CardPlugin.h>                    // CardCapabilities
#include <LibreSCRS/Plugin/PluginTypes.h>                   // PINResult

#include <atomic>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

constexpr std::string_view kVerbChange = "change";
constexpr std::string_view kVerbUnblock = "unblock";
constexpr std::string_view kVerbActivatePin = "activate_pin";

[[nodiscard]] bool isKnownVerb(std::string_view verb) noexcept
{
    return verb == kVerbChange || verb == kVerbUnblock || verb == kVerbActivatePin;
}

// Resolve the addressed record from the latest snapshot; nullptr if the snapshot
// is absent or carries no record with this id.
[[nodiscard]] const CredentialRecord* findRecord(const CredentialSnapshot* snapshot, const std::string& pinId)
{
    if (snapshot == nullptr) {
        return nullptr;
    }
    for (const auto& record : snapshot->records) {
        if (record.id == pinId) {
            return &record;
        }
    }
    return nullptr;
}

[[nodiscard]] CredentialOpResult resultWith(CredentialOutcome outcome)
{
    CredentialOpResult r;
    r.outcome = outcome;
    return r;
}

// Map a completed LM PINResult onto the wire result. retriesLeft describes the
// PIN presented (the old PIN for a change); blocked mirrors the card flag.
[[nodiscard]] CredentialOpResult mapPinResult(const LibreSCRS::Plugin::PINResult& lm)
{
    CredentialOpResult r;
    r.outcome = toCredentialOutcome(lm.outcome);
    r.retriesLeft = lm.retriesLeft;
    r.blocked = lm.blocked;
    return r;
}

// Session-open failures reach the credential vocabulary as: a card that is gone
// (NoCardPresent -> ErrorCode::CardRemoved) -> the agent-assigned CardRemoved
// outcome; any other open failure -> the non-card Unspecified. A pre-seam open
// failure never reached the card, so nothing on it moved (and the caches stay
// intact — reachedCard is still false here). This mirrors KeyActivationFlow's
// identical classification. Cancellation is handled before this is called.
[[nodiscard]] CredentialOutcome openFailureOutcome(ErrorCode code) noexcept
{
    return code == ErrorCode::CardRemoved ? CredentialOutcome::CardRemoved : CredentialOutcome::Unspecified;
}

} // namespace

std::expected<void, EntryError> validatePinManageRequest(const PinManageRequest& r, const CredentialSnapshot* snapshot)
{
    if (!isKnownVerb(r.verb)) {
        return std::unexpected(EntryError::UnknownVerb);
    }
    // `activateKey` only carries meaning for the "activate_pin" verb.
    if (r.activateKey && r.verb != kVerbActivatePin) {
        return std::unexpected(EntryError::InvalidCombination);
    }
    // Mutations address a record by an id minted by a prior ListCredentials. A
    // client that never listed (null snapshot) or names an unknown id is
    // rejected here rather than triggering an implicit list — an implicit list
    // could prompt for CAN inside a call the user never framed as a read.
    const CredentialRecord* record = findRecord(snapshot, r.pinId);
    if (record == nullptr) {
        return std::unexpected(EntryError::UnknownCredential);
    }
    // The seam addresses the card by the record's LABEL (ids are agent-local).
    // Two same-label records are distinct ids on the wire but indistinguishable
    // at the seam — the plugin would have to guess which PIN the user meant, so
    // a mutation addressing a non-unique label is rejected at entry.
    for (const auto& other : snapshot->records) {
        if (&other != record && other.label == record->label) {
            return std::unexpected(EntryError::AmbiguousCredential);
        }
    }
    return {};
}

CredentialOpResult runPinManage(PinManageFlowDeps& deps, const PinManageRequest& request)
{
    // Ground-truth card-reach: set true immediately BEFORE the seam call, so the
    // post-mutation cache-invalidation rule keys off whether the card was actually
    // contacted — NOT off the outcome the seam happened to return. An attempt that
    // reached the card drops this card's snapshot + identity/cert reads (never the
    // secret cache); an open failure or a prompter-only cancel leaves them intact.
    bool reachedCard = false;
    const CredentialOpResult result = [&]() -> CredentialOpResult {
        const CredentialRecord* record = findRecord(deps.snapshot, request.pinId);
        // Entry validation (validatePinManageRequest) runs first and rejects an
        // unknown/absent record, so a live Operation only ever runs for a resolvable
        // record. Fail closed if that invariant is somehow violated.
        if (record == nullptr) {
            return resultWith(CredentialOutcome::Unspecified);
        }

        // Capability gate, BEFORE any session or prompt (prompt-before-capability
        // is forbidden — mirroring KeyActivationFlow's keyActivatable gate). The
        // addressed record's OWN capability flags decide, not the verb string: a
        // record the card cannot unblock / activate / change answers Unsupported
        // without ever raising a dialog.
        if (request.verb == kVerbUnblock && !record->unblockable) {
            return resultWith(CredentialOutcome::Unsupported);
        }
        if (request.verb == kVerbActivatePin && !record->activatable) {
            return resultWith(CredentialOutcome::Unsupported);
        }
        if (request.verb == kVerbChange && !record->canChange) {
            return resultWith(CredentialOutcome::Unsupported);
        }

        // Increment #1 wires only `change`. A capable unblock/activate_pin record
        // has no prompter kind or seam entry point yet — driving the LM unblock/
        // activate entry points with empty secrets could burn PUK budget against a
        // future plugin — so those verbs answer Unsupported WITHOUT prompting until
        // increment #2 adds the real collection path. (`change` on a canChange
        // record falls through to the prompt + seam below.)
        if (request.verb != kVerbChange) {
            return resultWith(CredentialOutcome::Unsupported);
        }

        // --- verb == "change" --------------------------------------------------
        // Acquire the held session first (mirrors the sibling read flows). The
        // ListCredentials the client had to run already established and cached the
        // PACE channel, so this reuses it. A card removed since then surfaces as an
        // open failure -> CardRemoved, before any secret is collected.
        auto opened = FlowPrelude::openSession(deps.holder, deps.token);
        if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
            return resultWith(CredentialOutcome::UserCancelled);
        }
        if (opened.status != FlowPrelude::OpenStatus::Ok) {
            return resultWith(openFailureOutcome(opened.code));
        }
        auto session = std::move(opened.session);
        // Route the change across the PIN-management-capable candidate subset (the
        // seam resolves the exact PIN by the record's label; empty here is fine —
        // an all-unsupported list answers Unsupported). The snapshot's listing
        // plugin goes FIRST: the mutation addresses a label minted by that
        // plugin's listing, so another candidate must not intercept it.
        const auto pinCandidates = prioritizeCandidate(
            filterByCapability(opened.candidates, LibreSCRS::Plugin::CardCapabilities::PinManagement),
            deps.snapshot->listPluginId);

        // Install the read credential provider so the plugin's changePIN can
        // self-activate the secure channel (CAN on a PACE card) on a cache miss.
        // The PIN pair itself is NOT sourced through this provider — it is prompted
        // below and passed as arguments. The scope guard resets the provider to a
        // no-op on exit (the session outlives this flow; see FlowPrelude).
        auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
        const auto providerGuard = FlowPrelude::installScopedReadProvider(
            session, FlowPrelude::makeReadCredentialProvider(deps.cache, deps.prompter, deps.serializer, deps.phaseSink,
                                                             deps.cardKey, deps.requester, deps.artifact, deps.token,
                                                             prompterFailed));

        if (deps.token.isCancelled()) {
            return resultWith(CredentialOutcome::UserCancelled);
        }

        // Collect the current + new PIN in one modal. The confirm re-entry never
        // leaves the prompter; both secrets return as independently-cleansed
        // Secure::Strings (never an fd here). The record's length bounds size the
        // fields; its label names the PIN role. The prompt is routed through the
        // agent-wide gate (a gated SerializingPrompter, mirroring KeyActivationFlow)
        // so the change modal holds the single live-prompt slot and can never stack
        // on top of another reader's concurrent PIN/CAN dialog.
        deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        PromptOptions opts;
        opts.requester = deps.requester;
        opts.artifact = deps.artifact;
        // Title stays EMPTY: the prompter renders its own localized action
        // title ("Change PIN"). What the change acts on rides the dedicated
        // display labels — the PIN role from the addressed record, the card/
        // token identity from the flow's reader name.
        opts.cardLabel = deps.reader;
        opts.pinLabel = record->label;
        if (record->minLength) {
            opts.minLength = static_cast<std::uint32_t>(*record->minLength);
        }
        if (record->maxLength) {
            opts.maxLength = static_cast<std::uint32_t>(*record->maxLength);
        }
        SerializingPrompter gated{deps.serializer, deps.prompter, deps.token};
        const auto prompt = gated.requestPinChange(opts);
        if (prompt.status == PromptStatus::Cancelled) {
            // A genuine user dismissal: do NOT touch the card. No card interaction
            // happened, so no retry counter is at risk.
            return resultWith(CredentialOutcome::UserCancelled);
        }
        if (prompt.status != PromptStatus::Ok || !prompt.current || !prompt.newPin) {
            // The prompter did not deliver the required secrets (UI broke / absent
            // on the bus, or the reply decoded without both secrets). On the agent
            // path the provider IS the prompter, so this is MissingFields — mapped
            // to ErrorCode::PrompterError on the wire (KeyActivationFlow's exact
            // vocabulary); Cancelled is reserved for a real user cancel. Still no
            // card contact.
            return resultWith(CredentialOutcome::MissingFields);
        }

        // Drive the seam. The record's label selects the exact PIN (LM resolves it
        // precisely — no silent fallback). The LM PINResult maps straight onto the
        // uniform mutation result, retriesLeft describing the presented (old) PIN.
        deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
        reachedCard = true; // ground truth: the card is now being contacted
        const auto lmResult =
            deps.credentialManager.changePIN(*session, pinCandidates, record->label, *prompt.current, *prompt.newPin);
        // A card pulled mid-changePIN: the seam's return is unreliable. Classify as
        // transport loss (mirroring CredentialListFlow's post-list isDead check).
        // reachedCard stays true, so the possibly-partial change still drops the
        // stale snapshot below.
        if (session->isDead()) {
            return resultWith(CredentialOutcome::CardRemoved);
        }
        return mapPinResult(lmResult);
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
