// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/RawCryptoFlow.h>

#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // signingCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Secure/String.h>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

RawCryptoFlow::Result makeError(RawCryptoFlow::Outcome outcome, std::string msgFallback)
{
    return RawCryptoFlow::Result{.outcome = outcome, .bytes = {}, .msgFallback = std::move(msgFallback)};
}

RawCryptoFlow::Result makeCancelled()
{
    return RawCryptoFlow::Result{.outcome = RawCryptoFlow::Outcome::Cancelled, .bytes = {}, .msgFallback = "cancelled"};
}

// LmRawCrypto hermetic status -> the flow's hermetic Outcome. AuthFailed is kept
// distinct so the host can revoke the lease + raise AuthFailed on the wire even
// though the current LM raw-sign/decipher outcome folds auth failures into
// CardError (see LmRawCrypto.h) — this mapping is ready for when LM grows the
// distinction.
RawCryptoFlow::Outcome mapStatus(RawCryptoStatus s) noexcept
{
    switch (s) {
    case RawCryptoStatus::Ok:
        return RawCryptoFlow::Outcome::Ok;
    case RawCryptoStatus::KeyNotFound:
        return RawCryptoFlow::Outcome::KeyNotFound;
    case RawCryptoStatus::AuthFailed:
        return RawCryptoFlow::Outcome::AuthFailed;
    case RawCryptoStatus::NotSupported:
        return RawCryptoFlow::Outcome::NotSupported;
    case RawCryptoStatus::CardError:
        return RawCryptoFlow::Outcome::CardError;
    }
    return RawCryptoFlow::Outcome::CardError;
}

} // namespace

RawCryptoFlow::RawCryptoFlow(RawCryptoFlowDeps deps) : m_deps(std::move(deps)) {}

RawCryptoFlow::Result RawCryptoFlow::runSign(std::span<const std::uint8_t> input)
{
    return run(Op::Sign, input);
}

RawCryptoFlow::Result RawCryptoFlow::runDecrypt(std::span<const std::uint8_t> ciphertext)
{
    return run(Op::Decrypt, ciphertext);
}

RawCryptoFlow::Result RawCryptoFlow::run(Op op, std::span<const std::uint8_t> bytes)
{
    // Open the held session (shared with the read/sign flows via FlowPrelude).
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeError(Outcome::CardError, std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    auto candidates = std::move(opened.candidates);
    auto signCands = signingCandidates(candidates);

    // Install a credential provider for CHANNEL-ESTABLISHMENT secrets only
    // (CAN/MRZ for travel-document cards), routed through the cache exactly like
    // SignFlow. The signing PIN is NOT collected here: unlike the AdES path
    // (where libresign's Pkcs11Token drives an internal PIN callback), the raw
    // CardPlugin::sign / decipher backends do NOT consult the installed provider
    // — they call sc_pkcs15_compute_signature / decipher directly. So the PIN
    // must be collected up front by THIS flow and verified on-card by the
    // terminal op (plugin->verifyPIN) before the PSO; otherwise the on-card op
    // fails security-status and the prompter never fires. PIN/CAN are
    // collected ONLY by the agent prompter — never off the RPC socket.
    auto& cache = m_deps.cache;
    auto& prompter = m_deps.prompter;
    auto& serializer = m_deps.serializer;
    auto& phaseSink = m_deps.phaseSink;
    const std::string cardKey = m_deps.cardKey;
    const std::string requester = m_deps.requester;
    const LibreSCRS::CancelToken token = m_deps.token;

    // Only channel-establishment secrets (CAN/MRZ) reach the installed provider;
    // the signing PIN is collected by the flow directly below. This is exactly
    // the read flows' provider (CAN/MRZ routed through the cache, AwaitingConsent
    // on a real prompt), so reuse FlowPrelude::makeReadCredentialProvider rather
    // than re-rolling the lambda. A CAN/MRZ prompter failure surfaces through the
    // failed channel establishment as CardError below (the raw path has no
    // PrompterError outcome — the flag the helper requires is write-only here).
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    LibreSCRS::Auth::CredentialProvider provider = FlowPrelude::makeReadCredentialProvider(
        cache, prompter, serializer, phaseSink, cardKey, requester, /*artifact=*/"pkcs11", token, prompterFailed);
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow, so the guard resets the session's provider to a stateless no-op
    // on run()-scope exit (see FlowPrelude::installScopedReadProvider).
    const auto providerGuard = FlowPrelude::installScopedReadProvider(session, std::move(provider));

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }

    // Collect the PIN-as-consent from the agent prompter + drive the watchdog
    // phases. Returns {Ok, pin} on success; on cancel/prompter-failure returns a
    // non-Ok PromptStatus and the caller maps it. The PIN is owned by the caller's
    // Secure::String and cleansed when it drops.
    auto collectPin = [&]() -> std::pair<PromptStatus, std::optional<LibreSCRS::Secure::String>> {
        SerializingPrompter gated{serializer, prompter, token};
        PromptOptions opts;
        opts.requester = requester;
        opts.artifact = "pkcs11";
        phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        auto prompt = gated.requestPin(opts);
        if (prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) {
            return {prompt.status, std::nullopt};
        }
        // PIN collected: arm the watchdog (Authenticating) and surface the on-card
        // op phase (Signing — the wire-stable enum has no separate Decrypting
        // phase; Signing covers the on-card PSO for both ops). Both happen AFTER
        // the human, so the unbounded consent wait is never timed.
        phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
        phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Signing));
        return {PromptStatus::Ok, std::move(*prompt.secret)};
    };

    // PIN-as-consent: collect + verify the PIN on the FIRST op of a lease only.
    // A subsequent op within the same lease (isPinVerified() == true) skips the
    // prompt and relies on the persisted on-card verified state of the held
    // channel — the PIN itself is NEVER cached, only the lease-scoped boolean.
    // When the host wires no lease state, isPinVerified is empty -> we prompt +
    // verify every op (fail-safe, never caches).
    const bool alreadyVerified = m_deps.isPinVerified && m_deps.isPinVerified();
    std::optional<LibreSCRS::Secure::String> pin;
    if (!alreadyVerified) {
        auto [status, secret] = collectPin();
        if (status == PromptStatus::Cancelled) {
            // A user-declined consent is never a card fault.
            return makeCancelled();
        }
        if (status != PromptStatus::Ok || !secret.has_value()) {
            // A broken/absent prompter (not the card) prevented PIN collection.
            return makeError(Outcome::CardError, "pkcs11: prompter unavailable for PIN consent");
        }
        pin = std::move(secret);
    } else {
        // Verified lease: no human consent, just the on-card PSO phase.
        phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Signing));
    }

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }

    // Terminal per-family raw op (CardPlugin::verifyPIN + sign / decipher inside
    // the production seam). A non-null @p pin tells the op to verify the PIN
    // on-card before the PSO (first op of a lease); a null @p pin means the held
    // channel is already verified and the op signs/deciphers directly.
    const RawCryptoOp& terminal = (op == Op::Sign) ? m_deps.signOp : m_deps.decryptOp;
    const LibreSCRS::Secure::String* pinPtr = pin ? &*pin : nullptr;
    RawCryptoResult result = terminal(signCands, m_deps.certId, bytes, pinPtr, *session, m_deps.token);
    Outcome outcome = mapStatus(result.status);

    // DESYNC RECOVERY: the lease idle-timeout (10 min) outlives the
    // holder's proactive idle-close (~45s), so a verify-SKIPPED op can run against
    // a FRESH, unverified channel that was silently reacquired under a still-
    // "verified" lease. The on-card PSO then fails security-status, which the
    // current LM ABI folds to CardError (NOT AuthFailed — see LmRawCrypto.h), so
    // the host's AuthFailed-only revoke never fires and the lease wedges forever
    // (the ssh-agent idle pattern). When a verify-skipped op returns CardError we
    // cannot tell verify-state-loss from a genuine card fault (the ABI fold), so
    // the pragmatic recovery is: clear the lease's verified state, raise ONE fresh
    // PIN prompt, re-verify + retry the op ONCE. If the retry (now with a real
    // verify) still fails we surface the error — one extra prompt at worst.
    if (alreadyVerified && outcome == Outcome::CardError) {
        if (m_deps.clearPinVerified) {
            m_deps.clearPinVerified();
        }
        if (m_deps.token.isCancelled()) {
            return makeCancelled();
        }
        auto [status, secret] = collectPin();
        if (status == PromptStatus::Cancelled) {
            return makeCancelled();
        }
        if (status != PromptStatus::Ok || !secret.has_value()) {
            return makeError(Outcome::CardError, "pkcs11: prompter unavailable for PIN consent");
        }
        if (m_deps.token.isCancelled()) {
            return makeCancelled();
        }
        pin = std::move(secret);
        // Retry ONCE with a real verify (non-null PIN). No further retry: a
        // second failure is surfaced below.
        result = terminal(signCands, m_deps.certId, bytes, &*pin, *session, m_deps.token);
        outcome = mapStatus(result.status);
        if (outcome == Outcome::Ok && m_deps.markPinVerified) {
            // The retry re-verified + succeeded: re-arm the lease boolean.
            m_deps.markPinVerified();
        }
    } else if (outcome == Outcome::Ok && !alreadyVerified && m_deps.markPinVerified) {
        // First op of the lease succeeded (verify + PSO): remember the verified
        // state so subsequent ops on this held channel skip the re-prompt. Only
        // the boolean is remembered — the PIN above is cleansed when `pin` drops.
        m_deps.markPinVerified();
    }

    if (outcome == Outcome::AuthFailed) {
        // A wrong PIN must not poison a later read's cached CAN; the PIN is never
        // cached, but evict the PACE secret so a card swap / retry re-establishes
        // cleanly. Mirrors SignFlow's eviction.
        m_deps.cache.invalidate(m_deps.cardKey);
        session->clearCachedPaceCredentials();
    }
    if (outcome != Outcome::Ok) {
        return makeError(outcome, "pkcs11: raw crypto op failed");
    }

    return RawCryptoFlow::Result{.outcome = Outcome::Ok, .bytes = std::move(result.bytes), .msgFallback = "ok"};
}

} // namespace LibreSCRS::Agent::Operations
