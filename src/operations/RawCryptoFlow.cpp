// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/RawCryptoFlow.h>

#include <LibreSCRS/Agent/cache/AttemptContext.h>
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
#include <variant>

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

// LmRawCrypto hermetic status -> the flow's hermetic Outcome. AuthFailed (the
// card refused the PIN presented for this operation) is kept distinct so the
// host can revoke the lease + raise AuthFailed on the wire.
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
    case RawCryptoStatus::ConsentRequired:
        // Only meaningful for an op given no PIN, which run() handles before
        // mapping. Reaching here means an op with a PIN answered it: fail closed.
        return RawCryptoFlow::Outcome::CardError;
    case RawCryptoStatus::InvalidInput:
        return RawCryptoFlow::Outcome::InvalidInput;
    }
    return RawCryptoFlow::Outcome::CardError;
}

// A preflight refusal as the flow's outcome. Ok without a key is a broken
// preflight, never a pass.
RawCryptoFlow::Outcome refusalOutcome(RawCryptoStatus s) noexcept
{
    return s == RawCryptoStatus::Ok ? RawCryptoFlow::Outcome::CardError : mapStatus(s);
}

} // namespace

RawCryptoFlow::RawCryptoFlow(RawCryptoFlowDeps deps) : m_deps(std::move(deps)) {}

RawCryptoFlow::Result RawCryptoFlow::runSign(Mechanism mechanism, std::span<const std::uint8_t> input)
{
    return run(Op::Sign, mechanism, input);
}

RawCryptoFlow::Result RawCryptoFlow::runDecrypt(Mechanism mechanism, std::span<const std::uint8_t> ciphertext)
{
    return run(Op::Decrypt, mechanism, ciphertext);
}

RawCryptoFlow::Result RawCryptoFlow::run(Op op, Mechanism mechanism, std::span<const std::uint8_t> bytes)
{
    // A cold lease always prompts. Charge that prompt before anything is
    // opened, so a refused caller costs no session, no channel, no card I/O
    // (an open that then fails, or a cancel before the prompt, still counts).
    // No gate wired is a refusal: a host that forgets its budget gets no
    // prompts rather than unlimited ones.
    const auto promptAllowed = [this] { return m_deps.allowPrompt && m_deps.allowPrompt(); };
    const bool alreadyVerified = m_deps.isPinVerified && m_deps.isPinVerified();
    if (!alreadyVerified && !promptAllowed()) {
        return makeError(Outcome::RateLimited, "pkcs11: PIN prompt refused by the per-caller limit");
    }

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
    // must be collected up front by THIS flow and handed to the terminal op,
    // which deposits it with the plugin for the card to verify inside the
    // operation's own transaction; otherwise the on-card op fails
    // security-status and the prompter never fires. PIN/CAN are
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
    // Per-operation retry context, captured HERE at the top of run() -- never
    // later (see IdentityReadFlow's identical field for the full rationale).
    auto attempts = std::make_shared<AttemptContext>(cache.refusalGenerationFor(cardKey));
    LibreSCRS::Auth::CredentialProvider provider =
        FlowPrelude::makeReadCredentialProvider(cache, prompter, serializer, phaseSink, cardKey, requester,
                                                /*artifact=*/"pkcs11", token, attempts, prompterFailed);
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow, so the guard resets the session's provider to a stateless no-op
    // on run()-scope exit (see FlowPrelude::installScopedReadProvider).
    const auto providerGuard = FlowPrelude::installScopedReadProvider(session, std::move(provider));

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }

    // Checked after the cold prompt was charged (above) and before any PIN is
    // asked for: the key is resolved off the card in the reader now -- the
    // read the operation then uses -- and a mechanism of the other family, an
    // input of the wrong length or a point off the key's curve is refused here.
    // No PIN prompt, no use of the key, and the lease stays as it was. The read
    // is the same public one CertDer and PublicKey make; on a cold PACE channel
    // it may need the CAN, which normally comes from the credential cache.
    // No preflight wired is a refusal (CardError), like an unwired prompt gate.
    const auto runPreflight = [&] {
        return m_deps.preflight ? m_deps.preflight(signCands, m_deps.certId, mechanism, bytes, *session)
                                : RawCryptoPreflight{};
    };
    RawCryptoPreflight checked = runPreflight();
    if (checked.status != RawCryptoStatus::Ok || !checked.key.has_value()) {
        return makeError(refusalOutcome(checked.status), "pkcs11: request refused before any PIN prompt");
    }

    // Collect the PIN-as-consent from the agent prompter + drive the watchdog
    // phases. Returns {Ok, pin} on success; on cancel/prompter-failure returns a
    // non-Ok PromptStatus and the caller maps it. The PIN is owned by the caller's
    // Secure::String and cleansed when it drops.
    auto collectPin = [&]() -> std::pair<PromptStatus, std::optional<LibreSCRS::Secure::String>> {
        SerializingPrompter gated{serializer, prompter, token, cardKey};
        PromptOptions opts;
        opts.requester = requester;
        opts.artifact = "pkcs11";
        phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        // SerializingPrompter reports an empty answer as Cancelled, so a PIN
        // that gets past here is never empty.
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

    // Every PIN prompt this flow raises is charged to the host's per-caller
    // budget before it is raised: the cold one at the top of run(), a
    // re-prompt here (@p charge). A refusal raises nothing. Yields the PIN, or
    // the Result to hand back as it is.
    auto obtainPin = [&](bool charge) -> std::variant<LibreSCRS::Secure::String, Result> {
        if (charge && !promptAllowed()) {
            return makeError(Outcome::RateLimited, "pkcs11: PIN prompt refused by the per-caller limit");
        }
        auto [status, secret] = collectPin();
        if (status == PromptStatus::Cancelled) {
            // A user-declined consent is never a card fault.
            return makeCancelled();
        }
        if (status != PromptStatus::Ok || !secret.has_value()) {
            // A broken/absent prompter (not the card) prevented PIN collection.
            return makeError(Outcome::CardError, "pkcs11: prompter unavailable for PIN consent");
        }
        return std::move(*secret);
    };

    // PIN-as-consent: collect the PIN on the FIRST op of a lease, and on every
    // op with a key the card marks for consent per operation. Any other
    // subsequent op within the same lease (isPinVerified() == true) skips the
    // prompt; it rides the card's verified state on the held session, or for
    // an ordinary key the PIN the plugin keeps deposited for that session. The
    // flow itself keeps only the lease-scoped boolean, and the lease decides
    // who may use what the plugin holds. When the host wires no lease state,
    // isPinVerified is empty -> we prompt every op (fail-safe). alreadyVerified
    // was read, and the cold prompt charged, at the top of run().
    std::optional<LibreSCRS::Secure::String> pin;
    if (!alreadyVerified) {
        auto got = obtainPin(/*charge=*/false);
        if (auto* done = std::get_if<Result>(&got)) {
            return std::move(*done);
        }
        pin = std::move(std::get<LibreSCRS::Secure::String>(got));
    } else {
        // Verified lease: no human consent, just the on-card PSO phase.
        phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Signing));
    }

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }

    // Terminal per-family raw op (PIN deposit + sign / decipher inside the
    // production seam). A non-null @p pin is presented by the plugin in the
    // operation's own card transaction (first op of a lease); a null @p pin
    // means the held channel is already verified and the op signs/deciphers
    // directly -- unless the card marks the key for consent per operation,
    // which the op answers with ConsentRequired before using the key.
    const RawCryptoOp& terminal = (op == Op::Sign) ? m_deps.signOp : m_deps.decryptOp;
    const LibreSCRS::Secure::String* pinPtr = pin ? &*pin : nullptr;
    RawCryptoResult result = terminal(*checked.key, mechanism, bytes, pinPtr, *session, m_deps.token);
    Outcome outcome = mapStatus(result.status);

    // Two reasons a verify-skipped op needs the PIN after all, one retry for both:
    //  * the card marks this key for consent per operation (ConsentRequired;
    //    no PIN was presented) -- the lease's verified state is right for the
    //    card's other keys, so it stays;
    //  * DESYNC RECOVERY: the lease idle-timeout (10 min) outlives the holder's
    //    idle-close (~45 s), so a verify-skipped op can meet a fresh, unverified
    //    channel -- or, after an op with a key the card marks, a plugin that no
    //    longer holds the ordinary key's PIN. The card's security-status
    //    failure surfaces as CardError, which cannot be told from a genuine
    //    card fault, so the verified state is cleared, the PIN asked for once
    //    more and the op retried ONCE. A second failure is surfaced below: one
    //    extra prompt at worst, never a wedged lease.
    //    A plugin refusal that repeats on every try (a key handle that names
    //    two keys, a reply that does not verify) is CardError too, and costs
    //    the same one prompt; whatever can be decided before the card -- the
    //    key's family, the input's length, an RSA mechanism the key's card
    //    does not take -- the preflight refuses before the first prompt.
    const bool consentAsked = alreadyVerified && result.status == RawCryptoStatus::ConsentRequired;
    const bool channelLost = alreadyVerified && !consentAsked && outcome == Outcome::CardError;
    if (consentAsked || channelLost) {
        if (channelLost && m_deps.clearPinVerified) {
            m_deps.clearPinVerified();
        }
        if (m_deps.token.isCancelled()) {
            return makeCancelled();
        }
        if (channelLost) {
            // A fresh channel: resolve the key on it again, as the first try did.
            checked = runPreflight();
            if (checked.status != RawCryptoStatus::Ok || !checked.key.has_value()) {
                return makeError(refusalOutcome(checked.status), "pkcs11: request refused before any PIN prompt");
            }
        }
        auto got = obtainPin(/*charge=*/true);
        if (auto* done = std::get_if<Result>(&got)) {
            return std::move(*done);
        }
        if (m_deps.token.isCancelled()) {
            return makeCancelled();
        }
        pin = std::move(std::get<LibreSCRS::Secure::String>(got));
        result = terminal(*checked.key, mechanism, bytes, &*pin, *session, m_deps.token);
        outcome = mapStatus(result.status);
        if (outcome == Outcome::Ok && !result.alwaysAuthenticate && m_deps.markPinVerified) {
            // The retry presented the PIN and succeeded: re-arm the lease
            // boolean -- never for a key the card marks. The human may have
            // spent minutes in that consent prompt while the lease was reset
            // (re-grant, a context-specific login); the card may still hold
            // the PIN just presented, and arming here would let the next
            // ordinary-key op sign with no prompt after an explicit reset.
            m_deps.markPinVerified();
        }
    } else if (outcome == Outcome::Ok && !alreadyVerified && !result.alwaysAuthenticate && m_deps.markPinVerified) {
        // First op of the lease succeeded (PIN + PSO): remember the verified
        // state so subsequent ops of the lease skip the re-prompt -- unless the
        // card marks this key for consent per operation. What carries that
        // state is the card, on a session the holder keeps open, or the
        // ordinary key's PIN the plugin keeps deposited for that session --
        // either can be lost while the lease lives, which is why
        // clearPinVerified above has to exist. The flow's own copy of the PIN
        // is cleansed when `pin` drops.
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
