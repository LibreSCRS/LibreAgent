// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/SignFlow.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // signingCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Agent/operations/SignatureParams.h> // isQualifiedSignLevel
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

SignFlow::Result makeError(ErrorCode code, std::string msgKey, std::string msgFallback)
{
    return SignFlow::Result{
        .outcome = SignFlow::Outcome::Error,
        .code = code,
        .signedDocumentBytes = {},
        .resolvedFormat = {},
        .resolvedLevel = {},
        .tsaUsed = false,
        .chainComplete = false,
        .candidates = {},
        .msgKey = std::move(msgKey),
        .msgFallback = std::move(msgFallback),
    };
}

SignFlow::Result makeCancelled()
{
    return SignFlow::Result{
        .outcome = SignFlow::Outcome::Cancelled,
        .code = ErrorCode::None,
        .signedDocumentBytes = {},
        .resolvedFormat = {},
        .resolvedLevel = {},
        .tsaUsed = false,
        .chainComplete = false,
        .candidates = {},
        .msgKey = "op.cancelled",
        .msgFallback = "Operation cancelled",
    };
}

// SignOutcome status -> wire ErrorCode (the new sign codes 11-17 plus the
// shared auth/card/comm codes). Kept local to SignFlow per the append-only
// ErrorTaxonomy discipline (the existing typed overloads stay untouched).
ErrorCode mapSignStatus(SignOutcome::Status s) noexcept
{
    switch (s) {
    case SignOutcome::Status::Ok:
        return ErrorCode::None;
    case SignOutcome::Status::KeyNotFound:
        return ErrorCode::KeyNotFound;
    case SignOutcome::Status::KeyAmbiguous:
        return ErrorCode::KeyAmbiguous;
    case SignOutcome::Status::CertExpiredBlocked:
        return ErrorCode::CertExpiredBlocked;
    case SignOutcome::Status::ChainIncomplete:
        return ErrorCode::ChainIncomplete;
    case SignOutcome::Status::TsaUnreachable:
        return ErrorCode::TsaUnreachable;
    case SignOutcome::Status::AuthFailed:
        return ErrorCode::AuthFailed;
    case SignOutcome::Status::CardBlocked:
        return ErrorCode::CredentialBlocked;
    case SignOutcome::Status::CommunicationError:
        return ErrorCode::CommunicationError;
    case SignOutcome::Status::Cancelled:
        return ErrorCode::None;
    case SignOutcome::Status::SigningEngineError:
        return ErrorCode::SigningEngineError;
    }
    return ErrorCode::SigningEngineError;
}

} // namespace

SignFlow::SignFlow(SignFlowDeps deps) : m_deps(std::move(deps)) {}

SignFlow::Result SignFlow::run()
{
    // Open the held session (shared with the read flows via FlowPrelude). The
    // sign credential provider below is sign-specific (it additionally handles the
    // uncached PIN), so SignFlow installs its own rather than the shared read one.
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeError(opened.code, "op.open_failed", std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    // Thread the resolved candidate list forward; the sign routes across the
    // signing-capable subset (PKI+PinManagement), picking the certId owner.
    auto candidates = std::move(opened.candidates);
    auto signCands = signingCandidates(candidates);

    // Build ONE unified credential provider. For PACE/BAC channel establishment
    // (purpose != Signing) it routes the cacheable CAN/MRZ through the cache; for
    // the signing PIN (purpose == Signing) it prompts uncached every time (PIN is
    // never cached) and drives the post-consent phases that arm the watchdog.
    auto& cache = m_deps.cache;
    auto& prompter = m_deps.prompter;
    auto& serializer = m_deps.serializer;
    auto& phaseSink = m_deps.phaseSink;
    const std::string cardKey = m_deps.cardKey;
    const std::string requester = m_deps.requester;
    // The document name is CLIENT-SUPPLIED (already sanitized at the Card1.Sign
    // entry). It rides the untrusted `description` slot, NOT `artifact`: artifact
    // is the trusted, agent-owned operation category (mirrors the read flows'
    // fixed "identity"/"photo"/"certificates"), so a hostile displayName cannot
    // masquerade as the trusted "what is being signed" label.
    const std::string description = m_deps.params.displayName;
    const LibreSCRS::CancelToken token = m_deps.token;
    // Set true iff a prompt fails because the prompter UI broke / was absent on
    // the bus (NOT cancellation, NOT a wrong-but-collected PIN/CAN). Remaps the
    // final ErrorCode to PrompterError below. shared_ptr so the flag outlives the
    // closure if LM defers the provider.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);

    LibreSCRS::Auth::CredentialProvider provider =
        [&cache, &prompter, &serializer, &phaseSink, cardKey, requester, description, token,
         prompterFailed](const LibreSCRS::Auth::AuthRequirement& req) -> LibreSCRS::Auth::CredentialResult {
        try {
            PromptOptions opts;
            opts.requester = requester;
            opts.artifact = "signature";
            opts.description = description;
            SerializingPrompter gated{serializer, prompter, token};

            if (req.purpose() == LibreSCRS::Auth::Purpose::Signing) {
                // PIN-as-consent: uncached, prompted every time.
                phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
                if (const auto fields = req.fields(); !fields.empty()) {
                    if (const auto mn = fields.front().minLength) {
                        opts.minLength = static_cast<std::uint32_t>(*mn);
                    }
                    if (const auto mx = fields.front().maxLength) {
                        opts.maxLength = static_cast<std::uint32_t>(*mx);
                    }
                }
                const auto prompt = gated.requestPin(opts);
                if (prompt.status == PromptStatus::Cancelled) {
                    return LibreSCRS::Auth::CredentialResult::cancelled();
                }
                if (prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) {
                    if (prompt.status == PromptStatus::Error) {
                        prompterFailed->store(true, std::memory_order_relaxed);
                    }
                    return LibreSCRS::Auth::CredentialResult::error(LibreSCRS::LocalizedText{});
                }
                // PIN collected: arm the watchdog (Authenticating) and surface
                // the on-card signing phase. Both happen AFTER the human, so the
                // unbounded consent wait above is never timed.
                //
                // The watchdog deliberately arms HERE (post-consent), not before
                // signer.sign(): arming earlier would time the unbounded human PIN
                // (and, on PACE cards, CAN) entry, aborting a user who is slow to
                // find their card. The cost is that the pre-consent on-card I/O
                // (the anti-TOCTOU re-read / PACE establishment) is not watchdog-
                // covered — exactly like the read flows' AwaitingConsent window. A
                // hang there is instead bounded by Cancel / client-disconnect /
                // reader-removal (the zombie-worker drain), not the per-op timer.
                phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
                phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Signing));
                std::vector<LibreSCRS::Auth::CredentialEntry> entries;
                entries.emplace_back(PrompterWire::kKindPin, *prompt.secret);
                return LibreSCRS::Auth::CredentialResult::ok(std::move(entries));
            }

            // Channel-establishment secret (CAN/MRZ): cacheable, no sign phases.
            phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
            return cache.requestCredential(cardKey, req, gated, opts, prompterFailed.get());
        } catch (...) {
            return LibreSCRS::Auth::CredentialResult::error(LibreSCRS::LocalizedText{});
        }
    };
    // Install with a UAF scope guard (see FlowPrelude::installScopedReadProvider):
    // the provider captures the per-op phaseSink by reference, but `session` is
    // owned by the CardSessionHolder and outlives this flow. Pass a COPY — the
    // same provider is also handed to the signer below (it additionally serves
    // the signing PIN), so the local must stay valid.
    const auto providerGuard = FlowPrelude::installScopedReadProvider(session, provider);

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    // In-process sign: the seam holds the live shared_ptr<CardSession> so the
    // PACE secure-messaging session is adopted (never re-established) and is
    // torn down with the session, not across a process boundary.
    SignOutcome outcome = m_deps.signer.sign(session, m_deps.params, signCands, std::move(provider), m_deps.token);

    // A cancelled token wins over the terminal status: on shutdown the token is
    // the agent-wide shutdown-cancel token, so bailing here returns Cancelled
    // BEFORE the AuthFailed branch below touches the credential cache — which an
    // abandoned worker must not reach once the aggregate that owns it is gone.
    if (outcome.status == SignOutcome::Status::Cancelled || m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    if (outcome.status == SignOutcome::Status::AuthFailed || outcome.status == SignOutcome::Status::CardBlocked) {
        // A wrong signing PIN must not poison a later read's cached CAN; the PIN
        // itself is never cached, but evict the PACE secret so a card swap or a
        // retry re-establishes cleanly. Mirrors the read flows' eviction.
        m_deps.cache.invalidate(m_deps.cardKey);
        session->clearCachedPaceCredentials();
    }
    if (outcome.status != SignOutcome::Status::Ok) {
        // A broken/absent prompter (not the card) prevented PIN/CAN collection:
        // surface PrompterError so the client knows the UI failed.
        const ErrorCode code =
            prompterFailed->load(std::memory_order_relaxed) ? ErrorCode::PrompterError : mapSignStatus(outcome.status);
        return makeError(code, "op.sign_failed", std::move(outcome.msgFallback));
    }

    // Declarative timestamping phase for the qualified family (b-t/b-lt/b-lta).
    // The timestamp round-trip ran INSIDE signer.sign() (the LM applies it during
    // the buffer-sign), so this is pure UX surfaced after a successful sign — the
    // watchdog already armed on Authenticating bounds the whole call, including
    // the TSA fetch, so no separate re-arm is needed here.
    if (SignatureParams::isQualifiedSignLevel(outcome.resolvedLevel)) {
        m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Timestamping));
    }

    return SignFlow::Result{
        .outcome = SignFlow::Outcome::Ok,
        .code = ErrorCode::None,
        .signedDocumentBytes = std::move(outcome.signedDocumentBytes),
        .resolvedFormat = std::move(outcome.resolvedFormat),
        .resolvedLevel = std::move(outcome.resolvedLevel),
        .tsaUsed = outcome.tsaUsed,
        .chainComplete = outcome.chainComplete,
        .candidates = std::move(candidates),
        .msgKey = "op.ok",
        .msgFallback = "Signature produced",
    };
}

} // namespace LibreSCRS::Agent::Operations
