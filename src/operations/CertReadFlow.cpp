// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CertReadFlow.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // pkiCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum
#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

CertReadFlow::Result makeError(ErrorCode code, std::string msgKey, std::string msgFallback)
{
    return CertReadFlow::Result{
        .outcome = CertReadFlow::Outcome::Error,
        .code = code,
        .certs = {},
        .candidates = {},
        .msgKey = std::move(msgKey),
        .msgFallback = std::move(msgFallback),
    };
}

CertReadFlow::Result makeCancelled()
{
    return CertReadFlow::Result{
        .outcome = CertReadFlow::Outcome::Cancelled,
        .code = ErrorCode::None,
        .certs = {},
        .candidates = {},
        .msgKey = "op.cancelled",
        .msgFallback = "Operation cancelled",
    };
}

ErrorCode mapCertStatus(CertReadOutcome::Status s) noexcept
{
    switch (s) {
    case CertReadOutcome::Status::Ok:
        return ErrorCode::None;
    case CertReadOutcome::Status::AuthFailed:
        return ErrorCode::AuthFailed;
    case CertReadOutcome::Status::ParseError:
        return ErrorCode::ParseError;
    case CertReadOutcome::Status::UnsupportedCard:
        return ErrorCode::UnsupportedCard;
    case CertReadOutcome::Status::CommunicationError:
        return ErrorCode::CommunicationError;
    case CertReadOutcome::Status::Cancelled:
        return ErrorCode::None;
    }
    return ErrorCode::CommunicationError;
}

} // namespace

CertReadFlow::CertReadFlow(CertReadFlowDeps deps) : m_deps(std::move(deps)) {}

CertReadFlow::Result CertReadFlow::run()
{
    // Audit the read up front, once per request. A cert read is PIN-free, so it
    // never reaches the consent prompt that records the requester for the
    // identity/sign paths — without this line a card-ACL-gated cardholder
    // fingerprinting read would leave no journald trace. The requester label is
    // already resolved and sanitized at the Card1 method entry; fall back to an
    // explicit "unknown" marker when best-effort resolution failed.
    log::infof("certificate read requested: requester={} reader=\"{}\" card={}",
               m_deps.requester.empty() ? "unknown" : m_deps.requester, m_deps.reader, m_deps.cardKey);

    // Open the held session + install the read credential provider (shared with
    // IdentityReadFlow/SignFlow via FlowPrelude). The plugin invokes the
    // provider on a secure-channel cache miss inside readCertificates (CAN-once
    // for PACE cards; never reached for free-read cards).
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeError(opened.code, "op.open_failed", std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    // Thread the resolved candidate list forward; the cert read routes across the
    // PKI-capable subset (capability-aware routing, lazy fallback in the seam).
    auto candidates = std::move(opened.candidates);
    auto pkiCands = pkiCandidates(candidates);

    // Set true by the credential provider iff a prompt fails because the
    // prompter UI broke / was absent (NOT cancellation, NOT a wrong secret);
    // remaps the final ErrorCode to PrompterError below.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow (see FlowPrelude::installScopedReadProvider).
    const auto providerGuard = FlowPrelude::installScopedReadProvider(
        session, FlowPrelude::makeReadCredentialProvider(m_deps.cache, m_deps.prompter, m_deps.serializer,
                                                         m_deps.phaseSink, m_deps.cardKey, m_deps.requester,
                                                         m_deps.artifact, m_deps.token, prompterFailed));

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
    auto outcome = m_deps.certReader.read(*session, pkiCands, m_deps.token);
    // A cancelled token wins over the read status: on shutdown the token is the
    // agent-wide shutdown-cancel token, so bailing here returns Cancelled BEFORE
    // the AuthFailed branch below touches the credential cache — which an
    // abandoned worker must not reach once the aggregate that owns it is gone.
    if (outcome.status == CertReadOutcome::Status::Cancelled || m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    if (outcome.status != CertReadOutcome::Status::Ok) {
        // A wrong pre-read secret must not be replayed on the next attempt.
        // (readCertificates rarely surfaces AuthFailed — see LmCertificateReader
        // — but keep the eviction symmetric with IdentityReadFlow.)
        if (outcome.status == CertReadOutcome::Status::AuthFailed) {
            m_deps.cache.invalidate(m_deps.cardKey);
            session->clearCachedPaceCredentials();
        }
        const ErrorCode code =
            prompterFailed->load(std::memory_order_relaxed) ? ErrorCode::PrompterError : mapCertStatus(outcome.status);
        return makeError(code, "op.read_failed", std::move(outcome.msgFallback));
    }

    return CertReadFlow::Result{
        .outcome = CertReadFlow::Outcome::Ok,
        .code = ErrorCode::None,
        .certs = std::move(outcome.certs),
        .candidates = std::move(candidates),
        .msgKey = "op.ok",
        .msgFallback = "Read completed",
    };
}

} // namespace LibreSCRS::Agent::Operations
