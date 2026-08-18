// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CertReadFlow.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // pkiCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum
#include <LibreSCRS/Auth/ErrorKeys.h>                 // ErrorKeys::preReadAuthFailed
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

// Human label for a security-status token, used as the labelFallback on the
// "security" group's field. Falls back to the token itself (still readable,
// e.g. for a value a future agent adds that this build does not yet know the
// pretty text for -- never happens today since the vocabulary is closed, but
// keeps the helper total rather than partial).
std::string securityTokenLabel(const std::string& token)
{
    if (token == "trusted") {
        return "Trusted";
    }
    if (token == "untrusted-root") {
        return "Untrusted Root";
    }
    if (token == "broken-chain") {
        return "Broken Chain";
    }
    if (token == "invalid") {
        return "Invalid";
    }
    if (token == "expired") {
        return "Expired";
    }
    if (token == "revoked") {
        return "Revoked";
    }
    if (token == "offline-unverified") {
        return "Offline (Unverified)";
    }
    return token;
}

// Build the "security" GroupSnapshot from the resolved security-status
// tokens -- one field per token, keyed by the token itself (the closed
// vocabulary guarantees uniqueness, so no ordinal scheme is needed). Returns
// an empty (fields-less) group when @p tokens is empty; the caller only
// appends a non-empty group so a cert with no tokens carries no stray
// "security" key.
GroupSnapshot makeSecurityGroup(const std::vector<std::string>& tokens)
{
    GroupSnapshot g;
    g.groupKey = "security";
    g.labelKey = "cert.group.security";
    g.labelFallback = "Security";
    g.fields.reserve(tokens.size());
    for (const auto& token : tokens) {
        FieldSnapshot f;
        f.fieldKey = token;
        f.labelKey = "cert.security." + token;
        f.labelFallback = securityTokenLabel(token);
        f.type = FieldType::Text;
        f.textValue = token;
        g.fields.push_back(std::move(f));
    }
    return g;
}

// Apply a resolved TrustVerdict to a parsed CertSnapshot: sets trustStatus +
// securityStatus (the agent-internal mirror) AND appends the "security"
// fields-group the wire actually carries them through (dict-key growth on
// BOTH wires -- see CertSnapshot.h). The two are written together here, from
// the SAME verdict, so they can never drift apart.
void applyTrustVerdict(CertSnapshot& cert, const TrustVerdict& verdict)
{
    cert.trustStatus = static_cast<std::uint32_t>(verdict.status);
    cert.securityStatus = verdict.securityStatus;
    if (!verdict.securityStatus.empty()) {
        cert.fields.push_back(makeSecurityGroup(verdict.securityStatus));
    }
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
    // Set true by the credential provider iff, on the card's re-prompt signal,
    // it already marked the now-live rejected secret wrong. The AuthFailed
    // branch below consults it to SKIP its own markCredentialWrong so a rejected
    // value is marked EXACTLY once. Run-scoped (fresh per run) so parallel
    // readers never cross-talk.
    auto providerMarkedWrong = std::make_shared<std::atomic<bool>>(false);
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow (see FlowPrelude::installScopedReadProvider).
    m_provider = FlowPrelude::makeReadCredentialProvider(
        m_deps.cache, m_deps.prompter, m_deps.serializer, m_deps.phaseSink, m_deps.cardKey, m_deps.requester,
        m_deps.artifact, m_deps.token, prompterFailed, /*userCancelled=*/{}, providerMarkedWrong);
    const FlowPrelude::ProviderResetGuard providerScrub{m_provider};
    const auto providerGuard = FlowPrelude::installScopedReadProvider(session, m_provider);

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
        // — but keep the eviction symmetric with IdentityReadFlow, including the
        // retry-context bookkeeping markCredentialWrong records.)
        if (outcome.status == CertReadOutcome::Status::AuthFailed) {
            // Double-mark guard: if the provider already marked the now-live
            // rejected secret wrong on the card's re-prompt signal, skip the
            // flow's own mark so the rejected value is counted EXACTLY once
            // (truthful attempt numbering). The provider only sets this when the
            // marked value was NOT replaced by a fresh collection.
            if (!providerMarkedWrong->load(std::memory_order_relaxed)) {
                m_deps.cache.markCredentialWrong(m_deps.cardKey, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key);
            }
            session->clearCachedPaceCredentials();
        }
        const ErrorCode code =
            prompterFailed->load(std::memory_order_relaxed) ? ErrorCode::PrompterError : mapCertStatus(outcome.status);
        return makeError(code, "op.read_failed", std::move(outcome.msgFallback));
    }

    // Resolve each cert's trust verdict from its DER (index-aligned with
    // outcome.certs) via the injected seam, and stitch it into the parsed
    // snapshot. Best-effort defensive bound: a producer that ever desyncs the
    // two vectors (should never happen -- see CertReadOutcome::derBytes'
    // comment) just leaves the trailing certs at their parser default
    // (Unknown, no security tokens) rather than reading out of bounds.
    for (std::size_t i = 0; i < outcome.certs.size() && i < outcome.derBytes.size(); ++i) {
        const auto verdict = m_deps.trustVerifier.verify(outcome.derBytes[i], {});
        applyTrustVerdict(outcome.certs[i], verdict);
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
