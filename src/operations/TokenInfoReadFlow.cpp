// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/TokenInfoReadFlow.h>
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

TokenInfoReadFlow::Result makeError(ErrorCode code, std::string msgKey, std::string msgFallback)
{
    return TokenInfoReadFlow::Result{
        .outcome = TokenInfoReadFlow::Outcome::Error,
        .code = code,
        .snapshot = std::nullopt,
        .candidates = {},
        .msgKey = std::move(msgKey),
        .msgFallback = std::move(msgFallback),
    };
}

TokenInfoReadFlow::Result makeCancelled()
{
    return TokenInfoReadFlow::Result{
        .outcome = TokenInfoReadFlow::Outcome::Cancelled,
        .code = ErrorCode::None,
        .snapshot = std::nullopt,
        .candidates = {},
        .msgKey = "op.cancelled",
        .msgFallback = "Operation cancelled",
    };
}

} // namespace

TokenInfoReadFlow::TokenInfoReadFlow(TokenInfoReadFlowDeps deps) : m_deps(std::move(deps)) {}

TokenInfoReadFlow::Result TokenInfoReadFlow::run()
{
    // Audit the read up front, once per request. A token-info read is
    // PIN-free in the common case, so it never reaches the consent prompt
    // that records the requester for the identity/sign paths — without this
    // line a card-ACL-gated read would leave no journald trace (mirrors
    // CertReadFlow's own audit line for the same reason).
    log::infof("token-info read requested: requester={} reader=\"{}\" card={}",
               m_deps.requester.empty() ? "unknown" : m_deps.requester, m_deps.readerName, m_deps.cardKey);

    // Open the held session + install the read credential provider (shared
    // with IdentityReadFlow/CertReadFlow/SignFlow via FlowPrelude). The
    // plugin invokes the provider on a secure-channel cache miss inside
    // readTokenInfo (CAN-once for PACE cards; never reached for free-read
    // cards).
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeError(opened.code, "op.open_failed", std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    // Thread the resolved candidate list forward; the token-info read routes
    // across the PKI-capable subset (capability-aware routing, lazy fallback
    // in the seam) — token info is PKI-adjacent (pkcs15), matching the same
    // gate ReadCertificates uses.
    auto candidates = std::move(opened.candidates);
    auto pkiCands = pkiCandidates(candidates);

    // Set true by the credential provider iff a prompt fails because the
    // prompter UI broke / was absent (NOT cancellation, NOT a wrong secret);
    // remaps the final ErrorCode to PrompterError below.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    // Set true iff a channel prompt EXPIRED — the clock twin of the flag above,
    // and the second failure this flow can still report post-session-open.
    auto entryExpired = std::make_shared<std::atomic<bool>>(false);
    // Set true iff the agent REFUSED to raise the prompt (helper too old).
    auto helperTooOld = std::make_shared<std::atomic<bool>>(false);
    // Install with a UAF scope guard: the provider captures the per-op
    // phaseSink by reference, but `session` is owned by the
    // CardSessionHolder and outlives this flow (see
    // FlowPrelude::installScopedReadProvider).
    const auto providerGuard = FlowPrelude::installScopedReadProvider(
        session, FlowPrelude::makeReadCredentialProvider(
                     m_deps.cache, m_deps.prompter, m_deps.serializer, m_deps.phaseSink, m_deps.cardKey,
                     m_deps.requester, m_deps.artifact, m_deps.token, prompterFailed,
                     /*userCancelled=*/{}, /*providerMarkedWrong=*/{},
                     /*offerMrzAlternative=*/false, /*mrzChoice=*/{}, entryExpired, helperTooOld));

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
    auto group = m_deps.reader.readTokenInfo(*session, pkiCands, m_deps.token);

    // A cancelled token wins over any result the seam produced: on shutdown
    // the token is the agent-wide shutdown-cancel token, so bailing here
    // returns Cancelled before the flow reports a (possibly stale) group.
    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    // NOTE: readTokenInfo never reports a read failure -- an unsupported
    // plugin, a channel-activation failure, or a parse error all degrade to
    // an empty group by the LM plugin's own defensive contract (see
    // pkcs15_card_plugin.cpp's readTokenInfo doc comment), which is SUCCESS
    // with zero fields here (the spec's empty-group resilience). The only
    // failures this flow can still report post-session-open are a broken
    // prompter UI (the CAN/MRZ prompt itself unreachable) and an entry window
    // that expired.
    if (helperTooOld->load(std::memory_order_relaxed)) {
        // Refused before any window was raised; the remedy is actionable.
        return makeError(ErrorCode::CapabilityMissing, FlowPrelude::kHelperTooOldMsgKey,
                         FlowPrelude::kHelperTooOldMsgFallback);
    }
    if (prompterFailed->load(std::memory_order_relaxed)) {
        return makeError(ErrorCode::PrompterError, "op.read_failed", "prompter unavailable");
    }
    // ...and the prompt that was reachable but ran out of the holder's time.
    if (entryExpired->load(std::memory_order_relaxed)) {
        return makeError(ErrorCode::EntryExpired, FlowPrelude::kEntryExpiredMsgKey,
                         FlowPrelude::kEntryExpiredMsgFallback);
    }

    CardReadSnapshot snapshot;
    snapshot.groups.push_back(std::move(group));

    return Result{
        .outcome = Outcome::Ok,
        .code = ErrorCode::None,
        .snapshot = std::move(snapshot),
        .candidates = std::move(candidates),
        .msgKey = "op.ok",
        .msgFallback = "Read completed",
    };
}

} // namespace LibreSCRS::Agent::Operations
