// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // identityCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum
#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

IdentityReadFlow::Result makeError(ErrorCode code, std::string msgKey, std::string msgFallback)
{
    return IdentityReadFlow::Result{
        .outcome = IdentityReadFlow::Outcome::Error,
        .code = code,
        .snapshot = std::nullopt,
        .candidates = {},
        .msgKey = std::move(msgKey),
        .msgFallback = std::move(msgFallback),
    };
}

IdentityReadFlow::Result makeCancelled(std::string msgKey, std::string msgFallback)
{
    return IdentityReadFlow::Result{
        .outcome = IdentityReadFlow::Outcome::Cancelled,
        .code = ErrorCode::None,
        .snapshot = std::nullopt,
        .candidates = {},
        .msgKey = std::move(msgKey),
        .msgFallback = std::move(msgFallback),
    };
}

ErrorCode mapReadStatus(ReadOutcome::Status s) noexcept
{
    switch (s) {
    case ReadOutcome::Status::Ok:
        return ErrorCode::None;
    case ReadOutcome::Status::AuthFailed:
        return ErrorCode::AuthFailed;
    case ReadOutcome::Status::ParseError:
        return ErrorCode::ParseError;
    case ReadOutcome::Status::UnsupportedCard:
        return ErrorCode::UnsupportedCard;
    case ReadOutcome::Status::CommunicationError:
        return ErrorCode::CommunicationError;
    case ReadOutcome::Status::Cancelled:
        return ErrorCode::None;
    }
    return ErrorCode::CommunicationError;
}

} // namespace

IdentityReadFlow::IdentityReadFlow(IdentityReadFlowDeps deps) : m_deps(std::move(deps)) {}

// Lifetime contract for m_deps.token: held by value (the LM CancelToken is
// a cheap-copy handle), never moved into a seam call. Each seam takes the
// token by value (cheap copy), so isCancelled() remains observable through
// m_deps.token across the entire run() — including after every seam call.
IdentityReadFlow::Result IdentityReadFlow::run()
{
    // -- Steps 1-2: open the held session + install the read credential provider
    // -- (shared with CertReadFlow/SignFlow via FlowPrelude; the read tail below
    // is identity-specific.)
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled("op.cancelled", "Operation cancelled");
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeError(opened.code, "op.open_failed", std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    // Thread the resolved candidate list forward; the identity read routes across
    // the identity-capable subset (capability-aware routing, lazy fallback).
    auto candidates = std::move(opened.candidates);
    auto idCands = identityCandidates(candidates);

    // Set true by the credential provider iff a prompt fails because the
    // prompter UI broke / was absent on the bus (NOT cancellation, NOT a
    // wrong-but-collected secret). Used below to remap the final ErrorCode to
    // PrompterError so a broken prompter is distinguishable from generic comms.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow (see FlowPrelude::installScopedReadProvider).
    const auto providerGuard = FlowPrelude::installScopedReadProvider(
        session, FlowPrelude::makeReadCredentialProvider(m_deps.cache, m_deps.prompter, m_deps.serializer,
                                                         m_deps.phaseSink, m_deps.cardKey, m_deps.requester,
                                                         m_deps.artifact, m_deps.token, prompterFailed));

    // -- Step 4: read card data ------------------------------------------
    if (m_deps.token.isCancelled()) {
        return makeCancelled("op.cancelled", "Operation cancelled");
    }
    // The plugin's readCard self-activates the secure channel (invoking the
    // provider above on a cache miss) and then reads the data groups. Emit
    // Authenticating before the read so the UI surfaces the unlock window,
    // then Reading immediately after: the watchdog arms on either, and we
    // have no per-group callback on the read seam to draw a finer boundary,
    // so the Authenticating→Reading split is intentionally coarse.
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
    auto readOutcome = m_deps.reader.read(*session, idCands, m_deps.token);
    // A cancelled token wins over the read status: on shutdown the token is the
    // agent-wide shutdown-cancel token, so bailing here returns Cancelled BEFORE
    // the AuthFailed branch below touches the credential cache — which an
    // abandoned worker must not reach once the aggregate that owns it is gone.
    if (readOutcome.status == ReadOutcome::Status::Cancelled || m_deps.token.isCancelled()) {
        return makeCancelled("op.cancelled", "Operation cancelled");
    }
    if (readOutcome.status != ReadOutcome::Status::Ok || !readOutcome.snapshot) {
        // A wrong pre-read secret (wrong CAN/MRZ, surfaced as AuthFailed) must
        // not be replayed from cache on the next attempt. Evict the agent-side
        // cached secret for this card AND clear LM's per-session PACE cache so a
        // retry re-prompts rather than silently re-using the rejected secret.
        // Strictly the auth-failure path: parse/comm errors leave a correct
        // cached secret in place. (The session is closed when run() returns; the
        // LM clear is belt-and-suspenders today and stays correct for a future
        // that holds the session open across retries.)
        if (readOutcome.status == ReadOutcome::Status::AuthFailed) {
            m_deps.cache.invalidate(m_deps.cardKey);
            session->clearCachedPaceCredentials();
        }
        // A broken/absent prompter (not the card) caused the secret to be
        // uncollectable: surface PrompterError so the client knows the UI
        // failed, not that the card or comms did.
        const ErrorCode code = prompterFailed->load(std::memory_order_relaxed) ? ErrorCode::PrompterError
                                                                               : mapReadStatus(readOutcome.status);
        return makeError(code, "op.read_failed", std::move(readOutcome.msgFallback));
    }

    return Result{
        .outcome = Outcome::Ok,
        .code = ErrorCode::None,
        .snapshot = std::move(*readOutcome.snapshot),
        .candidates = std::move(candidates),
        .msgKey = "op.ok",
        .msgFallback = "Read completed",
    };
}

} // namespace LibreSCRS::Agent::Operations
