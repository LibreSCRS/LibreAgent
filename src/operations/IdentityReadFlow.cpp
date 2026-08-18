// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/cache/MrzPayload.h>             // parseMrzPayload (the canonical payload contract)
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // identityCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum
#include <LibreSCRS/Auth/ErrorKeys.h>                 // ErrorKeys::preReadAuthFailed
#include <LibreSCRS/Plugin/PluginTypes.h>             // CardCapabilities, hasCapability
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
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

// The alternative-kind offer is a property of the CARD, read off the candidate
// list the holder resolved: travel documents are the one family whose pre-read
// secret has a CAN/MRZ duality, and they declare it in their manifest. Nothing
// injects this — a caller cannot ask for the offer on a card that has no
// alternative to offer.
bool offersMrzAlternative(const CandidateList& candidates)
{
    return std::ranges::any_of(candidates, [](const auto& c) {
        return c &&
               LibreSCRS::Plugin::hasCapability(c->capabilities(), LibreSCRS::Plugin::CardCapabilities::EmrtdCrypto);
    });
}

// Scrubs a choice sink that was filled but never consumed (an error path, a
// cancelled run) before run() returns, so no payload outlives the run holding
// secret bytes. A consumed sink is already disarmed and empty; reset() is a
// no-op on it.
class ChoiceSinkScrubGuard
{
public:
    explicit ChoiceSinkScrubGuard(std::shared_ptr<LibreSCRS::Agent::MrzChoiceSink> sink) : m_sink(std::move(sink)) {}
    ~ChoiceSinkScrubGuard()
    {
        if (m_sink) {
            m_sink->reset();
        }
    }
    ChoiceSinkScrubGuard(const ChoiceSinkScrubGuard&) = delete;
    ChoiceSinkScrubGuard& operator=(const ChoiceSinkScrubGuard&) = delete;
    ChoiceSinkScrubGuard(ChoiceSinkScrubGuard&&) = delete;
    ChoiceSinkScrubGuard& operator=(ChoiceSinkScrubGuard&&) = delete;

private:
    std::shared_ptr<LibreSCRS::Agent::MrzChoiceSink> m_sink;
};

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
    // Set true by the credential provider iff, on the M5′ rejection signal, it
    // already marked the now-live rejected secret wrong (A2, sec I3). The
    // AuthFailed branch below consults it to SKIP its own markCredentialWrong so
    // a rejected value is marked EXACTLY once. Run-scoped (fresh per run) so
    // parallel readers never cross-talk.
    auto providerMarkedWrong = std::make_shared<std::atomic<bool>>(false);
    // A CAN prompt may be renegotiated into an MRZ read: the offer is derived
    // from THIS card's candidates, and the payload the user chose comes back
    // through the flow-owned sink below (scrubbed at run() exit, consumed at
    // most once).
    const bool offerMrzAlternative = offersMrzAlternative(idCands);
    const ChoiceSinkScrubGuard choiceGuard{m_mrzChoice};
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow (see FlowPrelude::installScopedReadProvider).
    m_provider = FlowPrelude::makeReadCredentialProvider(
        m_deps.cache, m_deps.prompter, m_deps.serializer, m_deps.phaseSink, m_deps.cardKey, m_deps.requester,
        m_deps.artifact, m_deps.token, prompterFailed,
        /*userCancelled=*/{}, providerMarkedWrong, offerMrzAlternative, m_mrzChoice);
    const FlowPrelude::ProviderResetGuard providerReset{m_provider};
    const auto providerGuard = FlowPrelude::installScopedReadProvider(session, m_provider);

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
    // Forward each streamed group straight to the sink, in the order the
    // reader produces them. Fires zero or more times DURING the call below,
    // strictly before it returns -- so every group this run() ever streams
    // is behind us by the time the Result assembled further down is
    // returned, let alone emitted by the caller (ReadIdentityOperation emits
    // Result only AFTER flow.run() returns).
    const auto onGroup = [this](const GroupSnapshot& g) { m_deps.groupSink.groupReady(g); };
    auto readOutcome = m_deps.reader.read(*session, idCands, m_deps.token, onGroup);

    // -- Step 5: the shutdown token wins over EVERYTHING ------------------
    // Checked on its OWN, ahead of the renegotiation below: on shutdown this is
    // the agent-wide cancel token, and an abandoned worker must put neither a
    // credential-cache write nor a SECOND card read past this guard.
    if (m_deps.token.isCancelled()) {
        return makeCancelled("op.cancelled", "Operation cancelled");
    }

    // -- Step 6: renegotiate a CAN prompt into an MRZ read (at most once) --
    // The walk unwound as a cancellation because the user swapped the secret
    // kind mid-dialog, not because anyone cancelled: deposit what they chose and
    // read again. Reached only with an un-cancelled token, and the sink is
    // one-shot, so this can never loop.
    if (m_mrzChoice->taken()) {
        if (auto payload = m_mrzChoice->take()) {
            const auto parts = parseMrzPayload(*payload);
            if (!parts.has_value()) {
                // Nothing usable was collected: no deposit, no cache write, and
                // certainly no second walk. The read's own mapped code is the
                // honest one; a walk that unwound as this renegotiation's
                // cancellation carries none, and a payload the agent cannot
                // parse is the prompter's contract broken, so say so.
                const ErrorCode mapped = mapReadStatus(readOutcome.status);
                return makeError(mapped != ErrorCode::None ? mapped : ErrorCode::PrompterError, "op.read_failed",
                                 std::move(readOutcome.msgFallback));
            }
            // Cache the RAW payload so any further read within this insertion
            // renegotiates silently (keyed on the per-insertion card identity).
            m_deps.cache.putMrz(m_deps.cardKey, std::move(*payload));
            if (!m_deps.depositor.depositMrz(*session, idCands, *parts)) {
                // No candidate could take the MRZ, so the re-run below cannot
                // possibly authenticate with it: it would re-ask for a CAN, the
                // cached payload would renegotiate silently, and the walk would
                // unwind as that renegotiation's cancellation — a silent cancel
                // that spends a card read and tells the user nothing. Report
                // the capability that is actually missing, in words about THIS
                // condition — the read outcome's own message at this point is
                // the cancelled renegotiation's text, and a client without a
                // per-code copy would render "cancelled" under an error code.
                return makeError(ErrorCode::CapabilityMissing, "op.read_failed",
                                 "No installed card driver can accept the entered document data for this card.");
            }
            // Re-check: the deposit is not instantaneous and the token may have
            // tripped while it ran.
            if (m_deps.token.isCancelled()) {
                return makeCancelled("op.cancelled", "Operation cancelled");
            }
            m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
            m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
            readOutcome = m_deps.reader.read(*session, idCands, m_deps.token, onGroup);
        }
    }

    // A cancelled read wins over the read status below: bail BEFORE the
    // AuthFailed branch touches the credential cache. A genuine user cancel —
    // one with nothing waiting in the choice sink — lands here and cancels.
    if (readOutcome.status == ReadOutcome::Status::Cancelled || m_deps.token.isCancelled()) {
        return makeCancelled("op.cancelled", "Operation cancelled");
    }
    if (readOutcome.status != ReadOutcome::Status::Ok || !readOutcome.snapshot) {
        // A wrong pre-read secret (wrong CAN/MRZ, surfaced as AuthFailed) must
        // not be replayed from cache on the next attempt. Evict the agent-side
        // cached secret for this card AND clear LM's per-session PACE cache so a
        // retry re-prompts rather than silently re-using the rejected secret.
        // markCredentialWrong (not plain invalidate) also remembers WHY, so the
        // next prompt for this card carries retry context (attempt count +
        // msgKey) instead of a cold re-prompt. Strictly the auth-failure path:
        // parse/comm errors leave a correct cached secret in place. (The
        // session is closed when run() returns; the LM clear is belt-and-
        // suspenders today and stays correct for a future that holds the
        // session open across retries.)
        if (readOutcome.status == ReadOutcome::Status::AuthFailed) {
            // Double-mark guard (A2, sec I3): if the provider already marked the
            // now-live rejected secret wrong on the card's re-prompt signal, skip
            // the flow's own mark so the rejected value is counted EXACTLY once
            // (truthful attempt numbering). The provider only sets this when the
            // marked value was NOT replaced by a fresh collection.
            if (!providerMarkedWrong->load(std::memory_order_relaxed)) {
                m_deps.cache.markCredentialWrong(m_deps.cardKey, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key);
            }
            session->clearCachedPaceCredentials();
        }
        // A broken/absent prompter (not the card) caused the secret to be
        // uncollectable: surface PrompterError so the client knows the UI
        // failed, not that the card or comms did.
        const ErrorCode code = prompterFailed->load(std::memory_order_relaxed) ? ErrorCode::PrompterError
                                                                               : mapReadStatus(readOutcome.status);
        return makeError(code, "op.read_failed", std::move(readOutcome.msgFallback));
    }

    // Push the authoritative cardType (if the plugin populated one) through to
    // the property-update path BEFORE the snapshot is moved out — this is the
    // single point every fresh identity read passes through.
    if (m_deps.onCardType && !readOutcome.snapshot->cardType.empty()) {
        m_deps.onCardType(readOutcome.snapshot->cardType);
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
