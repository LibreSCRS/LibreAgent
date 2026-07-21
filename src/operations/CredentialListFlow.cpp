// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CredentialListFlow.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // filterByCapability
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // OperationPhase enum
#include <LibreSCRS/Plugin/PluginTypes.h>             // CardCapabilities
#include <LibreSCRS/SecureChannel/ChannelErrors.h>    // ChannelActivationError
#include <atomic>
#include <cstdint>
#include <memory>
#include <stdexcept> // std::runtime_error (mapper unrepresentable-data throws)
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

CredentialListFlow::Result makeError(ErrorCode code, std::string msgKey, std::string msgFallback)
{
    return CredentialListFlow::Result{
        .outcome = CredentialListFlow::Outcome::Error,
        .code = code,
        .snapshot = {},
        .candidates = {},
        .msgKey = std::move(msgKey),
        .msgFallback = std::move(msgFallback),
    };
}

CredentialListFlow::Result makeCancelled()
{
    return CredentialListFlow::Result{
        .outcome = CredentialListFlow::Outcome::Cancelled,
        .code = ErrorCode::None,
        .snapshot = {},
        .candidates = {},
        .msgKey = "op.cancelled",
        .msgFallback = "Operation cancelled",
    };
}

} // namespace

CredentialListFlow::CredentialListFlow(CredentialListFlowDeps deps) : m_deps(std::move(deps)) {}

// Lifetime contract for m_deps.token: held by value (the LM CancelToken is a
// cheap-copy handle). The list seam takes the session by reference and has no
// CancelToken of its own (the LM getPINList entry point has none), so the token
// is a pre-/post-dispatch best-effort check only.
CredentialListFlow::Result CredentialListFlow::run()
{
    // Open the held session + install the read credential provider (shared with
    // the read flows via FlowPrelude). A pre-auth (PACE) card self-activates its
    // secure channel inside getPINList and invokes this provider on a cache miss;
    // the cached CAN rides the held session (CAN-once).
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeError(opened.code, "op.open_failed", std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    // Thread the resolved candidate list forward; the credential list routes
    // across the PIN-management-capable subset (lazy fallback in the seam).
    auto candidates = std::move(opened.candidates);
    auto credCands = filterByCapability(candidates, LibreSCRS::Plugin::CardCapabilities::PinManagement);

    // Set true by the credential provider iff a prompt fails because the prompter
    // UI broke / was absent (NOT cancellation, NOT a wrong-but-collected secret);
    // remaps the final ErrorCode to PrompterError below.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    // Set true by the provider iff the user DISMISSED a channel prompt (CAN/MRZ)
    // — the cancel twin of prompterFailed. getPINList has no status channel and
    // the seam swallows a candidate's channel-activation throw, so this flag is
    // the only way to tell a cancelled prompt from a valid empty listing.
    auto promptCancelled = std::make_shared<std::atomic<bool>>(false);
    // Install with a UAF scope guard: the provider captures the per-op phaseSink
    // by reference, but `session` is owned by the CardSessionHolder and outlives
    // this flow (see FlowPrelude::installScopedReadProvider).
    const auto providerGuard = FlowPrelude::installScopedReadProvider(
        session, FlowPrelude::makeReadCredentialProvider(
                     m_deps.cache, m_deps.prompter, m_deps.serializer, m_deps.phaseSink, m_deps.cardKey,
                     m_deps.requester, m_deps.artifact, m_deps.token, prompterFailed, promptCancelled));

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
    m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
    // The seam lists the active applet's PIN credentials on the same held
    // session (lazy fallback across candidates; a throwing candidate is skipped
    // and an all-empty result comes back as an empty vector). toCredentialRecord
    // may throw on malformed guidance/length bounds — that is caught below and
    // mapped to an Error result, so a single unrepresentable field fails this op
    // cleanly rather than escaping into the Operation's exception funnel.
    auto listing = m_deps.credentials.list(*session, credCands);
    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }
    // A user-dismissed channel prompt (CAN/MRZ) during the list: the plugin's
    // activation aborted and the seam swallowed the throw, so the entries are
    // not a valid listing. Finish Cancelled — never Ok-with-empty-snapshot —
    // and cache nothing (the caching put is on the Ok tail only).
    if (promptCancelled->load(std::memory_order_relaxed)) {
        return makeCancelled();
    }

    // An empty list is ambiguous: a live card that advertises no PIN credentials
    // (valid empty snapshot) vs. a card removed mid-list (the seam swallowed the
    // channel-activation throw and returned empty). The dead-session flag and the
    // prompter-failure flag disambiguate; otherwise the empty result is valid.
    // The dead-session classification is UNCONDITIONAL (mirrors the mutation
    // flows): even a non-empty listing from a card pulled mid-list must not be
    // reported Ok, and must never re-create a snapshot under a cardKey whose
    // removal hook already dropped it.
    if (session->isDead()) {
        return makeError(errorCodeFor(LibreSCRS::SecureChannel::ChannelActivationError::CardRemoved), "op.read_failed",
                         "Card removed");
    }
    if (listing.entries.empty() && prompterFailed->load(std::memory_order_relaxed)) {
        return makeError(ErrorCode::PrompterError, "op.read_failed", "Credential prompt unavailable");
    }

    CredentialSnapshot snapshot;
    // Bind the snapshot to the candidate whose non-empty getPINList produced
    // it: the mutation flows route to this plugin first, so the plugin that
    // minted the id/label namespace answers a mutation addressed against it.
    snapshot.listPluginId = std::move(listing.pluginId);
    snapshot.records.reserve(listing.entries.size());
    try {
        for (const auto& entry : listing.entries) {
            snapshot.records.push_back(toCredentialRecord(entry));
        }
    } catch (const std::runtime_error&) {
        // A field carried plugin data the wire record cannot represent: an
        // out-of-range length bound (narrowLengthToInt -> std::overflow_error) or
        // placeholder-bearing guidance (splitGuidance -> std::runtime_error), now
        // the same runtime-exception family caught by this one handler. Fail the
        // whole ListCredentials cleanly rather than letting the throw escape.
        return makeError(ErrorCode::ParseError, "op.read_failed", "Malformed credential metadata");
    }
    // Suffix colliding synthesized ids so every record id is unique within the
    // snapshot (stable per card session for equal list order).
    disambiguateCredentialIds(snapshot.records);

    // Hand the freshly-read snapshot to the per-card cache, which stamps it with
    // the next monotonic version; carry that version into the returned snapshot so
    // the client's copy matches the cached one (a later mutation the adaptor
    // resolves from this cache addresses the same version). Only a valid list
    // reaches here — error/cancel paths returned above and cache nothing.
    snapshot.version = m_deps.snapshotCache.put(m_deps.cardKey, snapshot);

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
