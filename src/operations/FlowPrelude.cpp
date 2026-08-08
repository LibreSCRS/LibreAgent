// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/OperationPhase.h> // OperationPhase enum
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialOutcome
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (A2 re-key signal)
#include <atomic>
#include <cstdint>
#include <utility>

namespace LibreSCRS::Agent::Operations::FlowPrelude {

namespace {

ErrorCode mapOpenError(LibreSCRS::SmartCard::OpenError::Kind kind) noexcept
{
    switch (kind) {
    case LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable:
        return ErrorCode::CommunicationError;
    case LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent:
        return ErrorCode::CardRemoved;
    case LibreSCRS::SmartCard::OpenError::Kind::ProtocolError:
        return ErrorCode::CommunicationError;
    }
    return ErrorCode::CommunicationError;
}

} // namespace

OpenOutcome openSession(CardSessionHolder& holder, const LibreSCRS::CancelToken& token)
{
    if (token.isCancelled()) {
        return OpenOutcome{.status = OpenStatus::Cancelled,
                           .session = {},
                           .candidates = {},
                           .code = ErrorCode::None,
                           .msgFallback = {}};
    }
    // Acquire the per-reader shared session: opens once, then reuses the held
    // handle (the PACE-established channel from a prior op is preserved) and
    // returns the candidate plugin list resolved for it.
    auto acquired = holder.acquire();
    if (!acquired) {
        return OpenOutcome{
            .status = OpenStatus::OpenFailed,
            .session = {},
            .candidates = {},
            .code = mapOpenError(acquired.error().kind),
            .msgFallback = acquired.error().userMessage.defaultText,
        };
    }
    auto session = std::move(acquired->session);
    auto candidates = std::move(acquired->candidates);

    if (token.isCancelled()) {
        return OpenOutcome{.status = OpenStatus::Cancelled,
                           .session = {},
                           .candidates = {},
                           .code = ErrorCode::None,
                           .msgFallback = {}};
    }

    return OpenOutcome{.status = OpenStatus::Ok,
                       .session = std::move(session),
                       .candidates = std::move(candidates),
                       .code = ErrorCode::None,
                       .msgFallback = {}};
}

CredentialOutcome openFailureOutcome(ErrorCode code) noexcept
{
    return code == ErrorCode::CardRemoved ? CredentialOutcome::CardRemoved : CredentialOutcome::Unspecified;
}

LibreSCRS::Auth::CredentialProvider makeReadCredentialProvider(
    CredentialCache& cache, PrompterClientBase& prompter, PromptSerializer& serializer, OperationPhaseSink& phaseSink,
    std::string cardKey, std::string requester, std::string artifact, LibreSCRS::CancelToken token,
    std::shared_ptr<std::atomic<bool>> prompterFailed, std::shared_ptr<std::atomic<bool>> userCancelled,
    std::shared_ptr<std::atomic<bool>> providerMarkedWrong)
{
    return [&cache, &prompter, &serializer, &phaseSink, cardKey = std::move(cardKey), requester = std::move(requester),
            artifact = std::move(artifact), token = std::move(token), prompterFailed = std::move(prompterFailed),
            userCancelled = std::move(userCancelled),
            providerMarkedWrong = std::move(providerMarkedWrong)](const LibreSCRS::Auth::AuthRequirement& req) {
        try {
            // About to (potentially) block on the prompter for user input —
            // surface the modal-dialog progress phase.
            phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
            // A2 (sec I3 re-key): evict on the card's REJECTION SIGNAL, never on
            // invocation counting. LM sets reasonForUser == preReadAuthFailed()
            // ONLY on a re-prompt after a wrong-secret rejection in the SAME
            // activation (M5′). On that signal, mark the cached value wrong FIRST
            // — evicting the rejected secret so the cache-hit branch is bypassed
            // BY EVICTION (not a parallel path) AND arming applyRetryContext so
            // the re-prompt carries attempt/last_error. A same-kind re-invocation
            // with an EMPTY reason (PACE→BAC fallback, multi-candidate walk) is
            // NOT a rejection and serves the never-rejected value from cache.
            bool markedNow = false;
            if (const auto& reason = req.message();
                reason.has_value() && reason->key == LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key) {
                cache.markCredentialWrong(cardKey, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key);
                markedNow = true;
            }
            PromptOptions opts;
            opts.requester = requester;
            opts.artifact = artifact;
            // Route through the agent-wide gate so two readers cannot stack two
            // dialogs. A cache hit returns inside requestCredential before the
            // wrapper's request* is reached, so the gate is contended only on a
            // real prompt. The routing keys off the AuthRequirement LM hands the
            // callback (its paceKind selects CAN vs MRZ), not a pre-read guess.
            SerializingPrompter gated{serializer, prompter, token};
            auto result = cache.requestCredential(cardKey, req, gated, opts, prompterFailed.get(), userCancelled.get());
            if (providerMarkedWrong) {
                // Double-mark guard: the value now live for LM is the one THIS
                // provider marked wrong IFF we marked and did NOT collect a fresh
                // replacement (a non-Ok result: prompt failed/cancelled/malformed
                // after the eviction). A fresh Ok collection — or any invocation
                // that did not mark — leaves an UNMARKED value live, so the flow
                // must still mark it on a later AuthFailed. Per-invocation store,
                // last invocation wins (it owns the live value the flow will see).
                providerMarkedWrong->store(markedNow && result.status != LibreSCRS::Auth::CredentialResult::Status::Ok,
                                           std::memory_order_relaxed);
            }
            return result;
        } catch (...) {
            return LibreSCRS::Auth::CredentialResult::error(LibreSCRS::LocalizedText{});
        }
    };
}

namespace {

// Stateless no-op provider. A FREE FUNCTION (not a lambda) so converting it to
// LibreSCRS::Auth::CredentialProvider (std::function) inside the guard's deleter
// cannot allocate — and therefore cannot throw — during shared_ptr teardown.
// Returns "credentials required" so a stale channel re-establishment fails closed.
LibreSCRS::Auth::CredentialResult noCredentialsProvider(const LibreSCRS::Auth::AuthRequirement&)
{
    return LibreSCRS::Auth::CredentialResult::error(LibreSCRS::LocalizedText{});
}

} // namespace

std::shared_ptr<void> installScopedReadProvider(std::shared_ptr<LibreSCRS::SmartCard::CardSession> session,
                                                LibreSCRS::Auth::CredentialProvider provider)
{
    session->setCredentialProvider(std::move(provider));
    // The deleter keeps a strong ref to the session (so it outlives the flow's
    // own copy) and resets the provider to a stateless no-op on flow-scope exit:
    // the provider captured the per-op phaseSink by reference but the session is
    // owned by the CardSessionHolder and outlives the flow. setCredentialProvider
    // is itself noexcept; the try/catch keeps the deleter exception-free.
    return std::shared_ptr<void>(nullptr, [sess = std::move(session)](void*) noexcept {
        try {
            sess->setCredentialProvider(&noCredentialsProvider);
        } catch (...) {
        }
    });
}

} // namespace LibreSCRS::Agent::Operations::FlowPrelude
