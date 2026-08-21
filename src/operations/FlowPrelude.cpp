// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/backend/PrompterWire.h> // shared kind vocabulary (alt_kinds value)
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/ConsentPhaseScope.h> // consent is a bounded excursion, not a one-way trip
#include <LibreSCRS/Agent/OperationPhase.h>               // OperationPhase enum
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialOutcome
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (A2 re-key signal)
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <atomic>
#include <cstdint>
#include <optional>
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
    std::shared_ptr<std::atomic<bool>> providerMarkedWrong, bool offerMrzAlternative,
    std::shared_ptr<MrzChoiceSink> mrzChoice, std::shared_ptr<std::atomic<bool>> entryExpired,
    std::shared_ptr<std::atomic<bool>> helperTooOld)
{
    return [&cache, &prompter, &serializer, &phaseSink, cardKey = std::move(cardKey), requester = std::move(requester),
            artifact = std::move(artifact), token = std::move(token), prompterFailed = std::move(prompterFailed),
            userCancelled = std::move(userCancelled), providerMarkedWrong = std::move(providerMarkedWrong),
            offerMrzAlternative, mrzChoice = std::move(mrzChoice), entryExpired = std::move(entryExpired),
            helperTooOld = std::move(helperTooOld)](const LibreSCRS::Auth::AuthRequirement& req) {
        try {
            // About to (potentially) block on the prompter for user input —
            // surface the modal-dialog progress phase, and give it back on the
            // way out. The scope spans the WHOLE body deliberately: the phase
            // must be handed back on the throwing paths too, and the catch-all
            // below would otherwise swallow the throw with the operation still
            // parked in AwaitingConsent — watchdog disarmed — while LM walks on
            // to its next candidate. Leaving it parked is not cosmetic: this
            // lambda is invoked from inside the plugin's readCard, so the
            // activation the collected secret unlocks and every data-group read
            // after it happen under whatever phase this body leaves behind.
            const ConsentPhaseScope consent{phaseSink};
            // A2 (sec I3 re-key): evict on the card's REJECTION SIGNAL, never on
            // invocation counting. LM sets reasonForUser == preReadAuthFailed()
            // ONLY on a re-prompt after a wrong-secret rejection in the SAME
            // activation (M5′). On that signal, mark the cached value wrong FIRST
            // — evicting the rejected secret so the cache-hit branch is bypassed
            // BY EVICTION (not a parallel path) AND arming applyRetryContext so
            // the re-prompt carries attempt/last_error. A same-kind re-invocation
            // with an EMPTY reason (PACE→BAC fallback, multi-candidate walk) is
            // NOT a rejection and serves the never-rejected value from cache.
            //
            // ...but that invariant is weaker than it reads, MEASURED on a live
            // agent: when the previous prompt EXPIRED, no secret ever reached
            // LM, LM's activation fails anyway, and it re-invokes with the same
            // preReadAuthFailed reason. Marking there evicts a value that was
            // never presented, burns one of the three PACE attempts, and makes
            // the next dialog say "the value entered was not accepted" to a
            // holder who entered nothing. So a re-prompt that follows an expiry
            // is not a rejection: skip the mark and let the retry context stay
            // clean. The flag is cleared again the moment a prompt DOES yield a
            // secret, so a wrong value entered after an expiry still marks.
            bool markedNow = false;
            // Asked of the CACHE, not of a per-run flag: the run that raised the
            // expired window ended with it, and this re-request arrives inside the
            // NEXT one. A per-run flag reads false here and the mark lands anyway.
            const bool lastPromptYieldedNothing = cache.lastPromptYieldedNothingFor(cardKey);
            if (const auto& reason = req.message();
                reason.has_value() && reason->key == LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key &&
                !lastPromptYieldedNothing) {
                cache.markCredentialWrong(cardKey, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key);
                markedNow = true;
            }
            PromptOptions opts;
            opts.requester = requester;
            opts.artifact = artifact;
            // The CAN⇄MRZ choice half. Reached only on a CAN requirement for a
            // card family that HAS the duality (the flag is derived from the
            // candidate list). The cache probe runs AFTER the rejection-signal
            // eviction above, so a rejected MRZ can never be re-served here.
            // The sink is part of the offer, not an optional extra: without one
            // a chosen-kind reply has nowhere to land, so the user's switch to
            // MRZ would be silently dropped. No sink, no offer.
            const auto kind = req.paceKind();
            const bool offeringAlternative =
                offerMrzAlternative && mrzChoice && kind.has_value() && *kind == LibreSCRS::Auth::PaceSecretKind::Can;
            std::optional<LibreSCRS::Auth::CredentialResult> renegotiated;
            if (offeringAlternative) {
                if (auto cached = cache.getMrz(cardKey)) {
                    // Same-insertion repeat read: renegotiate silently.
                    mrzChoice->offer(std::move(*cached));
                    renegotiated = LibreSCRS::Auth::CredentialResult::cancelled();
                } else {
                    opts.altKinds = {PrompterWire::kKindMrz};
                }
            }
            // Route through the agent-wide gate so two readers cannot stack two
            // dialogs. A cache hit returns inside requestCredential before the
            // wrapper's request* is reached, so the gate is contended only on a
            // real prompt. The routing keys off the AuthRequirement LM hands the
            // callback (its paceKind selects CAN vs MRZ), not a pre-read guess.
            SerializingPrompter gated{serializer, prompter, token, cardKey};
            // The sink is handed down ONLY on the prompt that actually
            // advertised the alternative, so a chosen-kind reply to a prompt
            // that never offered one fails closed agent-side too, not only at
            // the backend's own only-if-sent parse guard.
            auto result =
                renegotiated.has_value()
                    ? std::move(*renegotiated)
                    : cache.requestCredential(cardKey, req, gated, opts, prompterFailed.get(), userCancelled.get(),
                                              offeringAlternative ? mrzChoice.get() : nullptr, entryExpired.get(),
                                              helperTooOld.get());
            if (providerMarkedWrong) {
                // Double-mark guard. An Ok result means a FRESH value is live
                // — unmarked, so a later AuthFailed must still mark it. A
                // non-Ok invocation that marked owns the live (now-evicted)
                // value and sets the flag. A non-Ok invocation that did NOT
                // mark owns nothing and must leave the flag ALONE: on a
                // multi-candidate walk a later candidate's empty-reason
                // invocation used to CLEAR the flag a prior invocation had
                // set, and one wrong CAN counted as two failed attempts.
                const bool ok = result.status == LibreSCRS::Auth::CredentialResult::Status::Ok;
                if (ok) {
                    providerMarkedWrong->store(false, std::memory_order_relaxed);
                } else if (markedNow) {
                    providerMarkedWrong->store(true, std::memory_order_relaxed);
                }
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
