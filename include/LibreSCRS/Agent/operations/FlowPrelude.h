// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <atomic>
#include <memory>
#include <string>

namespace LibreSCRS::Agent {
class CredentialCache;
}

namespace LibreSCRS::Agent::Operations {

class PrompterClientBase;
class PromptSerializer;
class CardSessionHolder;

// Shared front-half of every per-reader flow (IdentityReadFlow, CertReadFlow,
// SignFlow). Each flow opens (acquires) the per-reader held session and installs
// a credential provider; the reading/signing tail then diverges. The plugin
// self-activates its channel and invokes the credential provider on a cache miss
// inside that tail, so no pre-read auth classification happens here. Extracted
// once SignFlow became the third consumer (the reuse-≥2× bar).
namespace FlowPrelude {

enum class OpenStatus { Ok, Cancelled, OpenFailed };

struct OpenOutcome
{
    OpenStatus status{OpenStatus::OpenFailed};
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session; // valid iff status == Ok
    // Candidate plugin list resolved once for the held session (valid iff
    // status == Ok). Threaded for capability-aware routing; flows that still
    // read via a single pre-bound seam may leave it unused.
    CandidateList candidates;
    ErrorCode code{ErrorCode::CommunicationError}; // meaningful iff status == OpenFailed
    std::string msgFallback;                       // open-error detail iff status == OpenFailed
};

// Token-check -> acquire the per-reader shared session from the holder ->
// token-check. The holder opens the session once and reuses it across operations
// (so a PACE-established secure channel survives), resolving the candidate plugin
// list once per held session. On a tripped token returns Cancelled; on an acquire
// failure returns OpenFailed with a mapped ErrorCode + the LM error's user
// message; otherwise Ok with the session AND the resolved candidates. The caller
// maps these onto its own Result type (each flow owns its msgKey).
[[nodiscard]] OpenOutcome openSession(CardSessionHolder& holder, const LibreSCRS::CancelToken& token);

// Classify a failed openSession() code onto the credential-outcome vocabulary,
// shared by the mutation flows (PinChangeFlow, KeyActivationFlow): a card that
// is gone (ErrorCode::CardRemoved) becomes the agent-assigned CardRemoved
// outcome; any other open failure is the non-card Unspecified (mapped to
// CommunicationError on the wire by the outcome->code overload). A pre-seam
// open failure never reached the card, so nothing on it moved and the caches
// stay intact. Cancellation is handled by the caller before this is consulted.
[[nodiscard]] CredentialOutcome openFailureOutcome(ErrorCode code) noexcept;

// The READ credential provider, shared by IdentityReadFlow + CertReadFlow:
// routes the cacheable CAN/MRZ through the cache (PIN is never reached here) and
// surfaces AwaitingConsent on a real prompt. SignFlow builds its own provider
// (it additionally handles the uncached signing PIN), so it is not a consumer.
//
// The references (cache/prompter/serializer/phaseSink) must outlive the returned
// provider's use, which is bounded by the flow's run(); the value captures
// (cardKey/requester/artifact/token) keep the closure valid if LM defers it.
//
// @p prompterFailed is a shared flag the provider sets to true iff a prompt
// returned PromptStatus::Error (prompter UI broke / absent on the bus). The flow
// remaps its final ErrorCode to PrompterError when the flag is set, so a broken
// prompter is distinguishable from a generic comms/auth failure. Shared by value
// (shared_ptr) so the flag outlives the closure even if LM defers it.
//
// @p userCancelled is the cancel twin of prompterFailed (optional, may be
// null): set to true iff a prompt returned PromptStatus::Cancelled. The list
// flow consults it because the LM seam swallows a candidate's channel-
// activation throw — without this signal a user-dismissed CAN prompt would be
// indistinguishable from a live card advertising no PIN credentials (and would
// be cached as a valid empty snapshot).
//
// @p providerMarkedWrong (A2, sec I3, optional/may be null) is the re-key
// signal channel, provider-scoped so parallel readers never cross-talk. When
// the incoming AuthRequirement's reasonForUser carries preReadAuthFailed().key
// (LM sets it ONLY on a re-prompt after a wrong-secret rejection in the SAME
// activation — M5′), the provider FIRST calls
// cache.markCredentialWrong(cardKey, preReadAuthFailed().key) — evicting the
// rejected value AND arming applyRetryContext, so the re-prompt carries
// attempt/last_error instead of replaying the rejected secret. The flag is set
// true iff, after that invocation, the value now live for LM is the one THIS
// provider marked wrong AND did not replace with a freshly collected value; the
// flow's AuthFailed branch consults it to skip its own markCredentialWrong so a
// rejected value is marked EXACTLY once (truthful attempt numbering). A
// same-kind re-invocation WITHOUT the signal serves the cache normally.
[[nodiscard]] LibreSCRS::Auth::CredentialProvider makeReadCredentialProvider(
    CredentialCache& cache, PrompterClientBase& prompter, PromptSerializer& serializer, OperationPhaseSink& phaseSink,
    std::string cardKey, std::string requester, std::string artifact, LibreSCRS::CancelToken token,
    std::shared_ptr<std::atomic<bool>> prompterFailed, std::shared_ptr<std::atomic<bool>> userCancelled = {},
    std::shared_ptr<std::atomic<bool>> providerMarkedWrong = {});

// Install @p provider on @p session and return a scope guard that, on
// destruction, replaces it with a stateless no-op provider. Use in EVERY flow
// that installs a flow-scoped provider (IdentityReadFlow, CertReadFlow,
// SignFlow, RawCryptoFlow): those providers capture the per-operation
// OperationPhaseSink by REFERENCE, but the CardSession is owned by the
// CardSessionHolder and OUTLIVES the flow — so a later channel/PACE
// re-establishment on the held session would otherwise invoke a lambda whose
// phaseSink has been destroyed (use-after-free). The guard's deleter runs at the
// caller's run()-scope exit (after the terminal op released its ActiveChannel
// holder, so setCredentialProvider does not re-enter a held channel) and is
// noexcept. The no-op returns "credentials required" until the next operation
// installs its own provider; it is a free function, so the std::function
// conversion in the deleter cannot allocate or throw during teardown.
[[nodiscard]] std::shared_ptr<void>
installScopedReadProvider(std::shared_ptr<LibreSCRS::SmartCard::CardSession> session,
                          LibreSCRS::Auth::CredentialProvider provider);

} // namespace FlowPrelude
} // namespace LibreSCRS::Agent::Operations
