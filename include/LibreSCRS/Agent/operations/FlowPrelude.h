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
[[nodiscard]] LibreSCRS::Auth::CredentialProvider
makeReadCredentialProvider(CredentialCache& cache, PrompterClientBase& prompter, PromptSerializer& serializer,
                           OperationPhaseSink& phaseSink, std::string cardKey, std::string requester,
                           std::string artifact, LibreSCRS::CancelToken token,
                           std::shared_ptr<std::atomic<bool>> prompterFailed);

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
