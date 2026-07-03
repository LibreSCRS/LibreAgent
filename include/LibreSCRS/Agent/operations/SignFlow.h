// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {
class CredentialCache;
}

namespace LibreSCRS::Agent::Operations {

class PromptSerializer;
class CardSessionHolder;

// References-only dependency bundle. Mirrors CertReadFlowDeps; the open +
// install-credential-provider prelude is structurally identical to the sibling
// read flows (extracted into a shared helper at the close of this increment —
// SignFlow is the 3rd consumer, the reuse-≥2× bar).
struct SignFlowDeps
{
    // Per-reader shared-session holder: the flow acquires the (reused) session +
    // resolved candidate plugin list from it instead of opening fresh each run.
    CardSessionHolder& holder;
    Signer& signer;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    OperationPhaseSink& phaseSink;
    std::string cardKey;
    std::string requester;
    // The signing parameters (certId, document bytes, resolved format/level/
    // packaging, allowExpired, display chrome) resolved at the Card1.Sign entry.
    SignParams params;
    LibreSCRS::CancelToken token;
};

// Pure orchestration mirroring CertReadFlow, specialised for signing: open the
// held session -> install ONE unified credential provider (CAN cached / PIN
// uncached) that ALSO drives the wire phases -> call the Signer seam in-process
// (which holds the live shared_ptr<CardSession> so the PACE secure-messaging
// session is adopted, never re-established) -> seal the bytes upstream. No LM
// types in the public Result.
//
// Watchdog discipline: this flow sets only Connecting; the provider lambda
// drives AwaitingConsent (unbounded human PIN entry, never armed) then
// Authenticating + Signing AFTER the PIN is collected, so the per-op watchdog
// (armed on Authenticating) covers the on-card signing PSO but never times the
// human at the PIN prompt.
class SignFlow
{
public:
    enum class Outcome { Ok, Cancelled, Error };
    struct Result
    {
        Outcome outcome{Outcome::Error};
        ErrorCode code{ErrorCode::CommunicationError};
        std::vector<std::uint8_t> signedDocumentBytes;
        std::string resolvedFormat;
        std::string resolvedLevel;
        bool tsaUsed{false};
        bool chainComplete{false};
        // Candidate plugin list resolved for the held session. Threaded for
        // capability-aware routing; not consumed by the current single-seam sign.
        CandidateList candidates;
        std::string msgKey;
        std::string msgFallback;
    };

    explicit SignFlow(SignFlowDeps deps);
    [[nodiscard]] Result run();

private:
    SignFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
