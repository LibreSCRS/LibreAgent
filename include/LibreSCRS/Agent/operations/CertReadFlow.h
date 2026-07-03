// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {
class CredentialCache;
}

namespace LibreSCRS::Agent::Operations {

class PromptSerializer;
class CardSessionHolder;

// References-only dependency bundle. Mirrors IdentityReadFlowDeps; the open +
// install-credential-provider prelude shared with the sibling read and sign
// flows lives in the FlowPrelude helper.
struct CertReadFlowDeps
{
    // Per-reader shared-session holder: the flow acquires the (reused) session +
    // resolved candidate plugin list from it instead of opening fresh each run.
    CardSessionHolder& holder;
    CertificateReader& certReader;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    OperationPhaseSink& phaseSink;
    std::string cardKey;
    // Human reader name, used only for the per-request audit line (a cert read
    // is PIN-free, so it never reaches the consent prompt that would otherwise
    // record the requester).
    std::string reader;
    std::string requester;
    std::string artifact;
    LibreSCRS::CancelToken token;
};

// Pure orchestration: open the held session -> install the CAN/PACE credential
// provider unconditionally (the plugin self-activates inside readCertificates and
// only then invokes it on a cache miss) -> read + parse certs. No LM types in the
// public Result; no bus, no threading.
class CertReadFlow
{
public:
    enum class Outcome { Ok, Cancelled, Error };
    struct Result
    {
        Outcome outcome{Outcome::Error};
        ErrorCode code{ErrorCode::CommunicationError};
        std::vector<CertSnapshot> certs;
        // Candidate plugin list resolved for the held session. Threaded for
        // capability-aware routing; not consumed by the current single-seam read.
        CandidateList candidates;
        std::string msgKey;
        std::string msgFallback;
    };

    explicit CertReadFlow(CertReadFlowDeps deps);
    [[nodiscard]] Result run();

private:
    CertReadFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
