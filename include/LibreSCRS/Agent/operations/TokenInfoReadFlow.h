// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <optional>
#include <string>

namespace LibreSCRS::Agent {
class CredentialCache;
}

namespace LibreSCRS::Agent::Operations {

class PromptSerializer;
class CardSessionHolder;

// References-only dependency bundle. Mirrors CertReadFlowDeps (same
// PKI-gated, PIN-free-in-the-common-case shape — token info is PKI-adjacent,
// exactly like certificate reads); the open + install-credential-provider
// prelude shared with the sibling flows lives in the FlowPrelude helper.
struct TokenInfoReadFlowDeps
{
    // Per-reader shared-session holder: the flow acquires the (reused)
    // session + resolved candidate plugin list from it instead of opening a
    // fresh session each run.
    CardSessionHolder& holder;
    // The identity-reader seam: readTokenInfo() is a sibling of read(),
    // exactly as CardPlugin::readTokenInfo is a sibling of
    // CardPlugin::readCard. Production: LmCardReader.
    CardReader& reader;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    OperationPhaseSink& phaseSink;
    std::string cardKey;
    // Human reader name, used only for the per-request audit line (a
    // token-info read is PIN-free in the common case, so it never reaches
    // the consent prompt that would otherwise record the requester).
    std::string readerName;
    std::string requester;
    std::string artifact;
    LibreSCRS::CancelToken token;
};

// Pure orchestration: open the held session -> install the CAN/PACE
// credential provider unconditionally (the plugin self-activates inside
// readTokenInfo and only then invokes it on a cache miss, exactly like
// readCard/readCertificates) -> read the token-info group off the
// PKI-capable candidate subset -> a ONE-group CardReadSnapshot (groupKey
// "token"). No LM types in the public Result; no bus, no threading.
//
// An unsupported plugin's empty group is a SUCCESS with zero fields (the
// spec's empty-group resilience) — there is no read-failure ErrorCode for
// this flow; the only non-Ok/non-Cancelled outcome is a session-open failure
// (FlowPrelude::openSession) or PrompterError (the CAN/MRZ prompt UI itself
// was unreachable — not a wrong secret, not the card).
class TokenInfoReadFlow
{
public:
    enum class Outcome { Ok, Cancelled, Error };
    struct Result
    {
        Outcome outcome{Outcome::Error};
        ErrorCode code{ErrorCode::CommunicationError};
        std::optional<CardReadSnapshot> snapshot;
        // Candidate plugin list resolved for the held session. Threaded for
        // capability-aware routing; not consumed by the current single-seam read.
        CandidateList candidates;
        std::string msgKey;
        std::string msgFallback;
    };

    explicit TokenInfoReadFlow(TokenInfoReadFlowDeps deps);
    [[nodiscard]] Result run();

private:
    TokenInfoReadFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
