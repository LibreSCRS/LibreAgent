// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/CancelToken.h>
#include <string>

namespace LibreSCRS::Agent {
class CredentialCache;
class CredentialSnapshotCache;
} // namespace LibreSCRS::Agent

namespace LibreSCRS::Agent::Operations {

class PromptSerializer;
class CardSessionHolder;

// References-only dependency bundle. Mirrors CertReadFlowDeps (the credential
// list is a read that shares the open + install-read-credential-provider prelude
// in FlowPrelude): the flow acquires the held session + resolved candidates from
// the holder, installs the CAN/PACE read provider so a pre-auth card can activate
// its channel inside getPINList, then lists the card's PIN credentials.
struct CredentialListFlowDeps
{
    CardSessionHolder& holder;
    CredentialManager& credentials;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    // Per-card snapshot store: on a successful list the produced CredentialSnapshot
    // is stamped with the next monotonic version and stored here (the returned
    // snapshot carries the same version). Distinct from `cache` (CAN/MRZ secrets).
    CredentialSnapshotCache& snapshotCache;
    OperationPhaseSink& phaseSink;
    std::string cardKey;
    std::string requester;
    std::string artifact;
    LibreSCRS::CancelToken token;
};

// Pure orchestration: open the held session -> install the read credential
// provider -> list the card's PIN credentials -> map each entry to a wire
// CredentialRecord and disambiguate colliding ids -> return a CredentialSnapshot.
// No LM plugin types in the public Result; no bus, no threading. The flow is
// cache-free: the snapshot version is left at its default until the credential
// cache stamps it.
class CredentialListFlow
{
public:
    enum class Outcome { Ok, Cancelled, Error };
    struct Result
    {
        Outcome outcome{Outcome::Error};
        ErrorCode code{ErrorCode::CommunicationError};
        CredentialSnapshot snapshot;
        // Candidate plugin list resolved for the held session. Threaded for the
        // capability-aware routing the sibling flows share; not consumed by the
        // current single-seam list.
        CandidateList candidates;
        std::string msgKey;
        std::string msgFallback;
    };

    explicit CredentialListFlow(CredentialListFlowDeps deps);
    [[nodiscard]] Result run();

private:
    CredentialListFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
