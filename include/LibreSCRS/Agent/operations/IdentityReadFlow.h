// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <optional>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

// References-only dependency bundle. Every member is a reference; the
// caller (typically ReadIdentityOperation or GetPhotoOperation)
// guarantees the references outlive the flow's run() invocation.
struct IdentityReadFlowDeps
{
    // Per-reader shared-session holder: the flow acquires the (reused) session
    // and the resolved candidate plugin list from it, instead of opening a fresh
    // session each run.
    CardSessionHolder& holder;
    CardReader& reader;
    PrompterClientBase& prompter;
    // Process-wide gate that admits at most one live prompter interaction
    // agent-wide. The flow wraps `prompter` in a per-op SerializingPrompter
    // bound to `token`, so a worker queued behind another reader's live prompt
    // blocks here (and breaks out on cancel) instead of stacking a second
    // dialog. A cache hit never reaches the gate, so card I/O stays parallel.
    PromptSerializer& serializer;
    CredentialCache& cache;
    // Phase sink: receives wire-stable Phase integers as the flow walks
    // its state machine. The production seam is the hosting OperationBase;
    // tests pass a recording fake to assert ordering.
    OperationPhaseSink& phaseSink;
    std::string cardKey;
    // Caller-identity chrome surfaced in the consent prompt so the user can
    // attribute the credential request. requester: a human-meaningful label
    // for the client that asked (e.g. its executable basename); artifact:
    // what is being read (e.g. "identity"). Both are CLIENT-SUPPLIED /
    // best-effort and may be empty; the prompter renders them in a visually
    // distinct, untrusted area (never as system chrome). Empty fields are
    // simply omitted from the prompt.
    std::string requester;
    std::string artifact;
    LibreSCRS::CancelToken token;
};

// Pure orchestration — no LM types in the public Result surface, no bus, no
// threading. Hermetic by construction: the seams are pure-virtual injection
// points. The flow installs the credential provider and drives the plugin
// read; the plugin self-activates its secure channel inside readCard, so the
// flow never drives channel activation itself.
class IdentityReadFlow
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

    explicit IdentityReadFlow(IdentityReadFlowDeps deps);
    [[nodiscard]] Result run();

private:
    IdentityReadFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
