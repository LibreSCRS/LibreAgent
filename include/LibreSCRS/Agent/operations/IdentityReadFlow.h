// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/AttemptContext.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/CancelToken.h>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

// Mostly-references dependency bundle (the sole exception is onCardType, a
// value callback). The caller (typically ReadIdentityOperation or
// GetPhotoOperation) guarantees the references outlive the flow's run()
// invocation.
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
    // Group sink: receives each field group, in read order, as the plugin
    // streams it during the read below -- strictly ahead of this run()'s own
    // one-shot Result, which stays the complete, authoritative set
    // regardless of what streamed. The production seam is the hosting
    // OperationBase (ReadIdentityOperation) or a NullGroupSink
    // (GetPhotoOperation -- see that seam's own doc comment for why); tests
    // pass a recording fake to assert order.
    GroupSink& groupSink;
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
    // Fired with the freshly-read CardData::cardType (via CardReadSnapshot)
    // right before a successful run() returns its Result — the SINGLE choke
    // point every fresh identity read passes through (ReadIdentity AND a
    // GetPhoto cache miss, on both daemons), so a caller with a card-property
    // update path to push into (the backend's Card1/card-state authoritative
    // cardType) wires this ONCE instead of duplicating the push at every call
    // site. Not invoked when the snapshot's cardType is empty (nothing new to
    // report) or the flow returns Cancelled/Error. Default (unset): a no-op,
    // for callers/tests with no property-update path to drive.
    std::function<void(const std::string&)> onCardType;
    // Deposits a user-chosen MRZ into the candidate plugins when the holder
    // renegotiated a CAN prompt into an MRZ read, so the ONE re-run below
    // resolves an MRZ-keyed activation profile. The production seam is
    // LmCredentialDepositor (plugin-registry-backed); a wiring site with no
    // registry to resolve deposit targets from passes NullCredentialDepositor.
    CredentialDepositor& depositor;
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

    // --- Observation seam (no production consumer) -------------------------
    //
    // The credential provider this flow installs on the held session, and the
    // flow-owned MRZ choice sink. Production drives BOTH through LM: readCard
    // invokes the provider on a channel cache miss, and run() consults the sink
    // itself — nothing outside this class reaches for either.
    //
    // They are exposed because LM's CardSession offers no accessor for an
    // installed credential provider, so a hermetic CardReader double cannot
    // model that on-cache-miss callback at all. Without this seam the
    // capability-derived alternative-kind offer and the renegotiation leg could
    // only be asserted against a provider the TEST built — which is exactly the
    // dead-wiring those assertions exist to rule out. The sink is valid from
    // construction; the provider is bound at the top of run() and EMPTY outside
    // it (it closes over run()-bounded references — see
    // FlowPrelude::ProviderResetGuard), so it is callable only from within a
    // seam the live run drives.
    [[nodiscard]] const LibreSCRS::Auth::CredentialProvider& credentialProvider() const noexcept
    {
        return m_provider;
    }
    [[nodiscard]] const std::shared_ptr<MrzChoiceSink>& choiceSink() const noexcept
    {
        return m_mrzChoice;
    }
    // This operation's own retry context (attempts belong to the operation,
    // not the card -- see AttemptContext). Bound at the top of run() (unlike
    // m_provider, it is never emptied at run() exit: it holds no run-scoped
    // references, so it stays safely observable after the run completes).
    // Exposed for the same reason credentialProvider() is: without it, moving
    // the attempt count off the cache and onto a per-run object makes it
    // unobservable from outside, and a test asserting "this run did not count
    // as a rejection" would have nothing left to assert against.
    [[nodiscard]] const AttemptContext& attemptContext() const noexcept
    {
        return *m_attempts;
    }

private:
    IdentityReadFlowDeps m_deps;
    // Flow-owned, never shared across runs: one sink per flow object, scrubbed
    // at run() exit whether or not it was consumed.
    std::shared_ptr<MrzChoiceSink> m_mrzChoice{std::make_shared<MrzChoiceSink>()};
    LibreSCRS::Auth::CredentialProvider m_provider;
    // Default-constructed (cold, generation 0) so attemptContext() is safe to
    // call before run() and on every early-return path; reassigned to a fresh
    // context seeded from the card's refusal generation at the top of run().
    std::shared_ptr<AttemptContext> m_attempts{std::make_shared<AttemptContext>()};
};

} // namespace LibreSCRS::Agent::Operations
