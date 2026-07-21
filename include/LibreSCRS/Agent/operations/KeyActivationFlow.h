// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/Agent/operations/Seams.h>             // CredentialManager, OperationPhaseSink
#include <LibreSCRS/Agent/value/CredentialRecord.h>       // CredentialRecord, CredentialOpResult
#include <LibreSCRS/CancelToken.h>
#include <optional>
#include <string>

namespace LibreSCRS::Agent {
class CredentialCache;
class CredentialSnapshotCache;
class CardReadCache;
} // namespace LibreSCRS::Agent

namespace LibreSCRS::Agent::Operations {

class PrompterClientBase;
class PromptSerializer;
class CardSessionHolder;

// References-only dependency bundle for the standalone signing-key activation
// flow. Mirrors the sibling flows' deps bundles (see CertReadFlowDeps): the flow
// acquires the reused held session + resolved candidate plugin list from the
// holder, prompts the operational SIGN PIN as a single secret, and drives the
// CredentialManager::activateSigningKey seam. The references must outlive the
// runKeyActivation() call; the value members (record/cardKey/... /pinActivated)
// are copied in.
struct KeyActivationFlowDeps
{
    CardSessionHolder& holder;
    CredentialManager& credentials;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    // Caches invalidated when the activation reaches the card (see
    // invalidateForMutationOutcome): the per-card credential snapshot and the
    // identity/cert read cache. The CAN/MRZ secret cache (`cache`) is never among
    // them — an activation must not evict a still-valid pre-read secret.
    CredentialSnapshotCache& snapshotCache;
    CardReadCache& cardReadCache;
    OperationPhaseSink& phaseSink;
    // The signing-key credential this activation addresses, already resolved from
    // the latest snapshot by the caller (entry gating validated the id). The flow
    // gates on record.keyActivatable BEFORE prompting: a card that cannot activate
    // its signing key answers Unsupported without ever raising a PIN dialog.
    CredentialRecord record;
    // Identity of the plugin whose listing produced the snapshot `record` was
    // resolved from (CredentialSnapshot::listPluginId; empty when unknown). The
    // activation is routed to this plugin FIRST — the record belongs to its
    // listing, so another candidate must not intercept the mutation.
    std::string listPluginId;
    std::string cardKey;
    std::string requester; // resolved, sanitized caller id (audit line only)
    std::string reader;    // human reader name (audit line only)
    std::string artifact;  // trusted, agent-owned operation category
    // Continuation state from a just-completed transport-PIN bring-up: carried
    // verbatim into the result's pinActivated (nullopt for a standalone run).
    std::optional<bool> pinActivated;
    LibreSCRS::CancelToken token;
};

// Pure orchestration, no LM types in the public result: gate on the record's
// keyActivatable capability -> open the held session + install the channel
// credential provider -> prompt the SIGN PIN once (single secret, never cached,
// never an fd) -> activateSigningKey(session, signPin) -> map PINResult onto a
// wire-facing CredentialOpResult (keyActivated=true only on Ok; the LM outcome —
// including KeyActivationFailed — is preserved verbatim, its wire ErrorCode
// mapping being a later task's job). No bus, no threading.
//
// Increment #1: no LM plugin overrides activateSigningKey yet, so the real seam
// answers Unsupported and this flow passes that valid outcome through.
[[nodiscard]] CredentialOpResult runKeyActivation(KeyActivationFlowDeps deps);

} // namespace LibreSCRS::Agent::Operations
