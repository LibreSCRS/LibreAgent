// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot, CredentialOpResult, EntryError
#include <LibreSCRS/Agent/operations/Seams.h>       // CredentialManager, OperationPhaseSink, PrompterClientBase
#include <LibreSCRS/CancelToken.h>
#include <expected>
#include <string>

namespace LibreSCRS::Agent {
class CredentialCache;
class CredentialSnapshotCache;
class CardReadCache;
} // namespace LibreSCRS::Agent

namespace LibreSCRS::Agent::Operations {

class PromptSerializer;
class CardSessionHolder;

// Client-issued credential-mutation request. `pinId` addresses one record from
// the latest ListCredentials snapshot (CredentialRecord.id); `verb` selects the
// mutation; `activateKey` is only meaningful with the "activate_pin" verb.
struct PinManageRequest
{
    std::string cardKey;
    std::string pinId; // CredentialRecord.id from the latest snapshot
    std::string verb;  // "change" | "unblock" | "activate_pin"
    bool activateKey = false;
};

// References-only dependency bundle, mirroring CertReadFlowDeps. `snapshot` is
// the latest per-card ListCredentials snapshot the client produced (a null /
// id-less snapshot is rejected by validatePinManageRequest before any Operation
// runs); runPinManage resolves the addressed record — its label, length bounds
// and capability flags — from it. The seams (holder / credentialManager /
// prompter / serializer / cache / phaseSink) must outlive the call.
struct PinManageFlowDeps
{
    CardSessionHolder& holder;
    CredentialManager& credentialManager;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    // Caches invalidated when the mutation reaches the card (see
    // invalidateForMutationOutcome): the per-card credential snapshot and the
    // identity/cert read cache. The CAN/MRZ secret cache (`cache`) is NOT among
    // them — a mutation must not evict a still-valid pre-read secret.
    CredentialSnapshotCache& snapshotCache;
    CardReadCache& cardReadCache;
    OperationPhaseSink& phaseSink;
    const CredentialSnapshot* snapshot = nullptr;
    std::string cardKey;
    std::string requester;
    // Human reader name — the card/token identity the change modal displays as
    // its card_label (and the audit line names).
    std::string reader;
    std::string artifact;
    LibreSCRS::CancelToken token;
};

// Entry validation: a typed error is produced BEFORE any Operation exists, so a
// malformed request never spins up a worker. Rejects an unknown verb
// (UnknownVerb), `activateKey` paired with a verb other than "activate_pin"
// (InvalidCombination), a pinId that resolves to no record — including the
// null-snapshot case, i.e. a client that never listed (UnknownCredential; the
// flow never auto-runs an implicit list, which could prompt for CAN inside a
// call the user did not frame as a read) — and a pinId whose record's label is
// not unique within the snapshot (AmbiguousCredential: the seam addresses the
// card by label, so the plugin must never guess between two same-label PINs).
// The undefined-options-key case is constructed at the adaptor layer and maps
// to UnknownOption there.
[[nodiscard]] std::expected<void, EntryError> validatePinManageRequest(const PinManageRequest& r,
                                                                       const CredentialSnapshot* snapshot);

// The mutation flow. In this first cut, verb=="change" collects the current +
// new PIN through the multi-secret prompter seam and drives the credential
// seam's changePIN, mapping the LM PINResult onto a CredentialOpResult. The
// other verbs short-circuit to the Unsupported outcome WITHOUT prompting (no
// prompter kinds exist for them yet; see the .cpp). Assumes the request already
// passed validatePinManageRequest.
[[nodiscard]] CredentialOpResult runPinManage(PinManageFlowDeps& deps, const PinManageRequest& request);

} // namespace LibreSCRS::Agent::Operations
