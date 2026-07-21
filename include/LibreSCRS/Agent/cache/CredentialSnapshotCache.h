// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot, CredentialOutcome
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace LibreSCRS::Agent {

// Forward decl: the post-mutation invalidation helper below drops this card's
// cached identity/cert reads too, but the snapshot cache itself never depends on
// CardReadCache's definition (only the .cpp includes it).
class CardReadCache;

// Per-card in-memory cache of the credential SNAPSHOT a ListCredentials produced:
// the enumerated PIN/PUK/key records (labels, lifecycle state, retry counters)
// that the mutation flows resolve their addressed record from. This is a DISTINCT
// type from CredentialCache — deliberately so. CredentialCache caches the CAN/MRZ
// pre-read SECRETS; this cache holds NO secret (no PIN, no CAN) and the two are
// never conflated. The two also invalidate under different rules: any credential
// mutation that reaches the card drops THIS snapshot (the retry counters / state
// it enumerated may have moved) but must NOT evict a still-valid pre-read secret.
//
// Every stored snapshot is stamped with a strictly-increasing version — agent-wide
// monotonic, never reused, and never reset (not even across an invalidate followed
// by a fresh list). The version is INTERNAL freshness bookkeeping only: it never
// crosses the wire and no client-visible comparison exists today. Its guarantees
// (strictly increasing, never reused) are pinned by CredentialSnapshotCacheTest so
// a future wire exposure could rely on them; version 0 is reserved for a snapshot
// that never passed through this cache.
//
// Residency mirrors the sibling CardReadCache: a sliding idle window refreshed on
// every get, and scrub-on-drop — every record string is OPENSSL_cleanse'd before
// an entry is dropped (overwrite / expiry / invalidate / clear) so no card-derived
// label or lifecycle state lingers in freed heap. Never persisted.
//
// Thread-safe via an internal mutex; callers do NOT hold the agent state mutex.
// get() is const but self-cleans an entry past its window (mutable map + clock).
class CredentialSnapshotCache
{
public:
    // Steady-clock seam (default steady_clock::now); injectable for deterministic
    // window/expiry tests, exactly as CardReadCache exposes it.
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // Idle window default 5 min, matching CardReadCache: long enough that a
    // list-then-mutate sequence never re-lists, short enough that an abandoned
    // card's credential metadata does not linger.
    explicit CredentialSnapshotCache(std::chrono::steady_clock::duration idleWindow = std::chrono::minutes{5},
                                     Clock clock = {});
    ~CredentialSnapshotCache();

    // Store @p snapshot under @p cardKey, stamping it with the next monotonic
    // version and returning that version. Both the STORED copy and the returned
    // value carry the stamp, so the list flow can stamp the snapshot it hands back
    // to the client to match the cached one. Replaces (scrubs) any prior snapshot.
    std::uint64_t put(const std::string& cardKey, CredentialSnapshot snapshot);

    // The cached snapshot (carrying its stamped version) and slide the idle timer;
    // an entry past the window is erased + scrubbed and nullopt returned.
    [[nodiscard]] std::optional<CredentialSnapshot> get(const std::string& cardKey) const;

    // Drop + scrub this card's snapshot. Invoked by a mutation that reached the
    // card (see invalidateForMutationOutcome) and by the card-removal hook.
    // Idempotent: a no-op when nothing is cached for @p cardKey.
    void invalidate(const std::string& cardKey);

    // Drop + scrub everything (shutdown / idle-exit).
    void clear();

private:
    struct Entry
    {
        CredentialSnapshot snapshot;
        std::chrono::steady_clock::time_point touchedAt;
    };

    // Zeroize every record string then empty the snapshot. noexcept.
    static void scrub(Entry& entry) noexcept;

    // Caller holds m_mutex: erase + scrub an entry past its window and return
    // nullptr; otherwise return the live Entry*. Does not slide the timer.
    [[nodiscard]] Entry* liveEntry(const std::string& cardKey) const;

    std::chrono::steady_clock::duration m_idleWindow;
    Clock m_clock;
    mutable std::mutex m_mutex;
    // mutable: a const get() self-cleans an expired entry (erase + scrub).
    mutable std::unordered_map<std::string, Entry> m_entries;
    // Monotonic version source. Starts at 1; 0 is reserved for "never cached".
    std::uint64_t m_nextVersion = 1;
};

// True iff a completed credential mutation with this outcome may have changed the
// card's on-card credential state — so a cached snapshot (and the cached
// identity/cert reads) for that card are now potentially stale.
//
//   * Ok / InvalidPin / Blocked / KeyActivationFailed reached the card and moved
//     its state (a mutation applied, or a PIN presentation decremented the retry
//     counter / blocked the credential / stepped the key lifecycle).
//   * PluginError is treated conservatively as "may have reached the card": a
//     mid-seam error is ambiguous, and serving a stale snapshot is worse than an
//     extra re-list.
//   * The remaining outcomes did NOT change card state — the two this policy calls
//     out (UserCancelled: prompter-only, no card contact; Unsupported: capability
//     short-circuit or seam "not supported", nothing applied) plus MissingFields
//     (required fields never presented), CardRemoved (card gone before the seam;
//     the removal hook owns that eviction) and Unspecified (a fail-closed / non-
//     card open failure) — so they return false and leave the caches intact.
[[nodiscard]] bool mutationReachedCard(CredentialOutcome outcome) noexcept;

// Apply the post-mutation invalidation RULE for one card: when
// mutationReachedCard(outcome) holds, drop this card's cached credential snapshot
// AND its cached identity/cert reads, since on-card state may have moved. The
// CAN/MRZ secret cache (CredentialCache) is deliberately NOT a parameter and is
// never touched here — a mutation must not evict a still-valid pre-read secret.
//
// NOTE: the mutation flows (PinChangeFlow / KeyActivationFlow) now invalidate on
// GROUND-TRUTH card-reach — a flow-local flag set immediately before the seam
// call — rather than inferring reach from the returned outcome, so a mid-op
// CardRemoved still drops the (possibly-partial) snapshot and a pre-seam open
// failure preserves it. This outcome-classified helper is retained as the
// documented mapping of "which outcomes imply the card was reached" and is
// exercised directly by CredentialSnapshotCacheTest.
void invalidateForMutationOutcome(CredentialOutcome outcome, const std::string& cardKey,
                                  CredentialSnapshotCache& snapshotCache, CardReadCache& cardReadCache);

} // namespace LibreSCRS::Agent
