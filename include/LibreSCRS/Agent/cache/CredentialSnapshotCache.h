// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace LibreSCRS::Agent {

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
// every get, and scrub-on-drop — every record string is secureZero'd before
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
    // card and by the card-removal hook.
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

} // namespace LibreSCRS::Agent
