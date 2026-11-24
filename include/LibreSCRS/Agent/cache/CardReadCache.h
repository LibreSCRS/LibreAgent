// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace LibreSCRS::Agent {

// Per-card in-memory cache of one inserted card's reads: the identity snapshot
// (which includes the face photo) and the enumerated signing certificates. Both
// halves share one entry, so CardRemoved drops everything and a single sliding
// idle window governs residency — read once per insertion, then serve browsing
// and cert re-reads from RAM instead of re-walking the card.
//
// Residency follows active use: the window is refreshed on every successful get,
// and an idle entry is erased + zeroized once it elapses. Every field buffer is
// secureZero'd before a (half-)entry is dropped so no card PII lingers in
// freed heap. Certificates are public but scrubbed uniformly. Never persisted.
//
// Thread-safe via an internal mutex. get()/getCertificates() are const but
// self-clean expired entries (mutable map + clock).
class CardReadCache
{
public:
    // Steady-clock seam (default steady_clock::now); injectable for deterministic
    // window/expiry tests.
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // Pass as the idle window to DISABLE idle expiry (card-lifetime residency):
    // the entry then lives until invalidate()/clear()/card removal, never on
    // idle time. For the immutable eID identity + certs, which cannot go stale
    // while the card is seated — any change is a physical re-issue, i.e. a card
    // removal, which already invalidates the cache. The production cache uses
    // this; the short default below is for the window/expiry unit tests.
    static constexpr std::chrono::steady_clock::duration kNoIdleExpiry = std::chrono::steady_clock::duration::max();

    // Idle window default 5 min: long enough that active use never re-reads,
    // short enough that an abandoned card's PII does not linger.
    explicit CardReadCache(std::chrono::steady_clock::duration idleWindow = std::chrono::minutes{5}, Clock clock = {});
    ~CardReadCache();

    // Identity (+ photo) half.
    void put(const std::string& cardKey, CardReadSnapshot snapshot);
    // Returns the cached identity and refreshes the shared idle timer; an entry
    // past the window is erased + zeroized and nullopt returned. A present entry
    // whose identity half is empty returns nullopt without evicting the certs.
    [[nodiscard]] std::optional<CardReadSnapshot> get(const std::string& cardKey) const;

    // Certificate half: same window + scrub semantics, sharing the entry and the
    // idle timer with the identity half.
    void putCertificates(const std::string& cardKey, std::vector<CertSnapshot> certs);
    [[nodiscard]] std::optional<std::vector<CertSnapshot>> getCertificates(const std::string& cardKey) const;

    void invalidate(const std::string& cardKey);

    // Card removal: like invalidate(), and afterwards put()/putCertificates()
    // under this key are dropped. Keys are minted per insertion and never reused,
    // so a read that finishes after the card was pulled (or a slot started for an
    // already-removed card) must not leave card data under the dead key. Only the
    // newest kRetiredCapacity keys are remembered, oldest forgotten first.
    void retire(const std::string& cardKey);

    // Drops every entry and forgets the retired keys.
    void clear();

    static constexpr std::size_t kRetiredCapacity = 256;

private:
    struct Entry
    {
        std::optional<CardReadSnapshot> identity;
        std::optional<std::vector<CertSnapshot>> certs;
        std::chrono::steady_clock::time_point touchedAt;
    };

    // Zeroize + reset one half (on same-half overwrite, so the other survives),
    // or the whole entry via scrub() on expiry/invalidate/clear. noexcept.
    static void cleanseIdentity(Entry& entry) noexcept;
    static void cleanseCerts(Entry& entry) noexcept;
    static void scrub(Entry& entry) noexcept;

    // Caller holds m_mutex: erase + scrub an entry past its window and return
    // nullptr; otherwise return the live Entry*. Does not slide the timer.
    [[nodiscard]] Entry* liveEntry(const std::string& cardKey) const;

    std::chrono::steady_clock::duration m_idleWindow;
    Clock m_clock;
    mutable std::mutex m_mutex;
    // mutable: a const get() self-cleans expired PII (erase + scrub).
    mutable std::unordered_map<std::string, Entry> m_entries;
    // Retired keys: the set answers membership, the deque keeps insertion order
    // for the bound. Both under m_mutex.
    std::deque<std::string> m_retiredOrder;
    std::unordered_set<std::string> m_retired;
};

} // namespace LibreSCRS::Agent
