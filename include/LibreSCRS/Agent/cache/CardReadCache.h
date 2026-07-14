// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace LibreSCRS::Agent {

// Per-Card in-memory cache of the most recent successful identity read. The
// cached CardReadSnapshot INCLUDES the face photo (a FieldType::Photo binary
// field), so identity + photo are cached together; populated by ReadIdentity,
// consumed by GetPhoto, dropped on CardRemoved.
//
// PII residency is bound to ACTIVE use (BACKLOG item 67): a SLIDING idle
// window — refreshed on every successful get() — keeps a card:// / plasmoid
// browsing session warm, while an idle entry is erased AND zeroized once the
// window elapses; the hard insertion boundary is invalidate() on CardRemoved.
// The identity strings + photo bytes are OPENSSL_cleanse'd before an entry is
// dropped (expiry, invalidate, clear, put-overwrite) so expired PII does not
// linger in freed heap. Never persisted.
//
// Thread-safe via an internal mutex — callers do NOT hold the agent's state
// mutex. get() is const but self-cleans expired entries (mutable map + clock).
class CardReadCache
{
public:
    // Steady clock seam (default steady_clock::now); injectable so the sliding
    // window + expiry are deterministically testable, mirroring CardSessionHolder.
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // Default idle window 5 min: long enough that active browsing never
    // re-reads, short enough that an abandoned card's PII does not linger. The
    // duration stays the first parameter so existing `CardReadCache(30s)`
    // construction (and the tests) keep compiling.
    explicit CardReadCache(std::chrono::steady_clock::duration idleWindow = std::chrono::minutes{5}, Clock clock = {});
    ~CardReadCache();

    void put(const std::string& cardKey, CardReadSnapshot snapshot);

    // Returns the cached snapshot and REFRESHES its idle timer (sliding); an
    // entry past the idle window is erased + zeroized and nullopt is returned.
    [[nodiscard]] std::optional<CardReadSnapshot> get(const std::string& cardKey) const;

    void invalidate(const std::string& cardKey);

    void clear();

private:
    struct Entry
    {
        CardReadSnapshot snapshot;
        std::chrono::steady_clock::time_point touchedAt;
    };

    // Zeroize the snapshot's PII buffers (identity text + photo/binary bytes)
    // before the Entry is dropped. noexcept — used on teardown paths.
    static void scrub(Entry& entry) noexcept;

    std::chrono::steady_clock::duration m_idleWindow;
    Clock m_clock;
    mutable std::mutex m_mutex;
    // mutable: a const get() self-cleans expired PII (erase + scrub).
    mutable std::unordered_map<std::string, Entry> m_entries;
};

} // namespace LibreSCRS::Agent
