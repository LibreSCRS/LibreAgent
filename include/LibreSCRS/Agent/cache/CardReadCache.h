// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace LibreSCRS::Agent {

// Per-Card in-memory cache of the most recent successful identity read.
// 30 s default TTL, populated by ReadIdentity, consumed by GetPhoto
// (or refreshed if stale), dropped on CardRemoved.
//
// Thread-safe via an internal mutex — callers do NOT need to hold the
// agent's state mutex.
class CardReadCache
{
public:
    explicit CardReadCache(std::chrono::steady_clock::duration ttl = std::chrono::seconds{30});

    void put(const std::string& cardKey, CardReadSnapshot snapshot);

    [[nodiscard]] std::optional<CardReadSnapshot> get(const std::string& cardKey) const;

    void invalidate(const std::string& cardKey);

    void clear();

private:
    struct Entry
    {
        CardReadSnapshot snapshot;
        std::chrono::steady_clock::time_point storedAt;
    };

    std::chrono::steady_clock::duration m_ttl;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, Entry> m_entries;
};

} // namespace LibreSCRS::Agent
