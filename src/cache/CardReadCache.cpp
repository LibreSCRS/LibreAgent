// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <utility>

namespace LibreSCRS::Agent {

CardReadCache::CardReadCache(std::chrono::steady_clock::duration ttl) : m_ttl(ttl) {}

void CardReadCache::put(const std::string& cardKey, CardReadSnapshot snapshot)
{
    std::lock_guard lock(m_mutex);
    m_entries[cardKey] = Entry{std::move(snapshot), std::chrono::steady_clock::now()};
}

std::optional<CardReadSnapshot> CardReadCache::get(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end()) {
        return std::nullopt;
    }
    if ((std::chrono::steady_clock::now() - it->second.storedAt) > m_ttl) {
        return std::nullopt;
    }
    return it->second.snapshot;
}

void CardReadCache::invalidate(const std::string& cardKey)
{
    std::lock_guard lock(m_mutex);
    m_entries.erase(cardKey);
}

void CardReadCache::clear()
{
    std::lock_guard lock(m_mutex);
    m_entries.clear();
}

} // namespace LibreSCRS::Agent
