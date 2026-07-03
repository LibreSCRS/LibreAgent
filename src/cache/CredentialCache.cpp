// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <utility>

namespace LibreSCRS::Agent {

void CredentialCache::putCan(const std::string& cardKey, Secret can)
{
    std::lock_guard lock(m_mutex);
    m_entries[cardKey].can = std::move(can);
}

void CredentialCache::putMrz(const std::string& cardKey, Secret mrz)
{
    std::lock_guard lock(m_mutex);
    m_entries[cardKey].mrz = std::move(mrz);
}

std::optional<CredentialCache::Secret> CredentialCache::getCan(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end() || !it->second.can.has_value()) {
        return std::nullopt;
    }
    return it->second.can;
}

std::optional<CredentialCache::Secret> CredentialCache::getMrz(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end() || !it->second.mrz.has_value()) {
        return std::nullopt;
    }
    return it->second.mrz;
}

bool CredentialCache::hasCan(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    return it != m_entries.end() && it->second.can.has_value();
}

bool CredentialCache::hasMrz(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    return it != m_entries.end() && it->second.mrz.has_value();
}

void CredentialCache::invalidate(const std::string& cardKey)
{
    std::lock_guard lock(m_mutex);
    m_entries.erase(cardKey);
}

void CredentialCache::clear()
{
    std::lock_guard lock(m_mutex);
    m_entries.clear();
}

} // namespace LibreSCRS::Agent
