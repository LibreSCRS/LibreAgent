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

void CredentialCache::markCredentialWrong(const std::string& cardKey, std::string errorMsgKey)
{
    std::lock_guard lock(m_mutex);
    auto& entry = m_entries[cardKey]; // default-constructs on first failure for this card
    entry.can.reset();
    entry.mrz.reset();
    entry.failedAttempts += 1;
    entry.lastErrorKey = std::move(errorMsgKey);
}

bool CredentialCache::lastPromptYieldedNothingFor(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    return it != m_entries.end() && it->second.lastPromptYieldedNothing;
}

void CredentialCache::noteLastPromptYieldedNothing(const std::string& cardKey, bool yieldedNothing)
{
    std::lock_guard lock(m_mutex);
    // Only create an entry to REMEMBER an empty prompt. Clearing a card that
    // has no entry has nothing to clear, and default-constructing one there
    // would put every card that ever answered a prompt into the map.
    if (!yieldedNothing) {
        if (auto it = m_entries.find(cardKey); it != m_entries.end()) {
            it->second.lastPromptYieldedNothing = false;
        }
        return;
    }
    m_entries[cardKey].lastPromptYieldedNothing = true;
}

std::uint32_t CredentialCache::failedAttemptsFor(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    return it == m_entries.end() ? 0U : it->second.failedAttempts;
}

void CredentialCache::applyRetryContext(const std::string& cardKey, PromptOptions& opts) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end() || it->second.failedAttempts == 0) {
        return; // no recorded failure -- first-ever prompt for this card
    }
    opts.attempt = it->second.failedAttempts + 1;
    opts.lastError = it->second.lastErrorKey;
}

} // namespace LibreSCRS::Agent
