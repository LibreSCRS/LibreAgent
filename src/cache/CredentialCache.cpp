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
    // A whole-entry erase, so the refusal generation goes back to 0 along with
    // the secrets. That is deliberate and it is safe IN ONE DIRECTION ONLY,
    // which is the direction that matters: an operation still holding a
    // captured generation of 1 or more now compares against 0 and finds itself
    // STILL WANTED, so at worst the holder is asked once more. The reverse --
    // an operation silenced for a refusal that never happened to the card in
    // front of it -- cannot arise from this, because the counter only ever
    // restarts BELOW what any live operation captured, never above it.
    m_entries.erase(cardKey);
}

void CredentialCache::clear()
{
    std::lock_guard lock(m_mutex);
    m_entries.clear();
}

void CredentialCache::markCredentialWrong(const std::string& cardKey)
{
    std::lock_guard lock(m_mutex);
    auto& entry = m_entries[cardKey]; // default-constructs on first failure for this card
    entry.can.reset();
    entry.mrz.reset();
    // The count and the message moved to the operation's AttemptContext: they
    // describe one read attempt, not the card. What stays here is the eviction
    // -- a rejected secret must never be replayed from cache.
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

void CredentialCache::noteRefusal(const std::string& cardKey, RefusalKind kind)
{
    std::lock_guard lock(m_mutex);
    auto& entry = m_entries[cardKey]; // default-constructs on first refusal
    ++entry.refusalGeneration;
    entry.refusalKind = kind;
}

std::uint64_t CredentialCache::refusalGenerationFor(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    return it == m_entries.end() ? 0U : it->second.refusalGeneration;
}

CredentialCache::RefusalKind CredentialCache::lastRefusalKindFor(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    return it == m_entries.end() ? RefusalKind::Timeout : it->second.refusalKind;
}

bool CredentialCache::stillWantedFor(const std::string& cardKey, const AttemptContext* attempts) const
{
    // refusalGenerationFor takes m_mutex itself; nothing here holds it first.
    return attempts == nullptr || refusalGenerationFor(cardKey) <= attempts->generationAtDispatch();
}

void CredentialCache::applyRetryContext(const AttemptContext& attempts, PromptOptions& opts)
{
    const std::uint32_t recorded = attempts.attempts();
    if (recorded == 0) {
        return; // no recorded rejection -- the first prompt of a fresh operation
    }
    opts.attempt = recorded + 1;
    opts.lastError = attempts.lastErrorKey();
}

} // namespace LibreSCRS::Agent
