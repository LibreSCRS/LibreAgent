// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/cache/CardReadCache.h>

#include <openssl/crypto.h> // OPENSSL_cleanse (zeroize PII on drop)

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

namespace {

void cleanse(std::string& s) noexcept
{
    if (!s.empty()) {
        OPENSSL_cleanse(s.data(), s.size());
    }
    s.clear();
}

void cleanse(std::vector<std::uint8_t>& v) noexcept
{
    if (!v.empty()) {
        OPENSSL_cleanse(v.data(), v.size());
    }
    v.clear();
}

} // namespace

CardReadCache::CardReadCache(std::chrono::steady_clock::duration idleWindow, Clock clock)
    : m_idleWindow(idleWindow),
      m_clock(clock ? std::move(clock) : Clock{[] { return std::chrono::steady_clock::now(); }})
{}

CardReadCache::~CardReadCache()
{
    clear();
}

void CardReadCache::scrub(Entry& entry) noexcept
{
    // Zeroize every field's PII buffer (identity text/date strings and photo/
    // binary bytes) so the values do not linger in freed heap after the Entry
    // is dropped. Photos ride as FieldType::Photo binaryValue.
    for (auto& group : entry.snapshot.groups) {
        for (auto& field : group.fields) {
            cleanse(field.textValue);
            cleanse(field.binaryValue);
        }
    }
}

void CardReadCache::put(const std::string& cardKey, CardReadSnapshot snapshot)
{
    std::lock_guard lock(m_mutex);
    if (auto it = m_entries.find(cardKey); it != m_entries.end()) {
        scrub(it->second); // zeroize the value we are about to overwrite
        it->second = Entry{std::move(snapshot), m_clock()};
    } else {
        m_entries.emplace(cardKey, Entry{std::move(snapshot), m_clock()});
    }
}

std::optional<CardReadSnapshot> CardReadCache::get(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end()) {
        return std::nullopt;
    }
    if ((m_clock() - it->second.touchedAt) > m_idleWindow) {
        scrub(it->second); // expired: erase AND zeroize the PII, never return it
        m_entries.erase(it);
        return std::nullopt;
    }
    it->second.touchedAt = m_clock(); // sliding window: active use keeps it warm
    return it->second.snapshot;
}

void CardReadCache::invalidate(const std::string& cardKey)
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end()) {
        return;
    }
    scrub(it->second);
    m_entries.erase(it);
}

void CardReadCache::clear()
{
    std::lock_guard lock(m_mutex);
    for (auto& [key, entry] : m_entries) {
        scrub(entry);
    }
    m_entries.clear();
}

} // namespace LibreSCRS::Agent
