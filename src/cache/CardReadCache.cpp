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

// Zeroize each field's text/binary buffer. Shared by both halves: identity
// groups and cert fields are the same GroupSnapshot value type.
void cleanseGroups(std::vector<GroupSnapshot>& groups) noexcept
{
    for (auto& group : groups) {
        for (auto& field : group.fields) {
            cleanse(field.textValue);
            cleanse(field.binaryValue);
        }
    }
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

void CardReadCache::cleanseIdentity(Entry& entry) noexcept
{
    if (!entry.identity) {
        return;
    }
    cleanseGroups(entry.identity->groups);
    entry.identity.reset();
}

void CardReadCache::cleanseCerts(Entry& entry) noexcept
{
    if (!entry.certs) {
        return;
    }
    for (auto& cert : *entry.certs) {
        // Public identifiers, but zeroized for uniformity so no card bytes linger.
        cleanse(cert.certId);
        for (auto& oid : cert.ekuOids) {
            cleanse(oid);
        }
        for (auto& cn : cert.chainSubjectCns) {
            cleanse(cn);
        }
        cleanseGroups(cert.fields);
    }
    entry.certs.reset();
}

void CardReadCache::scrub(Entry& entry) noexcept
{
    cleanseIdentity(entry);
    cleanseCerts(entry);
}

CardReadCache::Entry* CardReadCache::liveEntry(const std::string& cardKey) const
{
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end()) {
        return nullptr;
    }
    // kNoIdleExpiry disables idle expiry entirely (card-lifetime residency): the
    // entry lives until invalidate()/clear()/card removal. Otherwise the sliding
    // idle window governs residency as usual.
    if (m_idleWindow != kNoIdleExpiry && (m_clock() - it->second.touchedAt) > m_idleWindow) {
        scrub(it->second); // expired: erase AND zeroize the PII, never return it
        m_entries.erase(it);
        return nullptr;
    }
    return &it->second;
}

void CardReadCache::put(const std::string& cardKey, CardReadSnapshot snapshot)
{
    std::lock_guard lock(m_mutex);
    Entry& entry = m_entries[cardKey]; // default-constructs an empty entry if absent
    cleanseIdentity(entry);            // zeroize the identity half we are overwriting; certs survive
    entry.identity = std::move(snapshot);
    entry.touchedAt = m_clock();
}

std::optional<CardReadSnapshot> CardReadCache::get(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    Entry* entry = liveEntry(cardKey);
    if (entry == nullptr || !entry->identity) {
        return std::nullopt;
    }
    entry->touchedAt = m_clock(); // sliding window: active use keeps the whole entry warm
    return entry->identity;
}

void CardReadCache::putCertificates(const std::string& cardKey, std::vector<CertSnapshot> certs)
{
    std::lock_guard lock(m_mutex);
    Entry& entry = m_entries[cardKey];
    cleanseCerts(entry); // zeroize the cert half we are overwriting; identity survives
    entry.certs = std::move(certs);
    entry.touchedAt = m_clock();
}

std::optional<std::vector<CertSnapshot>> CardReadCache::getCertificates(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    Entry* entry = liveEntry(cardKey);
    if (entry == nullptr || !entry->certs) {
        return std::nullopt;
    }
    entry->touchedAt = m_clock(); // sliding window: shared with the identity half
    return entry->certs;
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
