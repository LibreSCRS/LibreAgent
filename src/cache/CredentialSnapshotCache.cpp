// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>

#include <LibreSCRS/Agent/SecureZero.h>

#include <optional>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

namespace {

void cleanse(std::string& s) noexcept
{
    if (!s.empty()) {
        secureZero(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size()));
    }
    s.clear();
}

void cleanse(std::optional<std::string>& s) noexcept
{
    if (s) {
        cleanse(*s);
        s.reset();
    }
}

// Zeroize every string buffer a credential record owns. The optional<int> / bool
// fields carry no heap buffer — they are released when the record is destroyed.
void cleanseRecord(CredentialRecord& record) noexcept
{
    cleanse(record.id);
    cleanse(record.label);
    cleanse(record.kind);
    cleanse(record.state);
    cleanse(record.recovery);
    cleanse(record.blockedGuidanceKey);
    cleanse(record.blockedGuidanceFallback);
    cleanse(record.keyActivationGuidanceKey);
    cleanse(record.keyActivationGuidanceFallback);
}

} // namespace

CredentialSnapshotCache::CredentialSnapshotCache(std::chrono::steady_clock::duration idleWindow, Clock clock)
    : m_idleWindow(idleWindow),
      m_clock(clock ? std::move(clock) : Clock{[] { return std::chrono::steady_clock::now(); }})
{}

CredentialSnapshotCache::~CredentialSnapshotCache()
{
    clear();
}

void CredentialSnapshotCache::scrub(Entry& entry) noexcept
{
    for (auto& record : entry.snapshot.records) {
        cleanseRecord(record);
    }
    entry.snapshot.records.clear();
    entry.snapshot.version = 0;
}

CredentialSnapshotCache::Entry* CredentialSnapshotCache::liveEntry(const std::string& cardKey) const
{
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end()) {
        return nullptr;
    }
    if ((m_clock() - it->second.touchedAt) > m_idleWindow) {
        scrub(it->second); // expired: erase AND zeroize the metadata, never return it
        m_entries.erase(it);
        return nullptr;
    }
    return &it->second;
}

std::uint64_t CredentialSnapshotCache::put(const std::string& cardKey, CredentialSnapshot snapshot)
{
    std::lock_guard lock(m_mutex);
    const std::uint64_t version = m_nextVersion++;
    snapshot.version = version;
    Entry& entry = m_entries[cardKey]; // default-constructs an empty entry if absent
    scrub(entry);                      // zeroize any prior snapshot we are overwriting
    entry.snapshot = std::move(snapshot);
    entry.touchedAt = m_clock();
    return version;
}

std::optional<CredentialSnapshot> CredentialSnapshotCache::get(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    Entry* entry = liveEntry(cardKey);
    if (entry == nullptr) {
        return std::nullopt;
    }
    entry->touchedAt = m_clock(); // sliding window: active use keeps the entry warm
    return entry->snapshot;
}

void CredentialSnapshotCache::invalidate(const std::string& cardKey)
{
    std::lock_guard lock(m_mutex);
    auto it = m_entries.find(cardKey);
    if (it == m_entries.end()) {
        return;
    }
    scrub(it->second);
    m_entries.erase(it);
}

void CredentialSnapshotCache::clear()
{
    std::lock_guard lock(m_mutex);
    for (auto& [key, entry] : m_entries) {
        scrub(entry);
    }
    m_entries.clear();
}

} // namespace LibreSCRS::Agent
