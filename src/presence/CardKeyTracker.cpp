// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/CardKeyTracker.h>
#include <utility>

namespace LibreSCRS::Agent {

void CardKeyTracker::setOnKeyRemoved(KeyRemovedFn cb)
{
    m_onRemoved = std::move(cb);
}

void CardKeyTracker::onCardInserted(const std::string& readerName, ObjectId cardId)
{
    // A re-insert without an intervening CardRemoved (rare but possible if the
    // monitor coalesces events) overwrites the previous mapping; the previous
    // card ObjectId is forwarded to the callback so its cache entry is dropped
    // before the new one becomes active.
    auto it = m_readerToCardKey.find(readerName);
    if (it != m_readerToCardKey.end()) {
        const ObjectId previous = it->second;
        m_readerToCardKey.erase(it);
        if (m_onRemoved) {
            m_onRemoved(previous, readerName);
        }
    }
    m_readerToCardKey.emplace(readerName, cardId);
}

void CardKeyTracker::onCardRemoved(const std::string& readerName)
{
    auto it = m_readerToCardKey.find(readerName);
    if (it == m_readerToCardKey.end()) {
        return; // unknown reader / no card mapped — silent no-op
    }
    const ObjectId dropped = it->second;
    m_readerToCardKey.erase(it);
    if (m_onRemoved) {
        m_onRemoved(dropped, readerName);
    }
}

void CardKeyTracker::onReaderRemoved(const std::string& readerName)
{
    // Reader gone: any card mapping under it is gone too. Same callback fire
    // as onCardRemoved — the cache key is the card ObjectId, not the reader
    // name, so the distinction does not matter to the cache.
    onCardRemoved(readerName);
}

std::optional<ObjectId> CardKeyTracker::currentKey(const std::string& readerName) const
{
    auto it = m_readerToCardKey.find(readerName);
    if (it == m_readerToCardKey.end()) {
        return std::nullopt;
    }
    return it->second;
}

} // namespace LibreSCRS::Agent
