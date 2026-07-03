// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <algorithm>
namespace LibreSCRS::Agent {

void ObjectRegistry::setObservers(AddReaderFn addReader, AddCardFn addCard, RemovedFn removed, ChangedFn changed)
{
    m_addReader = std::move(addReader);
    m_addCard = std::move(addCard);
    m_removed = std::move(removed);
    m_changed = std::move(changed);
}

void ObjectRegistry::addReader(const ReaderState& reader)
{
    if (contains(reader.id)) {
        return;
    }
    m_readers.push_back(reader);
    if (m_addReader) {
        m_addReader(m_readers.back());
    }
}

void ObjectRegistry::addCard(const CardState& card)
{
    if (contains(card.id)) {
        return;
    }
    m_cards.push_back(card);
    if (m_addCard) {
        m_addCard(m_cards.back());
    }
}

void ObjectRegistry::remove(ObjectId id)
{
    if (auto it = std::find_if(m_readers.begin(), m_readers.end(), [&](const ReaderState& r) { return r.id == id; });
        it != m_readers.end()) {
        m_readers.erase(it);
        if (m_removed) {
            m_removed(id);
        }
        return;
    }
    if (auto it = std::find_if(m_cards.begin(), m_cards.end(), [&](const CardState& c) { return c.id == id; });
        it != m_cards.end()) {
        m_cards.erase(it);
        if (m_removed) {
            m_removed(id);
        }
    }
}

void ObjectRegistry::update(ObjectId reader, const PropertyDelta& delta)
{
    if (!reader.valid()) {
        return;
    }
    auto it = std::find_if(m_readers.begin(), m_readers.end(), [&](const ReaderState& r) { return r.id == reader; });
    if (it == m_readers.end()) {
        return;
    }
    if (it->hasCard == delta.hasCard && it->card == delta.card) {
        return; // no-change delta: no notification
    }
    it->hasCard = delta.hasCard;
    it->card = delta.card;
    if (m_changed) {
        m_changed(reader, delta);
    }
}

const std::vector<ReaderState>& ObjectRegistry::readers() const noexcept
{
    return m_readers;
}

const std::vector<CardState>& ObjectRegistry::cards() const noexcept
{
    return m_cards;
}

bool ObjectRegistry::contains(ObjectId id) const
{
    return std::any_of(m_readers.begin(), m_readers.end(), [&](const ReaderState& r) { return r.id == id; }) ||
           std::any_of(m_cards.begin(), m_cards.end(), [&](const CardState& c) { return c.id == id; });
}

} // namespace LibreSCRS::Agent
