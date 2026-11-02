// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <algorithm>
#include <string>
namespace LibreSCRS::Agent {

void ObjectRegistry::setObservers(AddReaderFn addReader, AddCardFn addCard, RemovedFn removed, ChangedFn changed,
                                  RelabelledFn relabelled)
{
    m_addReader = std::move(addReader);
    m_addCard = std::move(addCard);
    m_removed = std::move(removed);
    m_changed = std::move(changed);
    m_relabelled = std::move(relabelled);
}

std::vector<ObjectId> ObjectRegistry::relabel()
{
    std::vector<std::string> names;
    names.reserve(m_readers.size());
    for (const auto& reader : m_readers) {
        names.push_back(reader.name);
    }
    const auto identities = readerIdentities(names);
    std::vector<ObjectId> changed;
    for (std::size_t i = 0; i < m_readers.size(); ++i) {
        auto& reader = m_readers[i];
        if (reader.model != identities[i].model || reader.iface != identities[i].iface) {
            reader.model = identities[i].model;
            reader.iface = identities[i].iface;
            changed.push_back(reader.id);
        }
    }
    return changed;
}

void ObjectRegistry::announceRelabels(const std::vector<ObjectId>& readers, ObjectId except)
{
    if (!m_relabelled) {
        return;
    }
    // By id, not by a held reference: an observer may reach back into the
    // registry.
    for (const ObjectId id : readers) {
        if (id == except) {
            continue;
        }
        const auto it = std::ranges::find(m_readers, id, &ReaderState::id);
        if (it != m_readers.end()) {
            m_relabelled(*it);
        }
    }
}

void ObjectRegistry::addReader(const ReaderState& reader)
{
    if (contains(reader.id)) {
        return;
    }
    m_readers.push_back(reader);
    m_readers.back().model.clear();
    m_readers.back().iface = ReaderInterface::Unknown;
    const auto relabelled = relabel();
    // The newcomer is announced with its label first: an observer never hears
    // of a relabel caused by a reader it has not been told about.
    if (m_addReader) {
        const auto it = std::ranges::find(m_readers, reader.id, &ReaderState::id);
        if (it != m_readers.end()) {
            m_addReader(*it);
        }
    }
    announceRelabels(relabelled, reader.id);
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
        const auto relabelled = relabel();
        if (m_removed) {
            m_removed(id);
        }
        announceRelabels(relabelled, id);
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
