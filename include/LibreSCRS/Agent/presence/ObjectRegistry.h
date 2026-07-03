// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <functional>
#include <vector>
namespace LibreSCRS::Agent {
// Owns the live set of published reader/card objects and notifies observers of
// typed deltas. Qt-free / transport-free: the AgentTransport backend registers
// observers to materialize the published objects (it owns the ObjectId->path
// mapping and all value/interface-name tagging); unit tests inspect the contents
// directly. Single-threaded, but driven on the LM monitor poll thread
// (PresenceModel runs the add/remove/update under MonitorBridge's state mutex);
// the AgentTransport backend observer marshals any event-loop-only work onto the
// dispatch thread via the loop poster.
class ObjectRegistry
{
public:
    using AddReaderFn = std::function<void(const ReaderState&)>;
    using AddCardFn = std::function<void(const CardState&)>;
    using RemovedFn = std::function<void(ObjectId)>;
    // Fired when an already-registered reader's card-presence fields flip
    // (HasCard/Card on card insert/remove). The typed delta carries only the
    // presence change so the observer can emit a minimal PropertiesChanged.
    using ChangedFn = std::function<void(ObjectId reader, const PropertyDelta&)>;

    void setObservers(AddReaderFn addReader, AddCardFn addCard, RemovedFn removed, ChangedFn changed = {});

    void addReader(const ReaderState& reader); // dedup by id; notifies AddReaderFn
    void addCard(const CardState& card);       // dedup by id; notifies AddCardFn
    void remove(ObjectId id);                  // searches readers then cards; notifies RemovedFn
    // Mutate the named reader's HasCard/Card in place and notify the changed
    // observer. No-op (no notification) when the id is invalid/unknown or the
    // delta matches the reader's current presence.
    void update(ObjectId reader, const PropertyDelta& delta);

    [[nodiscard]] const std::vector<ReaderState>& readers() const noexcept;
    [[nodiscard]] const std::vector<CardState>& cards() const noexcept;
    [[nodiscard]] bool contains(ObjectId id) const;

private:
    std::vector<ReaderState> m_readers;
    std::vector<CardState> m_cards;
    AddReaderFn m_addReader;
    AddCardFn m_addCard;
    RemovedFn m_removed;
    ChangedFn m_changed;
};
} // namespace LibreSCRS::Agent
