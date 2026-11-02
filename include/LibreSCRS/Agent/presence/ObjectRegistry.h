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
    // Fired when an already-registered reader's label (model / interface)
    // changes because another reader arrived or left: the label is decided
    // over the whole roster (a dual-interface twin, a same-model neighbour),
    // so it is not fixed at the reader's arrival. Carries the reader's state
    // with its new label.
    using RelabelledFn = std::function<void(const ReaderState&)>;

    void setObservers(AddReaderFn addReader, AddCardFn addCard, RemovedFn removed, ChangedFn changed = {},
                      RelabelledFn relabelled = {});

    // Dedup by id. Labels the reader over the roster it joins (whatever label
    // the caller passed is replaced), notifies AddReaderFn with that label,
    // then RelabelledFn for every OTHER reader whose label its arrival changed.
    void addReader(const ReaderState& reader);
    void addCard(const CardState& card); // dedup by id; notifies AddCardFn
    // Searches readers then cards; notifies RemovedFn. A reader's removal then
    // notifies RelabelledFn for every remaining reader whose label it changed.
    void remove(ObjectId id);
    // Mutate the named reader's HasCard/Card in place and notify the changed
    // observer. No-op (no notification) when the id is invalid/unknown or the
    // delta matches the reader's current presence.
    void update(ObjectId reader, const PropertyDelta& delta);

    [[nodiscard]] const std::vector<ReaderState>& readers() const noexcept;
    [[nodiscard]] const std::vector<CardState>& cards() const noexcept;
    [[nodiscard]] bool contains(ObjectId id) const;

private:
    // Label every reader over the current roster; the ids whose label changed.
    [[nodiscard]] std::vector<ObjectId> relabel();
    void announceRelabels(const std::vector<ObjectId>& readers, ObjectId except);

    std::vector<ReaderState> m_readers;
    std::vector<CardState> m_cards;
    AddReaderFn m_addReader;
    AddCardFn m_addCard;
    RemovedFn m_removed;
    ChangedFn m_changed;
    RelabelledFn m_relabelled;
};
} // namespace LibreSCRS::Agent
