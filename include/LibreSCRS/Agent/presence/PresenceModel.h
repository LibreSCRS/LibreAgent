// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/Identity.h>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
namespace LibreSCRS::Agent {
class ObjectRegistry;
// Pure mapping of reader/card presence to registry objects. No D-Bus, no PCSC,
// no Qt. Reader/card identities are stable opaque counters per process
// lifetime — the stable per-card fingerprint must never appear in a D-Bus
// object path (it is consent-gated; path-leaking it would let any peer
// correlate cards across insertions via simple introspection).
class PresenceModel
{
public:
    PresenceModel(ObjectRegistry& registry, CapabilityResolver& resolver);

    void onReaderAdded(const std::string& readerName);
    void onReaderRemoved(const std::string& readerName);
    void onCardInserted(const std::string& readerName, const std::vector<std::uint8_t>& atr);
    void onCardRemoved(const std::string& readerName);

    // Reader ObjectId for `name` (the opaque id the backend maps to the exported
    // Reader1 path and OperationManager keys its per-reader worker by), or an
    // invalid ObjectId{} when the reader is not currently mapped. Used on card
    // removal to map the reader name to its per-reader shared CardSession for
    // invalidation.
    [[nodiscard]] ObjectId readerIdFor(const std::string& name) const;

    // Current card ObjectId for `readerName` (the per-insertion id minted in
    // onCardInserted), or an invalid ObjectId{} when no card is currently mapped.
    // The CardKeyTracker keys its cache-scrub on this id; the backend maps it back
    // to the object path the credential/read caches were populated under, so those
    // caches are actually invalidated on removal.
    [[nodiscard]] ObjectId cardIdFor(const std::string& readerName) const;

private:
    ObjectRegistry& m_registry;
    CapabilityResolver& m_resolver;
    std::unordered_map<std::string, ObjectId> m_readerIds; // reader name -> reader id
    std::unordered_map<std::string, ObjectId> m_cardIds;   // reader name -> current card id
    std::uint64_t m_nextId{0};                             // single monotonic per-process counter (0 == none)
};
} // namespace LibreSCRS::Agent
