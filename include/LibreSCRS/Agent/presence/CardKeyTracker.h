// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // ObjectId
#include <functional>
#include <map>
#include <optional>
#include <string>
namespace LibreSCRS::Agent {

// Maps PC/SC reader name -> the currently-inserted card's per-insertion
// ObjectId (the same opaque id PresenceModel mints; the backend maps it to the
// object path it keys the credential and read caches by). When a card or its
// reader disappears, the held id is forwarded to the on-removed callback so the
// backend can map it back to that path and invalidate the exact entry the caches
// were populated under.
//
// The per-insertion ObjectId — not the ATR fingerprint — is the cache key on
// purpose: the product contract is "CAN entered once per card INSERTION"
// (cleared on removal, re-prompt on re-insertion), and the per-insertion id
// matches it one-to-one. An ATR fingerprint is non-unique across same-batch
// cards and persists across re-insertions, so it would cross-link distinct
// cards' secrets and survive a removal.
//
// Pure C++: no D-Bus, no PCSC, no Qt. Single-threaded — callers serialize
// access through the agent's state mutex.
class CardKeyTracker
{
public:
    // Fired on card/reader removal with both the dropped cache key (the card
    // ObjectId) and the reader name. The cardKey scrubs the credential/read
    // caches (via the backend's id->path mapping); the readerName lets the
    // handler map the reader to its per-reader shared CardSession and close it (so
    // the next op re-opens against whatever card is present next).
    using KeyRemovedFn = std::function<void(ObjectId cardKey, const std::string& readerName)>;

    void setOnKeyRemoved(KeyRemovedFn cb);

    void onCardInserted(const std::string& readerName, ObjectId cardId);
    void onCardRemoved(const std::string& readerName);   // fires callback with the dropped cardKey
    void onReaderRemoved(const std::string& readerName); // same as onCardRemoved + erases reader

    [[nodiscard]] std::optional<ObjectId> currentKey(const std::string& readerName) const;

private:
    std::map<std::string, ObjectId> m_readerToCardKey;
    KeyRemovedFn m_onRemoved;
};

} // namespace LibreSCRS::Agent
