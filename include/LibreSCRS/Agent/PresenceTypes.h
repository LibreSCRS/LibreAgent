// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/value/ReaderLabels.h>
#include <LibreSCRS/Auth/AuthRequirement.h> // PreReadAuthMethod
#include <cstdint>
#include <string>

namespace LibreSCRS::Agent {

// One published reader (Reader1: Name / HasCard / Card / Model / Interface).
struct ReaderState
{
    ObjectId id;
    std::string name;
    bool hasCard{false};
    ObjectId card; // default/invalid == no card
    // Reader1.Model / Reader1.Interface: the reader's label, derived from the
    // whole roster by readerIdentities() (value/ReaderLabels.h). ObjectRegistry
    // fills both -- whatever a caller puts here is replaced -- and they can
    // change while the reader stays, when a reader arrives or leaves beside it.
    std::string model;
    ReaderInterface iface{ReaderInterface::Unknown};
};

// One published card insertion (Card1: Capabilities / Reader / PreReadAuthMethod /
// CardType / Atr). Carries the neutral LM enum, NOT the wire string — the
// AgentTransport backend stringifies it.
struct CardState
{
    ObjectId id;
    ObjectId reader;
    std::uint32_t capabilities{0};
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth{LibreSCRS::Auth::PreReadAuthMethod::None};
    // Card1.CardType: empty until known. Set from the single-candidate plugin's
    // pluginId() when the held-session candidate list resolves to exactly one
    // entry (same deferred resolution point as capabilities/preReadAuth above);
    // left empty (ambiguous / not yet resolved) otherwise. Authoritatively
    // overwritten with CardReadSnapshot::cardType once a real read completes
    // (IdentityReadFlow), pushed to already-published clients via the
    // property-update path — this field only seeds the INITIAL value.
    std::string cardType;
    // Card1.Atr: uppercase hex, no separators, the full session ATR. Always
    // known synchronously at insertion (PresenceModel::onCardInserted) and
    // never changes for the card's lifetime.
    std::string atrHex;
};

// The only in-place property mutation the agent emits: a reader's card-presence
// flipping on insert/remove. Replaces ObjectRegistry::update(path,iface,PropertyMap).
struct PropertyDelta
{
    bool hasCard{false};
    ObjectId card; // default/invalid when hasCard == false
};

} // namespace LibreSCRS::Agent
