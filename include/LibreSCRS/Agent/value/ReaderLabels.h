// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/ReaderInterface.h>

#include <string>
#include <vector>

namespace LibreSCRS::Agent {

/// Which physical interface of a reader a slot represents -- the wire's own
/// enum, so the classifier below and every published reader name one type.
///
/// @since 5.0
using ReaderInterface = Wire::ReaderInterface;

/// A reader's identity as the prompt chrome needs it: a model string, a
/// STRUCTURED interface qualifier, and the raw PC/SC name.
///
/// Deliberately carries no composed human sentence. LibreAgent has no
/// localisation, so any English wording it produced would be unfixable by a
/// prompter; the prompter receives the qualifier and says it in the holder's
/// language (see the design's M-1 correction).
///
/// @since 5.0
struct ReaderIdentity
{
    std::string model;
    ReaderInterface iface{ReaderInterface::Unknown};
    std::string full;
    bool operator==(const ReaderIdentity&) const = default;
};

/// Derive identities for @p rawNames, index-aligned with the input. The one
/// classifier of PC/SC reader names: the agent publishes its result on every
/// reader, so no client parses a reader name itself.
///
/// - The model drops the pcsc-lite " (serial) <ifd> <slot>" tail, prefers the
///   bracketed product string when it names a model, and drops trailing
///   generic words ("Smartcard", "Reader", "CCID", "USB", "Interface") and the
///   contactless marker ("PICC", "Contactless", a "CL" token or one fused to a
///   model number).
/// - Contactless: the name carries a contactless marker ("contactless",
///   "PICC", "NFC", that "CL"). Contact: a slot WITHOUT the marker whose unit
///   also surfaces another name with the same serial. Unknown otherwise --
///   a contact slot is never guessed from a model match alone, because only a
///   Contact slot's reader is ever held powered.
/// - Two DISTINCT names that would still read alike (same model, same
///   interface) get the last four characters of their serial appended, or a
///   1-based position when there is none, until every label differs. The same
///   name listed twice is one reader and keeps one label.
///
/// Roster-aware by necessity: whether a unit is dual-interface, and whether a
/// label collides, is only decidable across the whole set, so this takes the
/// list rather than one name. Never returns an empty model (falls back to the
/// raw name).
///
/// @since 5.0
[[nodiscard]] std::vector<ReaderIdentity> readerIdentities(const std::vector<std::string>& rawNames);

/// The readers a host currently presents, each with the card it holds:
/// index-aligned, an empty key for a reader with no card. The key is whatever
/// the host names a card by (an object path, a decimal id); only equality is
/// used.
///
/// @since 5.0
struct PresenceRoster
{
    std::vector<std::string> readerNames;
    std::vector<std::string> cardKeys;
};

/// The identity of the reader in @p roster that holds @p cardKey, labelled by
/// readerIdentities() over the whole roster. An empty identity when no reader
/// holds that card, and for an empty key, which would otherwise match the
/// first reader that holds none.
///
/// @since 5.0
[[nodiscard]] ReaderIdentity identityForCardIn(const PresenceRoster& roster, const std::string& cardKey);

/// Whether the reader holding @p cardKey is the contact slot of a
/// dual-interface unit: the one slot whose power hold keeps the same chip's
/// contactless twin from flapping. A single-interface reader (Unknown) and a
/// contactless slot are never that slot.
///
/// @since 5.0
[[nodiscard]] bool isContactSlotOfDualInterfaceUnit(const PresenceRoster& roster, const std::string& cardKey);

} // namespace LibreSCRS::Agent
