// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

/// Which physical interface of a reader a slot represents. A dual-interface
/// unit surfaces two PC/SC names that share a serial, so this is what tells
/// a holder which of two otherwise identical dialogs belongs to which slot.
///
/// @since 4.3
enum class ReaderInterface : std::uint8_t {
    Unknown,     ///< Single-interface reader, or not determinable.
    Contact,     ///< Contact slot of a dual-interface unit.
    Contactless, ///< Contactless slot of a dual-interface unit.
};

/// A reader's identity as the prompt chrome needs it: a model string, a
/// STRUCTURED interface qualifier, and the raw PC/SC name.
///
/// Deliberately carries no composed human sentence. LibreAgent has no
/// localisation, so any English wording it produced would be unfixable by a
/// prompter; the prompter receives the qualifier and says it in the holder's
/// language (see the design's M-1 correction).
///
/// @since 4.3
struct ReaderIdentity
{
    std::string model;
    ReaderInterface iface{ReaderInterface::Unknown};
    std::string full;
    bool operator==(const ReaderIdentity&) const = default;
};

/// Derive identities for @p rawNames, index-aligned with the input.
///
/// Roster-aware by necessity: whether a unit is dual-interface is only
/// decidable across the whole set, so this takes the list rather than one
/// name. Never returns an empty model (falls back to the raw name).
///
/// @since 4.3
[[nodiscard]] std::vector<ReaderIdentity> readerIdentities(const std::vector<std::string>& rawNames);

} // namespace LibreSCRS::Agent
