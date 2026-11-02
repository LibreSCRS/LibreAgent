// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

/// @file
/// @brief Which physical interface of a reader a PC/SC slot is, and its wire token.

namespace LibreSCRS::Agent::Wire {

/// Which physical interface of a reader a slot represents. A dual-interface
/// unit surfaces two PC/SC names that share a serial, so this is what tells a
/// holder which of two otherwise identical readers is which.
///
/// Std-only and in the wire layer because it travels: the agent publishes it on
/// every reader (D-Bus `Reader1.Interface`, socket `reader-state.interface`) and
/// hands it to the prompter. The values are append-only; the agent's own reader
/// classifier (`readerIdentities`, `value/ReaderLabels.h`) is the only producer.
///
/// @since 5.0
enum class ReaderInterface : std::uint8_t {
    Unknown,     ///< A single-interface contact reader, or not determinable.
    Contact,     ///< The contact slot of a dual-interface unit.
    Contactless, ///< A contactless interface: a slot of a dual-interface unit, or a contactless-only reader.
};

/// The wire token of @p iface: "unknown", "contact" or "contactless" -- the
/// closed vocabulary `reader-interface` of the contract grammar.
///
/// @since 5.0
[[nodiscard]] constexpr std::string_view readerInterfaceToken(ReaderInterface iface) noexcept
{
    switch (iface) {
    case ReaderInterface::Unknown:
        return "unknown";
    case ReaderInterface::Contact:
        return "contact";
    case ReaderInterface::Contactless:
        return "contactless";
    }
    return "unknown";
}

/// The interface @p token names, or nullopt for a token this build does not
/// know. A reader of the wire treats nullopt as ReaderInterface::Unknown: a
/// value appended later must never fail a decode.
///
/// @since 5.0
[[nodiscard]] constexpr std::optional<ReaderInterface> readerInterfaceFromToken(std::string_view token) noexcept
{
    for (const auto iface : {ReaderInterface::Unknown, ReaderInterface::Contact, ReaderInterface::Contactless}) {
        if (readerInterfaceToken(iface) == token) {
            return iface;
        }
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Agent::Wire
