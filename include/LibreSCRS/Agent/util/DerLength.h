// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

/// @file
/// @brief The one rule this agent reads a DER length by.
///
/// Std-only and header-only, so the PKCS#11 facade -- which links no crypto
/// library and no core -- reads lengths the same way the CSCA import does.

namespace LibreSCRS::Agent {

/// The longest length encoding accepted: four octets already describe a 4 GiB
/// value, far above anything this agent parses (a certificate, a master list
/// capped well below that), and the cap keeps the accumulation below from
/// overflowing on any platform.
inline constexpr std::size_t kMaxDerLengthOctets = 4;

/// A length read by readDerLength().
struct DerLength
{
    /// The value the length declares.
    std::size_t length{0};
    /// How many octets the length itself took, the first one included: 1 for
    /// the short form, 1 + n for the long form with n octets.
    std::size_t lengthOctets{0};
};

/// Read the definite length at `data[pos]`, accepting it only when the value
/// it declares lies wholly inside @p data.
///
/// nullopt when the encoding is truncated, longer than kMaxDerLengthOctets,
/// declares more bytes than @p data holds, or is the BER indefinite form
/// (0x80). Indefinite is not a length; a caller that accepts BER (the outer
/// ContentInfo of a published master list does use it) recognises 0x80 itself,
/// before asking this, and finds the end by its end-of-contents octets.
///
/// Containment is tested by subtraction, never by adding the length to an
/// offset: a hostile length can make that addition wrap past the check.
[[nodiscard]] constexpr std::optional<DerLength> readDerLength(std::span<const std::uint8_t> data,
                                                               std::size_t pos) noexcept
{
    if (pos >= data.size()) {
        return std::nullopt;
    }
    const std::uint8_t first = data[pos];
    std::size_t value = first;
    std::size_t lengthOctets = 1;
    if ((first & 0x80U) != 0) {
        const std::size_t octets = first & 0x7FU;
        if (octets == 0 || octets > kMaxDerLengthOctets || octets > data.size() - pos - 1) {
            return std::nullopt;
        }
        value = 0;
        for (std::size_t i = 0; i < octets; ++i) {
            value = (value << 8) | data[pos + 1 + i];
        }
        lengthOctets = 1 + octets;
    }
    // pos + lengthOctets <= data.size() on both branches, so this cannot wrap.
    if (value > data.size() - pos - lengthOctets) {
        return std::nullopt;
    }
    return DerLength{value, lengthOctets};
}

} // namespace LibreSCRS::Agent
