// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The few DER shapes the module serves and reads for EC keys, with no crypto
// library: a named curve's OID, an EC point as an OCTET STRING -- and the one
// check, shared by every transport, of which points are worth serving.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief CKA_EC_PARAMS for an EC key of @p keyBits: the DER OID of P-256,
///        P-384 or P-521; empty for any other size.
[[nodiscard]] std::span<const std::uint8_t> ecParamsDerFor(std::uint32_t keyBits) noexcept;

/// @brief True when @p crv names P-256, P-384 or P-521 and @p x and @p y are
///        both exactly that curve's field width (32, 48, 66 bytes). The wire
///        carries any curve name and any length; anything else is a malformed
///        answer, never a key handed to a loader.
[[nodiscard]] bool isNamedCurvePoint(std::string_view crv, std::span<const std::uint8_t> x,
                                     std::span<const std::uint8_t> y) noexcept;

/// @brief isNamedCurvePoint(), on the curve of an EC key of @p keyBits: the
///        point served as CKA_EC_POINT must lie on the curve CKA_EC_PARAMS
///        names, or the key a loader sees contradicts itself.
[[nodiscard]] bool isPointOfKey(std::uint32_t keyBits, std::string_view crv, std::span<const std::uint8_t> x,
                                std::span<const std::uint8_t> y) noexcept;

/// @brief CKA_EC_POINT: a DER OCTET STRING around the uncompressed point
///        04||x||y (long-form length on P-521); empty when @p x or @p y is
///        empty or the two differ in length.
[[nodiscard]] std::vector<std::uint8_t> ecPointOctetString(std::span<const std::uint8_t> x,
                                                           std::span<const std::uint8_t> y);

/// @brief The peer's uncompressed point from CK_ECDH1_DERIVE_PARAMS::pPublicData
///        for a key of @p keyBits: the raw point (1 + 2*ceil(bits/8) bytes) or
///        the same point in a DER OCTET STRING. nullopt for anything else,
///        including a compressed point. Whether the point is on the curve is
///        the agent's check -- this module has no crypto.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> peerPointFromPublicData(std::span<const std::uint8_t> publicData,
                                                                               std::uint32_t keyBits);

} // namespace LibreSCRS::Pkcs11Agent
