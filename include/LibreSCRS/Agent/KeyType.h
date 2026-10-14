// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

/// @file
/// @brief The kind of key a certificate carries, as the agent reports it on
///        both wires and as the PKCS#11 facade models it.
///
/// Std-only, like FeatureTokens.h: reachable from the core, the wire library,
/// the facade (which links no crypto) and the platform backends.

namespace LibreSCRS::Agent {

/// @brief The family of a certificate's public key.
///
/// `Ec` means a NIST prime curve -- P-256, P-384 or P-521 -- and nothing else.
/// Every other key (an RSASSA-PSS key, brainpool, EdDSA, a certificate the
/// agent cannot read) is `Other`; an `Other` key is never published as a
/// PKCS#11 or Keychain private key. It keeps whatever document signing the
/// agent offers for it. Append-only.
/// @since 5.0
enum class KeyType : std::uint8_t { Rsa, Ec, Other };

/// @brief The wire token for @p type: "RSA", "EC" or "OTHER".
[[nodiscard]] constexpr std::string_view keyTypeToken(KeyType type) noexcept
{
    switch (type) {
    case KeyType::Rsa:
        return "RSA";
    case KeyType::Ec:
        return "EC";
    case KeyType::Other:
        return "OTHER";
    }
    return "OTHER";
}

/// @brief The key type a wire token names. A token this build does not know --
///        one a newer agent appended -- reads as `Other`, never as an error.
[[nodiscard]] constexpr KeyType keyTypeFromToken(std::string_view token) noexcept
{
    if (token == "RSA") {
        return KeyType::Rsa;
    }
    if (token == "EC") {
        return KeyType::Ec;
    }
    return KeyType::Other;
}

/// @brief One of the NIST prime curves an `Ec` key is on, under every name the
///        agent stack knows it by.
///
/// The one table of these curves: the certificate classifier, the public-key
/// reader, the wire decoder and the PKCS#11 facade all read it, so a curve is
/// added or renamed in one place.
/// @since 5.0
struct NistCurve
{
    std::uint32_t keyBits;                ///< 256, 384 or 521.
    std::size_t fieldBytes;               ///< ceil(keyBits / 8): one coordinate, an ECDH secret.
    std::string_view crv;                 ///< The wire's name: "P-256", "P-384", "P-521".
    std::string_view group;               ///< OpenSSL's group name for the curve.
    std::span<const std::uint8_t> oidDer; ///< The named curve's OID, DER-encoded (CKA_EC_PARAMS).
};

namespace detail {
inline constexpr std::array<std::uint8_t, 10> kP256OidDer{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
inline constexpr std::array<std::uint8_t, 7> kP384OidDer{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
inline constexpr std::array<std::uint8_t, 7> kP521OidDer{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
} // namespace detail

/// @brief The three curves an `Ec` key may be on.
/// @since 5.0
inline constexpr std::array<NistCurve, 3> kNistCurves{{
    {256, 32, "P-256", "prime256v1", detail::kP256OidDer},
    {384, 48, "P-384", "secp384r1", detail::kP384OidDer},
    {521, 66, "P-521", "secp521r1", detail::kP521OidDer},
}};

/// @brief The curve of an `Ec` key of @p keyBits bits; null for any other size.
[[nodiscard]] constexpr const NistCurve* nistCurveByBits(std::uint32_t keyBits) noexcept
{
    for (const auto& c : kNistCurves) {
        if (c.keyBits == keyBits) {
            return &c;
        }
    }
    return nullptr;
}

/// @brief The curve the wire names @p crv; null for any other name.
[[nodiscard]] constexpr const NistCurve* nistCurveByName(std::string_view crv) noexcept
{
    for (const auto& c : kNistCurves) {
        if (c.crv == crv) {
            return &c;
        }
    }
    return nullptr;
}

/// @brief The curve OpenSSL names @p group; null for any other group.
[[nodiscard]] constexpr const NistCurve* nistCurveByGroup(std::string_view group) noexcept
{
    for (const auto& c : kNistCurves) {
        if (c.group == group) {
            return &c;
        }
    }
    return nullptr;
}

} // namespace LibreSCRS::Agent
