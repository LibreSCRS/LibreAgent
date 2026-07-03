// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// RSA public key components extracted from a certificate's SubjectPublicKeyInfo,
// in the PKCS#11 CKA_* convention: unpadded big-endian, no leading zero byte.
struct RsaPublicKey
{
    std::vector<std::uint8_t> modulus;
    std::vector<std::uint8_t> exponent;
};

// Parse the X.509 certificate @p der and return its RSA public key
// (modulus + public exponent) for the crypto-free PKCS#11 module to serve as
// CKA_MODULUS / CKA_PUBLIC_EXPONENT (ssh-pkcs11 builds the pubkey from them).
// Returns std::nullopt when @p der is unparseable OR the key is not RSA — the
// host distinguishes those from "no such cert" upstream. The agent already has
// the cert DER (CertDer export) and OpenSSL (Sha256Hex), so no new crypto
// dependency is pulled in.
[[nodiscard]] std::optional<RsaPublicKey> rsaPublicKeyFromCertDer(std::span<const std::uint8_t> der);

} // namespace LibreSCRS::Agent::Operations
