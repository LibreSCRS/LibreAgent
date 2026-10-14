// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// Public keys read off a certificate's SubjectPublicKeyInfo, for the
// crypto-free PKCS#11 module and the agent's own checks.
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
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

// The EC public key of a certificate on a NIST prime curve: `crv` is "P-256",
// "P-384" or "P-521"; x and y are big-endian, each exactly ceil(bits/8) bytes,
// left-padded with zeros -- the halves of the uncompressed point 04||X||Y.
struct EcPublicKey
{
    std::string crv;
    std::vector<std::uint8_t> x;
    std::vector<std::uint8_t> y;
};

// Parse @p der and return its EC point when the key is on P-256, P-384 or
// P-521; nullopt for any other key, curve or unparseable DER.
[[nodiscard]] std::optional<EcPublicKey> ecPublicKeyFromCertDer(std::span<const std::uint8_t> der);

// A certificate's public key as the agent serves it: an RSA modulus and
// exponent, or an EC point on a NIST curve. Any other key has none.
using CertPublicKey = std::variant<RsaPublicKey, EcPublicKey>;

// The public key of the certificate @p der: its RSA key (rsaPublicKeyFromCertDer),
// else its EC key (ecPublicKeyFromCertDer); nullopt for any other key and for
// DER that does not parse. What the agent's PublicKey call answers with.
[[nodiscard]] std::optional<CertPublicKey> publicKeyFromCertDer(std::span<const std::uint8_t> der);

// The key ID the agent reports when the card names none, computed as OpenSC
// does: SHA-1 of the RSA modulus (no leading zeros), of the EC X coordinate
// (fixed width), otherwise of the subjectPublicKey BIT STRING's bits (RFC 5280
// section 4.2.1.2, method 1) -- and of the whole @p der when it does not parse.
// Never empty: where this OpenSSL refuses SHA-1 it is the SHA-256 of @p der
// (the certId's bytes), and where SHA-256 is refused too it throws, as the
// certId does.
[[nodiscard]] std::vector<std::uint8_t> fallbackKeyIdFromCertDer(std::span<const std::uint8_t> der);

// True iff @p point is an uncompressed point (04||X||Y, 1 + 2*ceil(bits/8)
// bytes) on the curve of the EC key in @p der, not at infinity. The agent's
// check of a key-agreement peer before any PIN prompt.
[[nodiscard]] bool ecPeerPointOnCertCurve(std::span<const std::uint8_t> der, std::span<const std::uint8_t> point);

} // namespace LibreSCRS::Agent::Operations
