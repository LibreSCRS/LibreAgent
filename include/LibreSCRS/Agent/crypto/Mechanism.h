// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace LibreSCRS::Agent {

// The crypto mechanism a private/public-key op requests. Append-only: a new
// primitive is a new enumerator plus, where it needs one, a parameter arm --
// never a seam-signature widening. Wired today: RsaPkcs1Sign,
// Sha256RsaPkcs1Sign, EcdsaSign, RsaPkcs1Decrypt (all with MechParamsEmpty)
// and EcdhDerive (MechParamsEcdh, kdf == kEcdhKdfNull only). The agent runs
// exactly the mechanism a request names and checks it against the key before
// any PIN prompt.
enum class Mechanism : std::uint8_t {
    // Private-key, lease-gated (PIN-as-consent).
    RsaPkcs1Sign,    // CKM_RSA_PKCS: the caller's complete block   [wired, Empty]
    RsaPssSign,      // CKM_RSA_PKCS_PSS -> future RsaPss params     [additive]
    EcdsaSign,       // CKM_ECDSA: the digest, 32/48/64 bytes        [wired, Empty]
    RsaPkcs1Decrypt, // CKM_RSA_PKCS decrypt                         [wired, Empty]
    RsaOaepDecrypt,  // CKM_RSA_PKCS_OAEP   -> RsaOaep params        [additive]
    EcdhDerive,      // CKM_ECDH1_DERIVE    -> Ecdh params           [wired, CKD_NULL]
    // Public-key, NO-consent (no lease/PIN; the CertDer/PublicKey policy path).
    RsaPkcs1Encrypt, // CKM_RSA_PKCS encrypt                         [additive, Empty]
    RsaOaepEncrypt,  // CKM_RSA_PKCS_OAEP   -> RsaOaep params        [additive]
    // Private-key, lease-gated: the RAW message, which the card hashes with
    // SHA-256 before it signs (CKM_SHA256_RSA_PKCS).                [wired, Empty]
    Sha256RsaPkcs1Sign,
};

struct MechParamsEmpty
{}; // RSA-PKCS sign/decrypt/encrypt, SHA256-RSA-PKCS sign, ECDSA

/// @brief CKD_NULL: the raw shared secret Z, no key-derivation function. The
///        only MechParamsEcdh::kdf the agent runs.
inline constexpr std::uint32_t kEcdhKdfNull = 1;

struct MechParamsEcdh
{                                              // CKM_ECDH1_DERIVE
    std::vector<std::uint8_t> peerPublicPoint; // peer EC point, uncompressed 04||X||Y
    std::uint32_t kdf{0};                      // CKD_* selector; only kEcdhKdfNull is run
    std::vector<std::uint8_t> sharedData;      // KDF shared data; must be empty with CKD_NULL
};

struct MechParamsRsaOaep
{                                    // CKM_RSA_PKCS_OAEP
    std::uint32_t hashAlg{0};        // CKM_* hash
    std::uint32_t mgf{0};            // CKG_* MGF
    std::vector<std::uint8_t> label; // optional OAEP label
};

// Closed-but-extensible: adding an arm is a reviewed API-version event, never a
// signature change. A future MechParamsRsaPss{hashAlg, mgf, saltLen} arm joins
// here when RsaPssSign is wired.
using MechanismParams = std::variant<MechParamsEmpty, MechParamsEcdh, MechParamsRsaOaep>;

/// @brief A mechanism's spelling on the wires (socket `mech`, D-Bus `s mech`).
struct MechanismToken
{
    std::string_view token;
    Mechanism mechanism;
};

/// @brief `pk-sign-mech`, in the contract's order.
inline constexpr std::array<MechanismToken, 3> kSignMechanismTokens{{
    {"rsa-pkcs", Mechanism::RsaPkcs1Sign},
    {"sha256-rsa-pkcs", Mechanism::Sha256RsaPkcs1Sign},
    {"ecdsa", Mechanism::EcdsaSign},
}};

/// @brief `pk-decrypt-mech`, in the contract's order.
inline constexpr std::array<MechanismToken, 1> kDecryptMechanismTokens{{
    {"rsa-pkcs", Mechanism::RsaPkcs1Decrypt},
}};

/// @brief The signing mechanism a wire token names; nullopt for any other token.
[[nodiscard]] constexpr std::optional<Mechanism> signMechanismFromToken(std::string_view token) noexcept
{
    for (const auto& t : kSignMechanismTokens) {
        if (t.token == token) {
            return t.mechanism;
        }
    }
    return std::nullopt;
}

/// @brief The decryption mechanism a wire token names; nullopt for any other token.
[[nodiscard]] constexpr std::optional<Mechanism> decryptMechanismFromToken(std::string_view token) noexcept
{
    for (const auto& t : kDecryptMechanismTokens) {
        if (t.token == token) {
            return t.mechanism;
        }
    }
    return std::nullopt;
}

/// @brief The wire token for @p m; empty for a mechanism that has none.
[[nodiscard]] constexpr std::string_view mechanismToken(Mechanism m) noexcept
{
    for (const auto& t : kSignMechanismTokens) {
        if (t.mechanism == m) {
            return t.token;
        }
    }
    for (const auto& t : kDecryptMechanismTokens) {
        if (t.mechanism == m) {
            return t.token;
        }
    }
    return {};
}

} // namespace LibreSCRS::Agent
