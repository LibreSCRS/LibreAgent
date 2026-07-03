// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <variant>
#include <vector>

namespace LibreSCRS::Agent {

// The crypto mechanism a private/public-key op requests. Frozen now so EC/ECDH
// and RSA-OAEP become additive enum values + closed-but-extensible params arms —
// never a seam-signature widening (spec §8). The core wires only RsaPkcs1Sign /
// RsaPkcs1Decrypt + Empty params (behaviour-identical to today's SignRaw /
// Decrypt); the rest are designed-additive.
enum class Mechanism : std::uint8_t {
    // Private-key, lease-gated (PIN-as-consent). RsaPkcs1Sign / EcdsaSign carry
    // MechParamsEmpty; RsaPssSign is designed-additive and rides a FUTURE
    // MechParamsRsaPss{hashAlg, mgf, saltLen} arm — it does NOT ride Empty params.
    RsaPkcs1Sign,    // CKM_RSA_PKCS / hash-on-card sign        [wired, Empty]
    RsaPssSign,      // CKM_RSA_PKCS_PSS -> future RsaPss params [additive]
    EcdsaSign,       // CKM_ECDSA                               [additive, Empty]
    RsaPkcs1Decrypt, // CKM_RSA_PKCS decrypt                    [wired, Empty]
    RsaOaepDecrypt,  // CKM_RSA_PKCS_OAEP   -> RsaOaep params   [additive]
    EcdhDerive,      // CKM_ECDH1_DERIVE    -> Ecdh params      [additive]
    // Public-key, NO-consent (no lease/PIN; the CertDer/PublicKey policy path).
    RsaPkcs1Encrypt, // CKM_RSA_PKCS encrypt                    [additive, Empty]
    RsaOaepEncrypt,  // CKM_RSA_PKCS_OAEP   -> RsaOaep params   [additive]
};

struct MechParamsEmpty
{}; // RSA-PKCS sign/decrypt/encrypt, ECDSA

struct MechParamsEcdh
{                                              // CKM_ECDH1_DERIVE
    std::vector<std::uint8_t> peerPublicPoint; // peer EC point (uncompressed)
    std::uint32_t kdf{0};                      // CKD_* selector
    std::vector<std::uint8_t> sharedData;      // optional KDF shared data
};

struct MechParamsRsaOaep
{                                    // CKM_RSA_PKCS_OAEP
    std::uint32_t hashAlg{0};        // CKM_* hash
    std::uint32_t mgf{0};            // CKG_* MGF
    std::vector<std::uint8_t> label; // optional OAEP label
};

// Closed-but-extensible: adding an arm is a reviewed API-version event, never a
// signature change (spec §8). A future MechParamsRsaPss{hashAlg, mgf, saltLen}
// arm joins here when RsaPssSign is wired (RSA-PSS needs the hash/MGF/salt-len
// triple — it cannot ride MechParamsEmpty).
using MechanismParams = std::variant<MechParamsEmpty, MechParamsEcdh, MechParamsRsaOaep>;

} // namespace LibreSCRS::Agent
