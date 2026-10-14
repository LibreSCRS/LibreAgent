// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentClient — the interface the PKCS#11 module talks to the per-user agent
// over, with no transport in it. It enumerates readers/cards, drives the
// per-card certificate read to learn the signing certs + their capabilities,
// and brokers the low-level primitives (CertDer / PublicKey / Login / Logout /
// SignRaw / Decrypt).
//
// Every type here is a value type — strings, spans, vectors, an outcome enum —
// so an implementation over a bus and one over a socket answer the same
// questions in the same words. The module holds NO secret: sign/decrypt I/O
// passes straight through and is NEVER logged. No crypto here, no Qt.

#pragma once

#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief Outcome of an AgentClient call, in the module's own vocabulary.
///
/// Each transport owns the table that maps its refusals onto these; the names
/// on the wire are that transport's business and appear nowhere in this header.
/// What is fixed here is the other half: which CKR_* the C_* layer answers with.
enum class Status : std::uint8_t {
    Ok,
    UserNotLoggedIn, ///< -> CKR_USER_NOT_LOGGED_IN
    NotAuthorized,   ///< -> CKR_PIN_INCORRECT / CKR_FUNCTION_FAILED
    AuthFailed,      ///< the card rejected the PIN      -> CKR_PIN_INCORRECT
    Cancelled,       ///< the user cancelled the prompt  -> CKR_FUNCTION_CANCELED
    KeyNotFound,     ///< -> CKR_KEY_HANDLE_INVALID
    UnknownCard,     ///< no card on that reader         -> CKR_TOKEN_NOT_PRESENT
    NotSupported,    ///< -> CKR_FUNCTION_NOT_SUPPORTED
    RateLimited,     ///< -> CKR_FUNCTION_REJECTED
    Communication,   ///< -> CKR_DEVICE_ERROR
    DeviceRemoved,   ///< connection lost / no agent     -> CKR_DEVICE_REMOVED
    GeneralError,    ///< anything else                  -> CKR_GENERAL_ERROR
    InvalidInput,    ///< the agent refused the input before any PIN prompt (a wrong length, a
                     ///< point off the key's curve) -> per call: CKR_DATA_LEN_RANGE (sign),
                     ///< CKR_ENCRYPTED_DATA_LEN_RANGE (decrypt), CKR_MECHANISM_PARAM_INVALID (derive)
};

/// @brief A login lease handle returned by login().
struct LoginResult
{
    Status status = Status::GeneralError;
    std::uint32_t idleTimeoutSecs = 0;
};

/// @brief A bytes-or-status result for sign / decrypt / certDer.
struct BytesResult
{
    Status status = Status::GeneralError;
    std::vector<std::uint8_t> bytes;
};

/// @brief A certificate's public key: RSA modulus + exponent (unpadded
///        big-endian, the CKA_* convention), or an EC point on a NIST curve.
///        The module serves CKA_MODULUS / CKA_PUBLIC_EXPONENT or CKA_EC_POINT
///        from these without any crypto of its own.
struct PublicKeyResult
{
    Status status = Status::GeneralError;
    std::vector<std::uint8_t> modulus;  ///< RSA
    std::vector<std::uint8_t> exponent; ///< RSA
    std::string crv;                    ///< EC: "P-256", "P-384" or "P-521"
    std::vector<std::uint8_t> x;        ///< EC, ceil(bits/8) bytes
    std::vector<std::uint8_t> y;        ///< EC, ceil(bits/8) bytes
};

/// @brief What the module needs from the agent, independent of how it asks.
///
/// A transport supplies exactly one implementation of this and the host links
/// exactly one factory that produces it (see AgentClientFactory.h). There is no
/// registry and no global: the choice is made at link time, which is the only
/// place a loadable module can make it once and be unable to change it later.
class AgentClient
{
public:
    AgentClient() = default;
    virtual ~AgentClient() = default;

    AgentClient(const AgentClient&) = delete;
    AgentClient& operator=(const AgentClient&) = delete;
    AgentClient(AgentClient&&) = delete;
    AgentClient& operator=(AgentClient&&) = delete;

    /// @brief True once a transport connection exists (the agent may still be
    ///        off). A false answer is not fatal: every call below then returns
    ///        Status::DeviceRemoved.
    [[nodiscard]] virtual bool connected() const noexcept = 0;

    /// @brief Enumerate readers/cards + per-card signing certs into a snapshot.
    ///        Presence changes must surface on the next C_GetSlotList, so an
    ///        implementation either watches for them or re-reads here.
    [[nodiscard]] virtual AgentSnapshot snapshot() = 0;

    /// @brief Public cert DER for (reader, certId). No consent, no lease.
    [[nodiscard]] virtual BytesResult certDer(const std::string& reader, const std::string& certId) = 0;

    /// @brief The public key of (reader, certId), of the family the snapshot
    ///        reported for it. Public data (no consent, no lease). A key of
    ///        another family than @p keyType answers NotSupported.
    [[nodiscard]] virtual PublicKeyResult publicKey(const std::string& reader, const std::string& certId,
                                                    LibreSCRS::Agent::KeyType keyType) = 0;

    /// @brief Establish/refresh the login lease (raises the agent prompter).
    ///        The lease is (caller, card)-scoped (C_Login is per-token), so no
    ///        certId is passed.
    [[nodiscard]] virtual LoginResult login(const std::string& reader) = 0;

    /// @brief Drop the lease for (caller, card). Idempotent.
    virtual Status logout(const std::string& reader) = 0;

    /// @brief Raw signature with exactly @p mechanism: RsaPkcs1Sign (a complete
    ///        PKCS#1 v1.5 block), Sha256RsaPkcs1Sign (the raw message, hashed on
    ///        the card) or EcdsaSign (the digest; answered r||s).
    [[nodiscard]] virtual BytesResult signRaw(const std::string& reader, const std::string& certId,
                                              LibreSCRS::Agent::Mechanism mechanism,
                                              std::span<const std::uint8_t> input) = 0;

    /// @brief Raw RSA PKCS#1 v1.5 decrypt of @p ciphertext.
    [[nodiscard]] virtual BytesResult decrypt(const std::string& reader, const std::string& certId,
                                              std::span<const std::uint8_t> ciphertext) = 0;
};

} // namespace LibreSCRS::Pkcs11Agent
