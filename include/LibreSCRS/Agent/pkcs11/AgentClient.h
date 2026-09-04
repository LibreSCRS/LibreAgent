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

/// @brief The RSA public key (modulus + public exponent) for a signing cert.
///        Both are unpadded big-endian (PKCS#11 CKA_* convention) exactly as the
///        agent returns them. The module serves CKA_MODULUS / CKA_PUBLIC_EXPONENT
///        from these without any crypto of its own.
struct PublicKeyResult
{
    Status status = Status::GeneralError;
    std::vector<std::uint8_t> modulus;
    std::vector<std::uint8_t> exponent;
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

    /// @brief RSA public key (modulus + public exponent) for (reader, certId).
    ///        Public data (no consent, no lease). The module serves
    ///        CKA_MODULUS / CKA_PUBLIC_EXPONENT from these.
    [[nodiscard]] virtual PublicKeyResult publicKey(const std::string& reader, const std::string& certId) = 0;

    /// @brief Establish/refresh the login lease (raises the agent prompter).
    ///        The lease is (caller, card)-scoped (C_Login is per-token), so no
    ///        certId is passed.
    [[nodiscard]] virtual LoginResult login(const std::string& reader) = 0;

    /// @brief Drop the lease for (caller, card). Idempotent.
    virtual Status logout(const std::string& reader) = 0;

    /// @brief Raw RSA PKCS#1 v1.5 sign over @p input (DigestInfo-or-raw bytes).
    [[nodiscard]] virtual BytesResult signRaw(const std::string& reader, const std::string& certId,
                                              std::span<const std::uint8_t> input) = 0;

    /// @brief Raw RSA PKCS#1 v1.5 decrypt of @p ciphertext.
    [[nodiscard]] virtual BytesResult decrypt(const std::string& reader, const std::string& certId,
                                              std::span<const std::uint8_t> ciphertext) = 0;
};

} // namespace LibreSCRS::Pkcs11Agent
