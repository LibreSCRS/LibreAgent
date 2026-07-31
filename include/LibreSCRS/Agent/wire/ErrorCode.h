// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

/// @file
/// @brief Stable agent-side error taxonomy, wire-frozen and append-only.

namespace LibreSCRS::Agent {

/// @brief Stable agent-side error taxonomy. Carried on the agent's
///        operation-finished signal as the `errorCode` field; clients branch
///        on the numeric value.
///
/// WIRE-FROZEN, APPEND-ONLY. Existing entries are never renumbered or
/// removed: the integers are a published wire contract. New codes are only
/// ever appended with the next free value.
///
/// This enum is the single source of truth, but its integers are mirrored by
/// hand in two out-of-repo consumers plus this repo's own guard test. All
/// of them MUST be updated in lockstep whenever a code is appended here:
///
///   1. The Linux agent host (LibreLinux) — its CBOR/CDDL wire schema and the
///      client-side error taxonomy it exposes.
///   2. The macOS Swift host — its `AgentTypes` mirror. This one is
///      FAIL-CLOSED with NO automatic guard: an unknown/unmirrored code is
///      treated as a hard error rather than silently ignored, so a forgotten
///      append surfaces as a macOS failure, not a wrong branch.
///   3. This repo's guard test (tests/ErrorTaxonomyTest.cpp) pins every
///      integer and the current maximum, so an append here trips CI until
///      the pin is added — the reminder to also update the two mirrors
///      above.
///
/// The rule for that list: an entry is needed only where the integers are
/// RE-DECLARED, in another language or another wire schema. A consumer that
/// reaches the taxonomy through this repo's Qt client library does not
/// re-declare anything — `LibreSCRS::AgentClient::ErrorCode` is a `using`
/// alias for THIS enum, the same type rather than a copy of its values, so
/// there is nothing on that side that can fall out of step. The KDE desktop
/// client is the worked example: it consumes that alias and holds no mirror
/// of its own, which is why it is absent above.
///
/// @note The Qt client (`LibreSCRS::AgentClient::ErrorCode`, ErrorCode.h in
///       `client/qt/include/LibreSCRS/AgentClient/`) decodes an unrecognised
///       numeric value through verbatim rather than rejecting it — see that
///       header's append-tolerance note.
enum class ErrorCode : std::uint32_t {
    None = 0,               ///< No error.
    CardRemoved = 1,        ///< The card was removed mid-operation.
    CredentialWrong = 2,    ///< A wrong PIN/CAN/secret was supplied.
    CredentialBlocked = 3,  ///< The credential is blocked (retry counter exhausted).
    CommunicationError = 4, ///< Transport/protocol failure talking to the card or a lost/unrecoverable result.
    ParseError = 5,         ///< Card data failed to parse against its expected structure.
    UnsupportedCard = 6,    ///< No plugin matched the card, or the requested op is unsupported on it.
    AuthFailed = 7,         ///< Card-side authentication (e.g. BAC/PACE) failed.
    /// The prompter UI failed or was absent on the bus (no
    /// org.librescrs.Prompter1 owner / proxy throw / memfd I/O error) —
    /// distinct from a wrong secret (`CredentialWrong`) or a generic
    /// transport failure (`CommunicationError`). The flows remap their final
    /// code to this when the credential provider reports a
    /// `PromptStatus::Error` (set via the `prompterFailed` flag); a
    /// cancellation or a wrong-but-collected secret never maps here.
    PrompterError = 8,
    CapabilityMissing = 9, ///< The requested operation needs a capability this card does not report.
    WatchdogTimeout = 10,  ///< The agent's own per-operation watchdog budget elapsed.
    // Signing. Append-only; never renumber.
    KeyNotFound = 11,        ///< Chosen cert not resolvable / certId mismatch.
    KeyAmbiguous = 12,       ///< More than one key matches the discriminator.
    CertExpiredBlocked = 13, ///< Expired signer blocked (per-level policy).
    ChainIncomplete = 14,    ///< Chain cannot be completed/validated (LT family).
    TsaUnreachable = 15,     ///< Timestamp authority unreachable/unconfigured.
    SigningEngineError = 16, ///< Engine failure not otherwise classified.
    RateLimited = 17,        ///< Too many sign requests from the caller.
    EngineUnavailable = 18,  ///< The signing engine/security module could not load (deployment).
    InvalidDocument = 19,    ///< The document to sign is invalid/unreadable — client input.
};

} // namespace LibreSCRS::Agent
