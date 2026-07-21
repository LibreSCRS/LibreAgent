// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/OperationPhase.h> // OperationStatus (the finish status)
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <cstdint>

namespace LibreSCRS::Agent {

// Defined in <LibreSCRS/Agent/value/CredentialRecord.h>; forward-declared here so
// this lean taxonomy header need not pull in the credential-record machinery.
// A scoped enum's underlying type defaults to int, so this opaque declaration
// matches the definition and stays in sync (a later explicit underlying type on
// the definition would break this on purpose).
enum class CredentialOutcome;

// Stable agent-side error taxonomy. Carried on the agent's operation-finished
// signal as the `errorCode` field; clients branch on the numeric value.
//
// WIRE-FROZEN, APPEND-ONLY. Existing entries are never renumbered or removed:
// the integers are a published wire contract. New codes are only ever appended
// with the next free value.
//
// This enum is the single source of truth, but its integers are mirrored by
// hand in three out-of-repo consumers plus this repo's own guard test. All of
// them MUST be updated in lockstep whenever a code is appended here:
//
//   1. The Linux agent host (LibreLinux) — its CBOR/CDDL wire schema and the
//      client-side error taxonomy it exposes.
//   2. The KDE client — its mirror of the taxonomy.
//   3. The macOS Swift host — its `AgentTypes` mirror. This one is FAIL-CLOSED
//      with NO automatic guard: an unknown/unmirrored code is treated as a hard
//      error rather than silently ignored, so a forgotten append surfaces as a
//      macOS failure, not a wrong branch.
//   4. This repo's guard test (tests/ErrorTaxonomyTest.cpp) pins every integer
//      and the current maximum, so an append here trips CI until the pin is
//      added — the reminder to also update the three mirrors above.
enum class ErrorCode : std::uint32_t {
    None = 0,
    CardRemoved = 1,
    CredentialWrong = 2,
    CredentialBlocked = 3,
    CommunicationError = 4,
    ParseError = 5,
    UnsupportedCard = 6,
    AuthFailed = 7,
    // The prompter UI failed or was absent on the bus (no org.librescrs.Prompter1
    // owner / proxy throw / memfd I/O error) — distinct from a wrong secret
    // (CredentialWrong) or a generic transport failure (CommunicationError). The
    // flows remap their final code to this when the credential provider reports a
    // PromptStatus::Error (set via the prompterFailed flag); a cancellation or a
    // wrong-but-collected secret never maps here.
    PrompterError = 8,
    CapabilityMissing = 9,
    WatchdogTimeout = 10,
    // Signing. Append-only; never renumber.
    KeyNotFound = 11,        // chosen cert not resolvable / certId mismatch
    KeyAmbiguous = 12,       // >1 key matches the discriminator
    CertExpiredBlocked = 13, // expired signer blocked (per-level policy)
    ChainIncomplete = 14,    // chain cannot be completed/validated (LT family)
    TsaUnreachable = 15,     // timestamp authority unreachable/unconfigured
    SigningEngineError = 16, // engine failure not otherwise classified
    RateLimited = 17,        // too many sign requests from the caller
    EngineUnavailable = 18,  // the signing engine/security module could not load (deployment)
    InvalidDocument = 19,    // the document to sign is invalid/unreadable — client input
};

[[nodiscard]] ErrorCode errorCodeFor(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept;

[[nodiscard]] ErrorCode errorCodeFor(LibreSCRS::Plugin::ReadResult::Status status) noexcept;

// The (finish status, wire ErrorCode) pair a credential-mutation outcome resolves
// to on the operation-finished signal. Unlike the two mappers above, a credential
// outcome also fixes the finish STATUS: a user cancel finishes Cancelled with no
// error code (cancellation is an OperationStatus, never an ErrorCode), while every
// failure finishes Error and the numeric code carries the coarse class — the finer
// distinctions (retries left, blocked, key-activation vs verify) ride the Result
// payload, not this integer.
struct CredentialFinish
{
    // Fail-closed defaults: an unassigned pair reads as an Error with a generic
    // transport code, never a spurious Ok / None.
    Operations::OperationStatus status = Operations::OperationStatus::Error;
    ErrorCode code = ErrorCode::CommunicationError;
    [[nodiscard]] bool operator==(const CredentialFinish&) const noexcept = default;
};

[[nodiscard]] CredentialFinish errorCodeFor(CredentialOutcome outcome) noexcept;

} // namespace LibreSCRS::Agent
