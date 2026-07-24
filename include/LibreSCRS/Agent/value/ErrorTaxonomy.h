// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/OperationPhase.h> // OperationStatus (the finish status)
#include <LibreSCRS/Agent/wire/ErrorCode.h> // ErrorCode: wire-frozen, <cstdint>-only, LM-free
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>

namespace LibreSCRS::Agent {

// Defined in <LibreSCRS/Agent/value/CredentialRecord.h>; forward-declared here so
// this lean taxonomy header need not pull in the credential-record machinery.
// A scoped enum's underlying type defaults to int, so this opaque declaration
// matches the definition and stays in sync (a later explicit underlying type on
// the definition would break this on purpose).
enum class CredentialOutcome;

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
