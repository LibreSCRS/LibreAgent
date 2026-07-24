// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

/// @file
/// @brief Wire-stable operation progress/outcome enums, shared by every
///        agent transport and re-exported to the Qt client.

namespace LibreSCRS::Agent::Operations {

/// @brief Wire-stable progress phase of an in-flight operation; match
///        `org.librescrs.Agent.Operation1.xml`. APPEND-ONLY, never renumbered.
///        Carried alongside a progress fraction on the operation's progress
///        notification (see `AgentOperation::phaseChanged()` on the Qt
///        client); not every operation kind visits every phase.
enum class OperationPhase : std::uint32_t {
    Created = 0,         ///< Minted, not yet dispatched to the transport.
    Connecting = 1,      ///< Establishing contact with the card/reader.
    AwaitingConsent = 2, ///< Waiting on a user-facing prompt (PIN/CAN/consent).
    Authenticating = 3,  ///< Running a card-side authentication step (e.g. BAC/PACE, PIN verify).
    Reading = 4,         ///< Reading card data (identity fields, certificates, photo).
    Signing = 5,         ///< Running the signing engine.
    Timestamping = 6,    ///< Contacting a timestamp authority (LT/LTA signature levels).
    Done = 7,            ///< Terminal phase; the operation has finished (see `OperationStatus` for the outcome).
};

/// @brief Wire-stable terminal outcome of an operation, carried alongside
///        `ErrorCode` (see `LibreSCRS/Agent/wire/ErrorCode.h`) on the
///        operation-finished signal. APPEND-ONLY, same freeze policy as
///        `OperationPhase` above.
enum class OperationStatus : std::uint32_t {
    Ok = 0,        ///< The operation completed successfully; its typed result is valid.
    Cancelled = 1, ///< The operation was cancelled (by the caller or the agent).
    Error = 2,     ///< The operation failed; see `ErrorCode` for the reason.
};

} // namespace LibreSCRS::Agent::Operations
