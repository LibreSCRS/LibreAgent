// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

/// @file
/// @brief Client-side, transport-local call-failure classification.

namespace LibreSCRS::AgentClient {

/// @brief LOCAL client-side call-failure classification — never itself
///        serialized on the wire (contrast `ErrorCode`, re-exported by
///        ErrorCode.h in this same directory, which IS a wire-carried
///        value). `AgentOperation::callError()` holds this when the
///        operation failed WITHOUT ever getting a wire-level answer: no
///        agent reachable, no reply in time, the transport broke mid-call,
///        or the call was rejected locally before any operation started.
///
/// The split with `ErrorCode`: `callError()` and `errorCode()` are
/// mutually exclusive on a failed operation. When the agent DID answer —
/// even with a failure — the answer is an `ErrorCode` and `callError()`
/// stays `None`; when the client never got that far, `errorCode()` stays
/// `None` and the reason is here instead.
enum class CallError : std::uint8_t {
    None,             ///< Call succeeded, or the operation failed with a wire-level `ErrorCode` instead.
    AgentUnavailable, ///< No agent reachable on the transport (not running / no socket).
    Timeout,          ///< No reply within the call's `ClientTimeouts` budget.
    AccessDenied,     ///< Rejected by the local IPC access-control layer (not a wire sync-error).
    InvalidArguments, ///< Caller-side argument validation failed before any wire send.
    TransportFailure, ///< The socket/transport itself failed mid-call (read/write/fd-passing error).
    ProtocolError,    ///< A reply/event failed to decode against the wire contract.
};

} // namespace LibreSCRS::AgentClient
