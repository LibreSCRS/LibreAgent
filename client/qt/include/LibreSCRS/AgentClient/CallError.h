// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

// LOCAL client-side call-failure classification -- never itself serialized
// on the wire (contrast LibreSCRS::Agent::ErrorCode, re-exported by
// ErrorCode.h in this same directory, which IS a wire value). A lifted
// AgentClient method (a later task) returns this when it cannot even get a
// wire-level answer: no agent, no reply in time, transport broke mid-call,
// or the call was rejected before any op started.
namespace LibreSCRS::AgentClient {

enum class CallError : std::uint8_t {
    None,             // call succeeded; no error
    AgentUnavailable, // no agent reachable on the transport (not running / no socket)
    Timeout,          // no reply within the call's ClientTimeouts budget
    AccessDenied,     // rejected by the local IPC access-control layer (not a wire sync-error)
    InvalidArguments, // caller-side argument validation failed before any wire send
    TransportFailure, // the socket/transport itself failed mid-call (read/write/fd-passing error)
    ProtocolError,    // a reply/event failed to decode against the wire contract
};

} // namespace LibreSCRS::AgentClient
