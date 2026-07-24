// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// Default call-timeout budgets (milliseconds) for the transport-neutral Qt
// client. Plain int, not std::chrono::milliseconds: every Qt timer/socket
// timeout API these feed (QTimer::start, a bus pending-call watcher, a raw
// AF_UNIX poll/recv deadline) takes int msec, and keeping the unit in the
// name avoids a duration<->int conversion at every call site.
//
// These are CLIENT-side defaults only -- nothing on the wire carries a
// timeout value (see wire/librescrs-agent.cddl); the agent's own per-op
// WatchdogTimeoutSeconds (op-progress's watchdogSecs) is a SEPARATE,
// server-side budget the client just observes. A caller of the lifted API
// (a later task) may override any of these per-call; these are only the
// library's out-of-the-box defaults.
namespace LibreSCRS::AgentClient {

// Cheap synchronous round-trips with no card/network work on the agent side
// (Hello handshake, GetState, GetConfig): a slow reply here means the agent
// is unresponsive, not merely busy with a card.
inline constexpr int kHandshakeTimeoutMs = 1000;

// The ordinary budget for a synchronous request/reply pair that may touch a
// smart card (ReadIdentity, ReadCertificates op-started acknowledgement,
// ListCredentials, ManagePin, Pkcs11.* method calls) but does no network I/O.
inline constexpr int kDefaultCallTimeoutMs = 3000;

// Long-running operations whose completion may involve a network round trip
// on the agent side (a TSA contact for a timestamped Sign, or a trusted-list
// revocation fetch for the b-lt/b-lta chain-completion family) -- these
// finish via the async op-progress/op-result-ready/op-finished event
// sequence, not a single reply, but a client still needs an overall budget
// to give up waiting on a stalled operation.
inline constexpr int kLongOperationTimeoutMs = 35000;

} // namespace LibreSCRS::AgentClient
