// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Default call-timeout budgets (milliseconds) for the
///        transport-neutral Qt client.
///
/// Plain `int`, not `std::chrono::milliseconds`: every Qt timer/socket
/// timeout API these feed (`QTimer::start`, a bus pending-call watcher, a raw
/// AF_UNIX poll/recv deadline) takes int msec, and keeping the unit in the
/// name avoids a duration<->int conversion at every call site.
///
/// @note These are CLIENT-side defaults only — nothing on the wire carries a
///       timeout value (see wire/librescrs-agent.cddl); the agent's own
///       per-op `WatchdogTimeoutSeconds` (op-progress's `watchdogSecs`) is a
///       SEPARATE, server-side budget the client just observes. A caller may
///       override any of these per-call; these are only the library's
///       out-of-the-box defaults.
///
/// @note Enforcement differs per constant: the transports apply
///       kHandshakeTimeoutMs and kDefaultCallTimeoutMs internally to their
///       synchronous round-trips, but kLongOperationTimeoutMs is a
///       CALLER-ENFORCED advisory budget — the library has NO internal
///       watchdog and never auto-fails a stalled operation. A consumer that
///       wants stall detection must run its own timer against this constant
///       and call AgentOperation::cancel() when it expires.

namespace LibreSCRS::AgentClient {

/// @brief Budget for cheap synchronous round-trips with no card/network work
///        on the agent side (Hello handshake, GetState, GetConfig): a slow
///        reply here means the agent is unresponsive, not merely busy with a
///        card.
inline constexpr int kHandshakeTimeoutMs = 1000;

/// @brief The ordinary budget for a synchronous request/reply pair that may
///        touch a smart card (ReadIdentity, ReadCertificates op-started
///        acknowledgement, ListCredentials, ManagePin, Pkcs11.* method
///        calls) but does no network I/O.
inline constexpr int kDefaultCallTimeoutMs = 3000;

/// @brief Budget for a synchronous call the agent may hold open while a PERSON
///        authorizes it (a polkit prompt on Linux, the equivalent ceremony on
///        another host): Config1 SetValue/Reset, whose trust tier is gated, and
///        ImportCscaMasterList, which is gated outright.
///
/// Sized for a human, not for a machine, because a human is what it waits on:
/// finding a password manager, mistyping once, reading the prompt. Two minutes
/// is generous for that and still bounded, so an agent that dies mid-ceremony
/// does not hang the caller forever.
///
/// This is its own budget rather than a reach for kDefaultCallTimeoutMs or
/// kLongOperationTimeoutMs because it measures something neither of those does.
/// The card budget assumes the only wait is a chip; the long-operation budget
/// is a CALLER-ENFORCED advisory with no transport enforcement behind it. An
/// authorization ceremony is enforced here, in the transport, and its length is
/// set by a person's hands.
///
/// The cost is accepted deliberately: a caller cannot know which config keys
/// the agent gates (the tiers are the agent's, not the client's), so every
/// SetValue/Reset is budgeted as though it might prompt. An unresponsive agent
/// is therefore reported slowly rather than quickly — the trade taken because
/// the opposite error is a false refusal shown to a person who did nothing
/// wrong, and that one happens on every ordinary use.
inline constexpr int kAuthorizedCallTimeoutMs = 120000;

/// @brief Budget for long-running operations whose completion may involve a
///        network round trip on the agent side (a TSA contact for a
///        timestamped Sign, or a trusted-list revocation fetch for the
///        b-lt/b-lta chain-completion family) — these finish via the async
///        op-progress/op-result-ready/op-finished event sequence, not a
///        single reply, but a client still needs an overall budget to give
///        up waiting on a stalled operation.
inline constexpr int kLongOperationTimeoutMs = 35000;

} // namespace LibreSCRS::AgentClient
