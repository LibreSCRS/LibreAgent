// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief The default stall bound of an `AgentOperation`, in milliseconds.
///
/// Plain `int`, not `std::chrono::milliseconds`: it feeds `QTimer::start()`,
/// which takes int msec. A CLIENT-side default only — nothing on the wire
/// carries a timeout value — and a caller may override it per operation with
/// `AgentOperation::setStallBudget()`.

namespace LibreSCRS::AgentClient {

/// @brief How long an operation may go without a sign of life from the agent
///        while the agent is working — long enough for a network round trip
///        on the agent side (a TSA contact for a timestamped Sign, or a
///        trusted-list revocation fetch for the b-lt/b-lta chain-completion
///        family). Operations finish via the async op-progress /
///        op-result-ready / op-finished sequence, not a single reply; every
///        AgentOperation gives up after this much silence by default, and the
///        clock does not run while a person is at the agent's prompt.
inline constexpr int kLongOperationTimeoutMs = 35000;

} // namespace LibreSCRS::AgentClient
