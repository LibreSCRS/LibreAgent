// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

/// @file
/// @brief Why the agent quiesced card access, wire-frozen and append-only.

namespace LibreSCRS::Agent {

/// @brief Why the agent quiesced card access: the holder's session went away
///        (the machine sleeps, the user switched away, the screen locked) or
///        the agent is stopping.
///
/// One vocabulary for every platform. The host translates its own system
/// events into a reason (systemd-logind on Linux, the workspace and power
/// notifications on macOS) and hands it to the core, which decides what to
/// forget; the agent then announces the same reason to every client
/// (D-Bus `Manager1.Quiesced`, socket `AgentQuiesced`).
///
/// WIRE-FROZEN, APPEND-ONLY: the integers travel. A client decodes a value
/// past the last one it knows through verbatim, as a quiesce for a reason it
/// cannot name.
///
/// @since 5.0
enum class QuiesceReason : std::uint8_t {
    SystemSleep = 0,     ///< The machine is about to sleep; the reader loses power.
    ScreenLocked = 1,    ///< The holder's screen locked; the session itself stays.
    SessionInactive = 2, ///< The holder's session stopped being the active one (user switch).
    Shutdown = 3,        ///< The agent is stopping.
};

} // namespace LibreSCRS::Agent
