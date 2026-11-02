// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. Resolution of the agent's AF_UNIX socket path
// for the socket transport.
//
// On macOS the socket is the App-Group container's agent.sock
// (Wire/SocketLocation.h names both), reached by its well-known absolute path
// under the user's home as the password database records it. Nothing in the
// environment moves it: `launchctl setenv` reaches every process the user's
// launchd starts, so a variable that relocated the socket — or a redirected
// $HOME — would let any process running as the user put its own listener in
// front of every client. On every other platform there is no production
// default: this transport ships there only as the testable implementation, and
// resolution yields an empty path, which the transport treats as "no agent
// socket on this system".
//
// Test binaries that compile this file themselves define
// LIBREAGENT_CLIENT_SOCKET_TESTING, which adds one override read from
// kAgentSocketEnvVar so a test can point the production constructor at its fake
// agent. The shipped library is never built with it.

#include <QString>
#include <QStringView>

namespace LibreSCRS::AgentClient {

#if defined(LIBREAGENT_CLIENT_SOCKET_TESTING)
/// The test-build-only override (see the file comment).
inline constexpr const char* kAgentSocketEnvVar = "LIBRESCRS_AGENT_SOCK";
#endif

/// @brief The macOS App Group shared by the host application, its
///        CryptoTokenKit extension, and the agent, for a signing team
///        (`Wire::appGroupFor`, as a QString).
[[nodiscard]] QString appGroupFor(QStringView team);

/// @brief The App Group of the team this build was configured with
///        (the LIBRESCRS_TEAM_ID CMake cache variable).
[[nodiscard]] QString agentAppGroupIdentifier();

/// @brief The user's home directory as the password database records it, the
///        environment's $HOME only when that lookup fails.
[[nodiscard]] QString accountHomeDirectory();

/// @brief The agent socket path; empty when the platform has no production
///        default.
[[nodiscard]] QString resolveAgentSocketPath();

} // namespace LibreSCRS::AgentClient
