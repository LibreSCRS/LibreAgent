// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. Resolution of the agent's AF_UNIX socket path
// for the socket transport: the one place that knows the App-Group container
// name and the resolution order, mirroring the Swift client's
// AgentSocketPath.resolve() exactly so both native clients find the same
// agent socket:
//   1. LIBRESCRS_AGENT_SOCK, when set to a non-empty value (tests, local
//      development against a non-container-installed agent).
//   2. The platform default: on macOS the App-Group container's agent.sock
//      (reached by its well-known absolute path — the same directory a
//      sandboxed process resolves through the application-groups
//      entitlement). On every other platform there is NO production default
//      — this transport ships on Linux only as the testable implementation,
//      and every test binds its fake agent to a temp path it exports via the
//      environment override — so resolution yields an empty path, which the
//      transport treats as "no agent socket on this system".
#include <QString>
#include <QStringView>

namespace LibreSCRS::AgentClient {

/// The environment override consulted first (same spelling as the Swift
/// client's AgentSocketPath.environmentOverrideKey).
inline constexpr const char* kAgentSocketEnvVar = "LIBRESCRS_AGENT_SOCK";

/// @brief The macOS App Group shared by the host application, its
///        CryptoTokenKit extension, and the agent, for a signing team.
///
/// Named after the team, because macOS 27 refuses an unprovisioned `group.`
/// container to a sandboxed process; an empty team (CI, tests) keeps the
/// `group.` spelling. The same rule as the agent's and the Swift client's.
[[nodiscard]] QString appGroupFor(QStringView team);

/// @brief The App Group of the team this build was configured with
///        (the LIBRESCRS_TEAM_ID CMake cache variable).
[[nodiscard]] QString agentAppGroupIdentifier();

/// @brief Resolve the agent socket path in the documented order. Empty when
///        no override is set and the platform has no production default.
[[nodiscard]] QString resolveAgentSocketPath();

} // namespace LibreSCRS::AgentClient
