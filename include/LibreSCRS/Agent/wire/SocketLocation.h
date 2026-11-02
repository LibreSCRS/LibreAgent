// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <string>
#include <string_view>

/// @file
/// @brief Where the macOS agent's socket lives: the App Group container shared
///        by the LibreMac host, its token extension, the agent and the
///        prompter, and the socket's name inside it.
///
/// Every end of the socket wire (the agent that binds it, the Qt client, the
/// PKCS#11 module, the Swift clients) names the same container, so the rule is
/// written once here. `wire/wire-vocabulary.json` carries the same two facts
/// for the ends that cannot include a C++ header.

namespace LibreSCRS::Agent::Wire {

/// The socket's file name inside the App Group container.
inline constexpr std::string_view kAgentSocketName = "agent.sock";

/// What follows the team in the App Group name.
inline constexpr std::string_view kAppGroupSuffix = ".org.librescrs.LibreMac";

/// What stands in for the team when the build names none.
inline constexpr std::string_view kNoTeamAppGroupPrefix = "group";

/// The App Group for a signing team: "<team>.org.librescrs.LibreMac", or
/// "group.org.librescrs.LibreMac" for a build without a team (CI, tests).
/// Named after the team because macOS 27 refuses an unprovisioned "group."
/// container to a sandboxed process; a group carrying the team prefix needs no
/// provisioning profile.
[[nodiscard]] inline std::string appGroupFor(std::string_view team)
{
    std::string group{team.empty() ? kNoTeamAppGroupPrefix : team};
    group += kAppGroupSuffix;
    return group;
}

} // namespace LibreSCRS::Agent::Wire
