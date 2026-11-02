// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — macOS only. Starting the agent there means launching the host
// app that registers its launchd job and kicking that job.

#include <LibreSCRS/AgentClient/AgentClient.h>

namespace LibreSCRS::AgentClient {

/// Launch the LibreMac host in the background (never activating it) and, once
/// it runs, kick the agent's launchd job. Returns at once: `Requested` when the
/// launch was started, `NotInstalled` when no host exists, `NotInApplications`
/// when one exists only outside an Applications folder, where a translocated
/// copy cannot register a lasting agent.
[[nodiscard]] AgentStartResult startMacAgentHost();

} // namespace LibreSCRS::AgentClient
