// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>

#include <memory>

/// @file
/// @brief The process-wide shared `AgentClient` accessor.

namespace LibreSCRS::AgentClient {

class AgentClient;

/// @brief The one process-wide `AgentClient`, created lazily on first call.
///        Every caller gets the SAME instance, so the agent connection +
///        discovery are established once per process, not per consumer.
///        Co-owned via `shared_ptr` so a caller may hold it for an
///        operation's duration; its internal availability watch keeps
///        liveness current, so a long-lived shared client also SEES an
///        on-demand-startable agent appear after a cold start.
///
/// @note Single-shared-library rule: this accessor relies on there being
///       exactly ONE copy of this library in the process (the default shared
///       build). Statically duplicating the library across plugin boundaries
///       would mint one "shared" client per copy — a known Qt static-state
///       failure mode this library's packaging deliberately avoids.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT std::shared_ptr<AgentClient> sharedAgentClient();

} // namespace LibreSCRS::AgentClient
