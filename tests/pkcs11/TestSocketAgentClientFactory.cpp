// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// This tree's answer to AgentClientFactory.h, for the module the suites here
// dlopen.
//
// It is deliberately NOT part of any exported component. A definition shipped
// inside an archive would either collide with a real host's own or, worse,
// silently win and send that host looking for the agent at a path this file
// invented -- which on the platform that has a real container path would be the
// one place the agent is not.

#include <LibreSCRS/Agent/pkcs11/AgentClientFactory.h>
#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>

#include <cstdlib>
#include <string>

namespace LibreSCRS::Pkcs11Agent {

std::unique_ptr<AgentClient> makeAgentClient()
{
    const char* sock = std::getenv("LIBRESCRS_AGENT_SOCK");
    return std::make_unique<SocketAgentClient>(std::string{sock != nullptr ? sock : ""});
}

} // namespace LibreSCRS::Pkcs11Agent
