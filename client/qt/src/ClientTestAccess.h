// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The test seam that replaces the lifted client's
// deleted test-bus injection ctor: this repo's own suites (and the later
// transport-parity suite) construct an AgentClient over an injected
// TransportSeam (a fake, or a concrete transport bound to a private test
// bus/socket) instead of the production default. Exported from the shared
// library (the symbol must be reachable from test executables) but the header
// stays out of the install tree, so no consumer can reach it.
#include <LibreSCRS/AgentClient/Export.h>

#include <memory>

class QObject;

namespace LibreSCRS::AgentClient {

class AgentClient;
class TransportSeam;

struct LIBRESCRS_AGENTCLIENT_EXPORT ClientTestAccess
{
    /// Construct an AgentClient over @p transport (must be non-null). The
    /// client takes ownership; construction runs the same initial
    /// availability probe + discovery as the production ctor.
    [[nodiscard]] static AgentClient* create(std::unique_ptr<TransportSeam> transport, QObject* parent = nullptr);
};

} // namespace LibreSCRS::AgentClient
