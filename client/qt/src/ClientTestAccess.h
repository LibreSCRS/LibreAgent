// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed, and never part of the shipped library. The test
// seam this repository's suites construct an AgentClient through: over an
// injected TransportSeam (a fake, or a concrete transport bound to a private
// test bus or socket) instead of the production default. It exists only in the
// testing archive (LibreAgentClientQtTesting, built with
// LIBREAGENT_CLIENT_TESTING), so the shared library has no way to swap its
// transport and its public header names no test hook.

#include <memory>
#include <optional>

class QObject;

namespace LibreSCRS::AgentClient {

class AgentClient;
class TransportSeam;

struct ClientTestAccess
{
    /// Construct an AgentClient over @p transport. The client takes
    /// ownership; construction runs the same initial availability probe +
    /// discovery as the production ctor. A null @p transport builds the
    /// inert transport-less client.
    [[nodiscard]] static AgentClient* create(std::unique_ptr<TransportSeam> transport, QObject* parent = nullptr);
};

/// The transport ClientTestAccess::create() is handing to the client it is
/// constructing, taken exactly once; disengaged for every other construction.
[[nodiscard]] std::optional<std::unique_ptr<TransportSeam>> takeInjectedTransport();

} // namespace LibreSCRS::AgentClient
