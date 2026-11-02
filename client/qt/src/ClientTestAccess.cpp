// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compiled into the testing archive only (see ClientTestAccess.h).

#include "ClientTestAccess.h"

#include <LibreSCRS/AgentClient/AgentClient.h>

#include "TransportSeam.h"

#include <utility>

namespace LibreSCRS::AgentClient {

namespace {
// Per thread: a client is constructed on the thread that calls create(), and
// the slot is filled and drained inside that one call.
thread_local std::optional<std::unique_ptr<TransportSeam>> t_injected;
} // namespace

std::optional<std::unique_ptr<TransportSeam>> takeInjectedTransport()
{
    return std::exchange(t_injected, std::nullopt);
}

AgentClient* ClientTestAccess::create(std::unique_ptr<TransportSeam> transport, QObject* parent)
{
    t_injected = std::move(transport);
    return new AgentClient(parent);
}

} // namespace LibreSCRS::AgentClient
