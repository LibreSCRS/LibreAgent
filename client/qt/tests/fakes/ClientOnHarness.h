// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// Test-only glue: build a production AgentClient wired to a Harness's
// FakeAgent, over the SAME DBusTransport a real deployment uses. Every
// FakeAgent-backed suite goes through this one path instead of constructing
// AgentClient/AgentCard/AgentReader directly — the public lift's scrub made
// those constructors private (minted only by AgentClient), so the ONLY way
// to exercise the real D-Bus transport in a test is the transport's own
// test constructor plus the exported ClientTestAccess factory.

#include "TestBus.h"

#include <LibreSCRS/AgentClient/AgentClient.h>

#include "ClientTestAccess.h"
#include "dbus/DBusTransport.h"

#include <memory>

namespace LibreSCRS::AgentClient::Fakes {

/// @brief Construct an AgentClient bound to @p harness's FakeAgent via a real
///        DBusTransport (its private-bus test constructor). Runs the same
///        initial availability probe + discovery as production.
[[nodiscard]] inline std::unique_ptr<LibreSCRS::AgentClient::AgentClient> makeClient(Harness& harness,
                                                                                     QObject* parent = nullptr)
{
    auto transport = std::make_unique<LibreSCRS::AgentClient::DBusTransport>(harness.client(), harness.service());
    return std::unique_ptr<LibreSCRS::AgentClient::AgentClient>(
        LibreSCRS::AgentClient::ClientTestAccess::create(std::move(transport), parent));
}

} // namespace LibreSCRS::AgentClient::Fakes
