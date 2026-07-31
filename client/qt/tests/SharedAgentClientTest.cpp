// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The process-wide shared AgentClient accessor. Consumers that reach the
// agent from several independent entry points -- a menu action, a file-manager
// worker, a background sweep -- each call sharedAgentClient(); they must all
// receive the SAME instance, so the agent connection and its ObjectManager
// discovery are established once per process rather than once per entry point.
// A regression here is not a crash but a quiet cost: every caller paying for
// its own connection and its own discovery round trip.
//
// Runs under dbus-run-session because the production AgentClient constructor
// builds this platform's default transport, which touches the session bus. No
// agent need be present on that bus -- construction alone is what is
// exercised.

#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/SharedAgentClient.h>

#include <gtest/gtest.h>

#include <memory>

using namespace LibreSCRS::AgentClient;

TEST(SharedAgentClient, ReturnsOneInstanceAcrossCallers)
{
    std::shared_ptr<AgentClient> first = sharedAgentClient();
    std::shared_ptr<AgentClient> second = sharedAgentClient();

    ASSERT_NE(first.get(), nullptr);
    // Same object -> a second caller reuses the first's connection/discovery.
    EXPECT_EQ(first.get(), second.get());
}
