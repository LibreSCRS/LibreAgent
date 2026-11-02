// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The App Group and socket name every end of the macOS socket wire uses. The
// expectations are literals: the test must not share the rule with the code.

#include <LibreSCRS/Agent/wire/SocketLocation.h>

#include <gtest/gtest.h>

using LibreSCRS::Agent::Wire::appGroupFor;
using LibreSCRS::Agent::Wire::kAgentSocketName;

TEST(SocketLocation, TheGroupIsNamedAfterTheTeam)
{
    EXPECT_EQ(appGroupFor("ABCDE12345"), "ABCDE12345.org.librescrs.LibreMac");
}

TEST(SocketLocation, WithoutATeamTheGroupKeepsTheGroupPrefix)
{
    EXPECT_EQ(appGroupFor(""), "group.org.librescrs.LibreMac");
}

TEST(SocketLocation, TheSocketIsAgentSock)
{
    EXPECT_EQ(kAgentSocketName, "agent.sock");
}
