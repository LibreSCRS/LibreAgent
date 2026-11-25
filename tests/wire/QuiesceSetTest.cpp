// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// QuiesceSet is the one record of which quiesce reasons are active, shared by
// the hosts (what to announce) and the client (when the agent is reachable).
#include <LibreSCRS/Agent/wire/QuiesceReason.h>
#include <gtest/gtest.h>

using LibreSCRS::Agent::QuiesceReason;
using LibreSCRS::Agent::QuiesceSet;

TEST(QuiesceSet, StartsEmpty)
{
    constexpr QuiesceSet set;
    static_assert(set.empty());
    EXPECT_TRUE(set.empty());
}

TEST(QuiesceSet, BeginReportsNewlyActiveOnly)
{
    QuiesceSet set;
    EXPECT_TRUE(set.begin(QuiesceReason::ScreenLocked));
    EXPECT_FALSE(set.begin(QuiesceReason::ScreenLocked));
    EXPECT_FALSE(set.empty());
}

TEST(QuiesceSet, EndReportsWhetherTheReasonWasActive)
{
    QuiesceSet set;
    EXPECT_FALSE(set.end(QuiesceReason::SystemSleep));
    set.begin(QuiesceReason::SystemSleep);
    EXPECT_TRUE(set.end(QuiesceReason::SystemSleep));
    EXPECT_FALSE(set.end(QuiesceReason::SystemSleep));
    EXPECT_TRUE(set.empty());
}

TEST(QuiesceSet, ReasonsAreIndependentAndEmptyMeansAllEnded)
{
    QuiesceSet set;
    set.begin(QuiesceReason::SystemSleep);
    set.begin(QuiesceReason::ScreenLocked);
    EXPECT_TRUE(set.end(QuiesceReason::ScreenLocked));
    EXPECT_FALSE(set.empty());
    EXPECT_FALSE(set.end(QuiesceReason::SessionInactive));
    EXPECT_FALSE(set.empty());
    EXPECT_TRUE(set.end(QuiesceReason::SystemSleep));
    EXPECT_TRUE(set.empty());
}

TEST(QuiesceSet, HoldsAReasonPastTheLastOneKnown)
{
    // A decoded reason this build cannot name still counts, at either end of
    // the uint8_t range.
    QuiesceSet set;
    EXPECT_TRUE(set.begin(static_cast<QuiesceReason>(42)));
    EXPECT_TRUE(set.begin(static_cast<QuiesceReason>(255)));
    EXPECT_FALSE(set.empty());
    EXPECT_TRUE(set.end(static_cast<QuiesceReason>(42)));
    EXPECT_FALSE(set.empty());
    EXPECT_TRUE(set.end(static_cast<QuiesceReason>(255)));
    EXPECT_TRUE(set.empty());
}

TEST(QuiesceSet, ClearForgetsEveryReason)
{
    QuiesceSet set;
    set.begin(QuiesceReason::SystemSleep);
    set.begin(QuiesceReason::SessionInactive);
    set.clear();
    EXPECT_TRUE(set.empty());
    EXPECT_FALSE(set.end(QuiesceReason::SystemSleep));
}
