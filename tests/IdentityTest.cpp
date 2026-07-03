// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/Identity.h>
#include <gtest/gtest.h>
#include <map>

using namespace LibreSCRS::Agent;

TEST(Identity, DefaultIsNone)
{
    EXPECT_TRUE(CallerToken{}.empty());
    EXPECT_FALSE(ObjectId{}.valid());
    EXPECT_EQ(ObjectId{}.value(), 0u);
    EXPECT_FALSE(OperationId{}.valid());
    EXPECT_EQ(OperationId{}.value(), 0u);
}

TEST(Identity, NonZeroIsValid)
{
    EXPECT_TRUE(ObjectId{1}.valid());
    EXPECT_TRUE(OperationId{42}.valid());
    EXPECT_EQ(OperationId{42}.value(), 42u);
    EXPECT_FALSE(CallerToken{":1.7"}.empty());
    EXPECT_EQ(CallerToken{":1.7"}.str(), ":1.7");
}

TEST(Identity, EqualityAndOrderingKeyMaps)
{
    // The three newtypes replace std::string / raw object-path strings as
    // std::map keys, so equality + strong ordering must be usable.
    std::map<OperationId, int> ops;
    ops.emplace(OperationId{2}, 20);
    ops.emplace(OperationId{1}, 10);
    EXPECT_EQ(ops.begin()->first, OperationId{1}); // ordered ascending
    EXPECT_EQ(ops.size(), 2u);

    std::map<CallerToken, int> callers;
    callers.emplace(CallerToken{":1.5"}, 1);
    EXPECT_TRUE(callers.contains(CallerToken{":1.5"}));
    EXPECT_FALSE(callers.contains(CallerToken{":1.9"}));

    EXPECT_EQ(ObjectId{7}, ObjectId{7});
    EXPECT_NE(ObjectId{7}, ObjectId{8});
}
