// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <gtest/gtest.h>

using namespace LibreSCRS::Agent;

TEST(Identity, ObjectIdReservesZeroForNone)
{
    EXPECT_FALSE(ObjectId{}.valid());
    EXPECT_TRUE(ObjectId{1}.valid());
    EXPECT_EQ(ObjectId{1}.value(), 1u);
    EXPECT_LT(ObjectId{1}, ObjectId{2}); // ordering for std::map keys
    EXPECT_EQ(ObjectId{7}, ObjectId{7});
}

TEST(PresenceTypes, TypedStatesCarryObjectIds)
{
    ReaderState r{.id = ObjectId{1}, .name = "R0", .hasCard = true, .card = ObjectId{2}};
    EXPECT_EQ(r.card, ObjectId{2});
    CardState c{.id = ObjectId{2},
                .reader = ObjectId{1},
                .capabilities = 0x3u,
                .preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::None};
    EXPECT_EQ(c.reader, ObjectId{1});
    PropertyDelta d{.hasCard = false, .card = ObjectId{}};
    EXPECT_FALSE(d.card.valid());
}
