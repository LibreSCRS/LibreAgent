// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>

#include <gtest/gtest.h>
#include <chrono>
#include <thread>

using LibreSCRS::Agent::CardReadCache;
using LibreSCRS::Agent::CardReadSnapshot;
using LibreSCRS::Agent::FieldType;
using namespace std::chrono_literals;

namespace {

CardReadSnapshot makeSnap(std::string cardType)
{
    CardReadSnapshot snap;
    snap.cardType = std::move(cardType);
    snap.groups.push_back({.groupKey = "personal",
                           .labelKey = "g.personal",
                           .labelFallback = "Personal",
                           .fields = {{.fieldKey = "name",
                                       .labelKey = "f.name",
                                       .labelFallback = "Name",
                                       .type = FieldType::Text,
                                       .textValue = "ANA",
                                       .binaryValue = {}}}});
    return snap;
}

} // namespace

TEST(CardReadCache, GetReturnsNulloptWhenAbsent)
{
    CardReadCache cache(30s);
    EXPECT_FALSE(cache.get("missing").has_value());
}

TEST(CardReadCache, PutThenGetWithinTtlReturnsSnapshot)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    auto fetched = cache.get("card-A");
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->cardType, "rs-eid");
}

TEST(CardReadCache, GetAfterTtlReturnsNullopt)
{
    CardReadCache cache(10ms); // intentionally short for the test
    cache.put("card-A", makeSnap("rs-eid"));
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(cache.get("card-A").has_value()) << "entry past TTL must not be returned";
}

TEST(CardReadCache, InvalidateDropsEntry)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value());
}

TEST(CardReadCache, MultiCardIsolation)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.put("card-B", makeSnap("nam"));
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value());
    auto b = cache.get("card-B");
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->cardType, "nam");
}

TEST(CardReadCache, PutReplacesExistingEntry)
{
    CardReadCache cache(30s);
    cache.put("card-A", makeSnap("rs-eid"));
    cache.put("card-A", makeSnap("nam"));
    auto a = cache.get("card-A");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->cardType, "nam") << "put must replace, not merge";
}
