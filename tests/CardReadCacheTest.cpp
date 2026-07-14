// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>

#include <gtest/gtest.h>
#include <chrono>
#include <memory>
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
                                       .binaryValue = {}},
                                      // A non-empty photo field so the binary
                                      // (photo) zeroize branch of scrub() is
                                      // actually exercised on drop.
                                      {.fieldKey = "photo",
                                       .labelKey = "f.photo",
                                       .labelFallback = "Photo",
                                       .type = FieldType::Photo,
                                       .textValue = {},
                                       .binaryValue = {0xFF, 0xD8, 0xFF, 0xE0}}}});
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

// --- item 67: sliding idle window + erase-on-expiry (injected clock) --------

TEST(CardReadCache, SlidingWindowRefreshesOnEachGet)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CardReadCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnap("rs-eid"));

    *now += 80ms; // within the window: get() returns AND refreshes the timer
    ASSERT_TRUE(cache.get("card-A").has_value());

    *now += 70ms; // 150 ms since put, but only 70 ms since the last get -> warm
    EXPECT_TRUE(cache.get("card-A").has_value()) << "sliding window: active use keeps the entry warm";
}

TEST(CardReadCache, IdleBeyondWindowExpiresAndErasesEntry)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CardReadCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnap("rs-eid"));

    *now += 200ms; // idle past the window
    EXPECT_FALSE(cache.get("card-A").has_value());

    // Rewinding the clock must NOT resurrect it: an expired entry is ERASED
    // (and zeroized), not merely hidden behind a timestamp check.
    *now -= 200ms;
    EXPECT_FALSE(cache.get("card-A").has_value()) << "expired entry is erased, not merely hidden";
}
