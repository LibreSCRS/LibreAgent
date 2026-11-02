// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/CardKeyTracker.h>
#include <LibreSCRS/Agent/Identity.h>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;

namespace {
// The tracker keys on the per-insertion card ObjectId that PresenceModel mints,
// NOT the ATR fingerprint. Distinct non-zero ids stand in for distinct card
// insertions (the backend maps each back to a card object path).
const ObjectId kCard0{10};
const ObjectId kCard1{11};
const ObjectId kCard2{12};
constexpr const char* kReader0 = "Acme CL 0";
constexpr const char* kReader1 = "Acme CL 1";

// The key @p t holds for @p reader, read the only way production reads it: by
// removing the card and taking what the removal reports. Destructive, and it
// replaces any callback the test installed, so it is a test's last look.
std::optional<ObjectId> keyFor(CardKeyTracker& t, const std::string& reader)
{
    std::optional<ObjectId> seen;
    t.setOnKeyRemoved([&](ObjectId k, const std::string&) { seen = k; });
    t.onCardRemoved(reader);
    t.setOnKeyRemoved({});
    return seen;
}
} // namespace

TEST(CardKeyTracker, OnCardInsertedRecordsKey)
{
    CardKeyTracker t;
    t.onCardInserted(kReader0, kCard0);

    const auto key = keyFor(t, kReader0);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(*key, kCard0);
}

TEST(CardKeyTracker, CurrentKeyOnUnknownReaderIsNullopt)
{
    CardKeyTracker t;
    EXPECT_FALSE(keyFor(t, "never-inserted").has_value());
}

// Leak-reproducing regression: the key fired on CardRemoved MUST equal the
// per-insertion card ObjectId that was inserted (the same id the backend maps to
// the path the cache is populated under). With the old fingerprint keying the
// fired key was provisionalFingerprint(atr), which never matched the cardPath the
// cache was populated under -> invalidate() was a guaranteed no-op and CAN/MRZ +
// the identity snapshot leaked.
TEST(CardKeyTracker, OnCardRemovedFiresCallbackWithCardIdAndDropsMapping)
{
    CardKeyTracker t;
    std::vector<ObjectId> removed;
    std::vector<std::string> removedReaders;
    t.setOnKeyRemoved([&](ObjectId k, const std::string& r) {
        removed.push_back(k);
        removedReaders.push_back(r);
    });

    t.onCardInserted(kReader0, kCard0);

    t.onCardRemoved(kReader0);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0], kCard0) << "the scrub key must equal the card ObjectId the cache was keyed by";
    ASSERT_EQ(removedReaders.size(), 1u);
    EXPECT_EQ(removedReaders[0], kReader0) << "the reader name must be forwarded so its session can be invalidated";
    EXPECT_FALSE(keyFor(t, kReader0).has_value());
}

TEST(CardKeyTracker, OnReaderRemovedFiresCallbackWithCardIdAndDropsMapping)
{
    CardKeyTracker t;
    std::vector<ObjectId> removed;
    std::vector<std::string> removedReaders;
    t.setOnKeyRemoved([&](ObjectId k, const std::string& r) {
        removed.push_back(k);
        removedReaders.push_back(r);
    });

    t.onCardInserted(kReader0, kCard0);

    t.onReaderRemoved(kReader0);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0], kCard0);
    ASSERT_EQ(removedReaders.size(), 1u);
    EXPECT_EQ(removedReaders[0], kReader0);
    EXPECT_FALSE(keyFor(t, kReader0).has_value());
}

TEST(CardKeyTracker, RemovingUnknownReaderIsSilentNoOp)
{
    CardKeyTracker t;
    int fireCount = 0;
    t.setOnKeyRemoved([&](ObjectId, const std::string&) { ++fireCount; });

    t.onCardRemoved("not-present");
    t.onReaderRemoved("also-not-present");

    EXPECT_EQ(fireCount, 0);
}

TEST(CardKeyTracker, ReinsertIntoSameReaderOverwritesPreviousKey)
{
    CardKeyTracker t;
    std::vector<ObjectId> removed;
    t.setOnKeyRemoved([&](ObjectId k, const std::string&) { removed.push_back(k); });

    t.onCardInserted(kReader0, kCard0);

    // Second insert without an intervening CardRemoved — the tracker must
    // drop the previous mapping (firing the callback so the cache for the
    // OLD card ObjectId is invalidated) before recording the new one. The
    // monotonic counter means the new card gets a fresh id.
    t.onCardInserted(kReader0, kCard1);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0], kCard0);

    const auto current = keyFor(t, kReader0);
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(*current, kCard1);
    EXPECT_NE(*current, kCard0);
}

TEST(CardKeyTracker, IndependentReadersDoNotInterfere)
{
    CardKeyTracker t;
    std::vector<ObjectId> removed;
    t.setOnKeyRemoved([&](ObjectId k, const std::string&) { removed.push_back(k); });

    t.onCardInserted(kReader0, kCard0);
    t.onCardInserted(kReader1, kCard1);

    t.onCardRemoved(kReader0);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0], kCard0);

    // Reader 1 still has its mapping.
    const auto stillThere = keyFor(t, kReader1);
    ASSERT_TRUE(stillThere.has_value());
    EXPECT_EQ(*stillThere, kCard1);
}

// Two same-batch cards share an ATR (so the old fingerprint key would collide
// across them), but each insertion mints a distinct card ObjectId — so the
// tracker keeps them distinct and the per-card cache entries never cross.
TEST(CardKeyTracker, SameAtrCardsOnDifferentReadersGetDistinctKeys)
{
    CardKeyTracker t;
    t.onCardInserted(kReader0, kCard0);
    t.onCardInserted(kReader1, kCard2);

    const auto k0 = keyFor(t, kReader0);
    const auto k1 = keyFor(t, kReader1);
    ASSERT_TRUE(k0.has_value());
    ASSERT_TRUE(k1.has_value());
    EXPECT_NE(*k0, *k1) << "distinct insertions must never share a cache key, even with an identical ATR";
}

TEST(CardKeyTracker, CallbackUnsetMeansRemovalIsSilent)
{
    CardKeyTracker t;
    // No setOnKeyRemoved call — std::function is empty.
    t.onCardInserted(kReader0, kCard0);
    t.onCardRemoved(kReader0); // must not crash on empty std::function
    EXPECT_FALSE(keyFor(t, kReader0).has_value());
}
