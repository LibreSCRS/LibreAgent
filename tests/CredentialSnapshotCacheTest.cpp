// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit tests for the per-card credential-SNAPSHOT cache: monotonic versioning,
// per-card isolation, scrub-on-drop, and the sliding idle window (mirrors
// CardReadCache). The removal-driven case is exercised against the cache directly.

#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

using LibreSCRS::Agent::CredentialRecord;
using LibreSCRS::Agent::CredentialSnapshot;
using LibreSCRS::Agent::CredentialSnapshotCache;
using namespace std::chrono_literals;

namespace {

// A snapshot with one populated record, so the scrub-on-drop branch (record
// strings + optional guidance) is actually exercised when an entry is dropped.
CredentialSnapshot makeSnapshot(std::string label = "Qualified signature PIN")
{
    CredentialRecord record;
    record.id = "sign:0x92";
    record.label = std::move(label);
    record.kind = "sign";
    record.state = "operational";
    record.retriesLeft = 3;
    record.minLength = 4;
    record.maxLength = 8;
    record.recovery = "holderViaPuk";
    record.blockedGuidanceKey = "guidance.blocked";
    record.blockedGuidanceFallback = "PIN blocked; unblock with the PUK";
    CredentialSnapshot snapshot;
    snapshot.records.push_back(std::move(record));
    return snapshot;
}

} // namespace

// --- the cache: versioning, isolation, residency --------------------------

TEST(CredentialSnapshotCache, GetReturnsNulloptWhenAbsent)
{
    CredentialSnapshotCache cache(30s);
    EXPECT_FALSE(cache.get("missing").has_value());
}

TEST(CredentialSnapshotCache, PutThenGetReturnsSnapshotWithStampedVersion)
{
    CredentialSnapshotCache cache(30s);
    const std::uint64_t version = cache.put("card-A", makeSnapshot());
    EXPECT_GE(version, 1u) << "0 is reserved for a never-cached snapshot";

    auto fetched = cache.get("card-A");
    ASSERT_TRUE(fetched.has_value());
    ASSERT_EQ(fetched->records.size(), 1u);
    EXPECT_EQ(fetched->records.front().id, "sign:0x92");
    EXPECT_EQ(fetched->version, version) << "the stored snapshot carries the stamped version";
}

TEST(CredentialSnapshotCache, PutStampsStrictlyIncreasingVersions)
{
    CredentialSnapshotCache cache(30s);
    const std::uint64_t v1 = cache.put("card-A", makeSnapshot());
    const std::uint64_t v2 = cache.put("card-B", makeSnapshot());
    const std::uint64_t v3 = cache.put("card-A", makeSnapshot()); // re-list of A
    EXPECT_LT(v1, v2);
    EXPECT_LT(v2, v3) << "version is agent-wide monotonic across cards and re-lists";
}

TEST(CredentialSnapshotCache, VersionIsNeverReusedAcrossInvalidate)
{
    CredentialSnapshotCache cache(30s);
    const std::uint64_t v1 = cache.put("card-A", makeSnapshot());
    cache.invalidate("card-A");
    const std::uint64_t v2 = cache.put("card-A", makeSnapshot());
    EXPECT_GT(v2, v1) << "a fresh list after an invalidate must get a higher version, never a reused one";
}

TEST(CredentialSnapshotCache, InvalidateDropsEntry)
{
    CredentialSnapshotCache cache(30s);
    cache.put("card-A", makeSnapshot());
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value());
}

TEST(CredentialSnapshotCache, InvalidateAbsentEntryIsNoop)
{
    CredentialSnapshotCache cache(30s);
    cache.invalidate("never-there"); // must not throw / crash
    EXPECT_FALSE(cache.get("never-there").has_value());
}

TEST(CredentialSnapshotCache, MultiCardIsolation)
{
    CredentialSnapshotCache cache(30s);
    cache.put("card-A", makeSnapshot("A-PIN"));
    cache.put("card-B", makeSnapshot("B-PIN"));
    cache.invalidate("card-A");
    EXPECT_FALSE(cache.get("card-A").has_value());
    auto b = cache.get("card-B");
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->records.front().label, "B-PIN") << "invalidating one card leaves the other intact";
}

TEST(CredentialSnapshotCache, PutReplacesExistingEntry)
{
    CredentialSnapshotCache cache(30s);
    cache.put("card-A", makeSnapshot("first"));
    const std::uint64_t v2 = cache.put("card-A", makeSnapshot("second"));
    auto a = cache.get("card-A");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->records.front().label, "second") << "put replaces, not merges";
    EXPECT_EQ(a->version, v2) << "the replacement carries the newer version";
}

TEST(CredentialSnapshotCache, GetAfterIdleWindowReturnsNullopt)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CredentialSnapshotCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnapshot());

    *now += 200ms; // idle past the window
    EXPECT_FALSE(cache.get("card-A").has_value());

    // Rewinding the clock must NOT resurrect it: an expired entry is ERASED
    // (and zeroized), not merely hidden behind a timestamp check.
    *now -= 200ms;
    EXPECT_FALSE(cache.get("card-A").has_value()) << "expired entry is erased, not merely hidden";
}

TEST(CredentialSnapshotCache, SlidingWindowRefreshesOnEachGet)
{
    auto now = std::make_shared<std::chrono::steady_clock::time_point>();
    CredentialSnapshotCache cache(100ms, [now] { return *now; });
    cache.put("card-A", makeSnapshot());

    *now += 80ms; // within the window: get() returns AND refreshes the timer
    ASSERT_TRUE(cache.get("card-A").has_value());

    *now += 70ms; // 150 ms since put, only 70 ms since the last get -> still warm
    EXPECT_TRUE(cache.get("card-A").has_value()) << "sliding window: active use keeps the entry warm";
}

TEST(CredentialSnapshotCache, ClearDropsEverything)
{
    CredentialSnapshotCache cache(30s);
    cache.put("card-A", makeSnapshot());
    cache.put("card-B", makeSnapshot());
    cache.clear();
    EXPECT_FALSE(cache.get("card-A").has_value());
    EXPECT_FALSE(cache.get("card-B").has_value());
}

// The removal hook (AgentService, a later task) calls snapshotCache.invalidate()
// on the dropped card key exactly like this. Unit-tested against the cache here.
TEST(CredentialSnapshotCache, RemovalDrivenInvalidateDropsSnapshot)
{
    CredentialSnapshotCache cache(30s);
    const std::string cardKey = "/org/librescrs/Agent/card/2";
    cache.put(cardKey, makeSnapshot());
    ASSERT_TRUE(cache.get(cardKey).has_value());

    cache.invalidate(cardKey); // the removal hook's call
    EXPECT_FALSE(cache.get(cardKey).has_value());
}
