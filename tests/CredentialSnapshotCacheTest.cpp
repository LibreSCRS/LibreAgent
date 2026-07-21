// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit tests for the per-card credential-SNAPSHOT cache and the post-mutation
// invalidation RULE. Two things are locked down here:
//
//   1. The cache itself: monotonic versioning, per-card isolation, scrub-on-drop,
//      and the sliding idle window (mirrors CardReadCache).
//   2. The rule (mutationReachedCard / invalidateForMutationOutcome): an attempt
//      that reached the card drops BOTH the snapshot AND the identity/cert read
//      cache; a prompter-only cancel or an agent-side Unsupported short-circuit
//      drops neither; and the CAN/MRZ SECRET cache is NEVER touched.
//
// The removal-driven case is exercised against the cache directly (the AgentService
// removal hook that also calls snapshotCache.invalidate() lands in a later task).

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

using LibreSCRS::Agent::CardReadCache;
using LibreSCRS::Agent::CardReadSnapshot;
using LibreSCRS::Agent::CredentialCache;
using LibreSCRS::Agent::CredentialOutcome;
using LibreSCRS::Agent::CredentialRecord;
using LibreSCRS::Agent::CredentialSnapshot;
using LibreSCRS::Agent::CredentialSnapshotCache;
using LibreSCRS::Agent::invalidateForMutationOutcome;
using LibreSCRS::Agent::mutationReachedCard;
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
    record.unblockStyle = "unblockAndChange";
    record.recovery = "holderViaPuk";
    record.blockedGuidanceKey = "guidance.blocked";
    record.blockedGuidanceFallback = "PIN blocked; unblock with the PUK";
    CredentialSnapshot snapshot;
    snapshot.records.push_back(std::move(record));
    return snapshot;
}

CardReadSnapshot makeReadSnapshot()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    return snap;
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

// --- mutationReachedCard: the outcome classification ----------------------

TEST(MutationReachedCard, ClassifiesEveryOutcome)
{
    // Reached the card / may have moved on-card credential state -> invalidate.
    EXPECT_TRUE(mutationReachedCard(CredentialOutcome::Ok));
    EXPECT_TRUE(mutationReachedCard(CredentialOutcome::InvalidPin));
    EXPECT_TRUE(mutationReachedCard(CredentialOutcome::Blocked));
    EXPECT_TRUE(mutationReachedCard(CredentialOutcome::PluginError));
    EXPECT_TRUE(mutationReachedCard(CredentialOutcome::KeyActivationFailed));

    // No card contact / nothing applied -> keep the caches.
    EXPECT_FALSE(mutationReachedCard(CredentialOutcome::Unspecified));
    EXPECT_FALSE(mutationReachedCard(CredentialOutcome::UserCancelled));
    EXPECT_FALSE(mutationReachedCard(CredentialOutcome::MissingFields));
    EXPECT_FALSE(mutationReachedCard(CredentialOutcome::Unsupported));
    EXPECT_FALSE(mutationReachedCard(CredentialOutcome::CardRemoved));
}

// --- invalidateForMutationOutcome: the rule against the caches ------------

namespace {

// One card seeded into both the snapshot cache and the read cache, so a rule
// application can be checked to drop (or keep) BOTH halves together.
struct SeededCaches
{
    CredentialSnapshotCache snapshotCache{30s};
    CardReadCache readCache{30s};
    std::string cardKey = "card-A";

    SeededCaches()
    {
        snapshotCache.put(cardKey, makeSnapshot());
        readCache.put(cardKey, makeReadSnapshot());
    }

    [[nodiscard]] bool snapshotPresent()
    {
        return snapshotCache.get(cardKey).has_value();
    }
    [[nodiscard]] bool readPresent()
    {
        return readCache.get(cardKey).has_value();
    }
};

} // namespace

TEST(InvalidateForMutationOutcome, InvalidPinDropsBothSnapshotAndReadCache)
{
    SeededCaches c;
    ASSERT_TRUE(c.snapshotPresent());
    ASSERT_TRUE(c.readPresent());

    // A failed PIN change still reached the card (retry counter decremented).
    invalidateForMutationOutcome(CredentialOutcome::InvalidPin, c.cardKey, c.snapshotCache, c.readCache);

    EXPECT_FALSE(c.snapshotPresent()) << "InvalidPin reached the card: snapshot must be dropped";
    EXPECT_FALSE(c.readPresent()) << "InvalidPin reached the card: identity/cert reads must be dropped too";
}

TEST(InvalidateForMutationOutcome, OkDropsBoth)
{
    SeededCaches c;
    invalidateForMutationOutcome(CredentialOutcome::Ok, c.cardKey, c.snapshotCache, c.readCache);
    EXPECT_FALSE(c.snapshotPresent());
    EXPECT_FALSE(c.readPresent());
}

TEST(InvalidateForMutationOutcome, UserCancelledKeepsBoth)
{
    SeededCaches c;
    // Prompter-only cancel: no card contact, so nothing is stale.
    invalidateForMutationOutcome(CredentialOutcome::UserCancelled, c.cardKey, c.snapshotCache, c.readCache);
    EXPECT_TRUE(c.snapshotPresent()) << "a prompter-only cancel must not invalidate the snapshot";
    EXPECT_TRUE(c.readPresent()) << "a prompter-only cancel must not invalidate the read cache";
}

TEST(InvalidateForMutationOutcome, UnsupportedShortCircuitKeepsBoth)
{
    SeededCaches c;
    // Agent-side capability short-circuit: nothing reached the card.
    invalidateForMutationOutcome(CredentialOutcome::Unsupported, c.cardKey, c.snapshotCache, c.readCache);
    EXPECT_TRUE(c.snapshotPresent()) << "an agent-side Unsupported short-circuit must not invalidate the snapshot";
    EXPECT_TRUE(c.readPresent()) << "an agent-side Unsupported short-circuit must not invalidate the read cache";
}

// The CAN/MRZ SECRET cache is a different cache with a different rule: a mutation
// must NEVER evict a still-valid pre-read secret. invalidateForMutationOutcome does
// not even take a CredentialCache — proven here by seeding one with a CAN and
// showing it survives a card-reaching mutation's invalidation (the "spy" that
// proves zero calls: the secret is still there afterward).
TEST(InvalidateForMutationOutcome, SecretCacheIsNeverTouched)
{
    SeededCaches c;
    CredentialCache secretCache;
    secretCache.putCan(c.cardKey, CredentialCache::Secret{"123456"});
    ASSERT_TRUE(secretCache.hasCan(c.cardKey));

    // The strongest card-reaching outcome.
    invalidateForMutationOutcome(CredentialOutcome::Ok, c.cardKey, c.snapshotCache, c.readCache);

    EXPECT_FALSE(c.snapshotPresent()) << "the snapshot IS dropped";
    EXPECT_FALSE(c.readPresent()) << "the read cache IS dropped";
    EXPECT_TRUE(secretCache.hasCan(c.cardKey)) << "the CAN/MRZ secret cache must be untouched by a mutation";
}
