// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end regression for the credential/read-cache scrub-on-removal path.
//
// The leak this guards against: the caches are populated under the per-card
// object path (the transport backend sets deps.cardKey = cardPath), but the
// CardKeyTracker used to fire onKeyRemoved with the ATR *fingerprint*. The two
// key spaces never intersected, so CredentialCache::invalidate / CardReadCache
// ::invalidate were guaranteed no-ops and the CAN/MRZ + identity snapshot
// leaked for the process lifetime.
//
// This test wires PresenceModel + CardKeyTracker + the caches exactly as
// AgentService/MonitorBridge do, populates the caches under the path the
// exporter would use (the backend id->path mapping), drives a CardRemoved, and
// asserts the caches are actually empty afterwards.

#include <LibreSCRS/Agent/presence/CardKeyTracker.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/Secure/String.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using Secret = LibreSCRS::Secure::String;

namespace {

// These tests exercise cache scrubbing keyed by card path, not capability
// resolution. The base ATR-only seam (no plugin match) is sufficient and opens
// no CardSession.
class FakeResolver : public CapabilityResolver
{};

// Mirror of the AgentService wiring: presence model + tracker + caches, with
// the tracker's onKeyRemoved invalidating both caches by the dropped key.
struct AgentLikeHarness
{
    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model{registry, resolver};
    CredentialCache cache;
    CardReadCache readCache;
    CardKeyTracker tracker;

    // The backend maps a card ObjectId to this object path (mirrors the
    // LibreLinux backend's agentObjectPath); the caches are populated + scrubbed
    // under it. Kept local here so the neutral core carries no path vocabulary.
    static std::string cardPath(ObjectId id)
    {
        return "/org/librescrs/Agent/card/" + std::to_string(id.value());
    }

    AgentLikeHarness()
    {
        tracker.setOnKeyRemoved([this](ObjectId cardKey, const std::string& /*readerName*/) {
            const std::string path = cardPath(cardKey);
            cache.invalidate(path);
            readCache.invalidate(path);
        });
    }

    // Mirror MonitorBridge::dispatch for CardInserted: the model mints the id
    // first, then the tracker records it. The returned path (backend id->path
    // mapping) is the cache key the caller populates the caches under.
    std::string insert(const std::string& reader, const std::vector<std::uint8_t>& atr)
    {
        model.onCardInserted(reader, atr);
        const ObjectId cardId = model.cardIdFor(reader);
        tracker.onCardInserted(reader, cardId);
        return cardPath(cardId);
    }

    void remove(const std::string& reader)
    {
        model.onCardRemoved(reader);
        tracker.onCardRemoved(reader);
    }

    void removeReader(const std::string& reader)
    {
        model.onReaderRemoved(reader);
        tracker.onReaderRemoved(reader);
    }
};

CardReadSnapshot makeSnapshot()
{
    CardReadSnapshot snap;
    snap.cardType = "fake-card";
    return snap;
}

} // namespace

TEST(CacheScrubOnRemoval, CardRemovedScrubsCredentialAndReadCachesKeyedByCardPath)
{
    AgentLikeHarness h;
    const std::string cardPath = h.insert("Acme CL 0", {0x3B, 0x01});
    ASSERT_EQ(cardPath, "/org/librescrs/Agent/card/2"); // auto-added reader takes id 1, its card id 2

    // Populate the caches under the SAME key the exporter would use
    // (deps.cardKey = cardPath). This is exactly the production population key.
    h.cache.putCan(cardPath, Secret{"123456"});
    h.readCache.put(cardPath, makeSnapshot());
    ASSERT_TRUE(h.cache.hasCan(cardPath));
    ASSERT_TRUE(h.readCache.get(cardPath).has_value());

    h.remove("Acme CL 0");

    EXPECT_FALSE(h.cache.hasCan(cardPath)) << "CardRemoved must scrub the cached CAN (was a guaranteed leak)";
    EXPECT_FALSE(h.readCache.get(cardPath).has_value()) << "CardRemoved must scrub the cached identity snapshot";
}

TEST(CacheScrubOnRemoval, ReaderRemovedScrubsCachesKeyedByCardPath)
{
    AgentLikeHarness h;
    const std::string cardPath = h.insert("Acme CL 0", {0x3B, 0x01});

    h.cache.putMrz(cardPath, Secret{"P<MRZ"});
    h.readCache.put(cardPath, makeSnapshot());

    h.removeReader("Acme CL 0");

    EXPECT_FALSE(h.cache.hasMrz(cardPath));
    EXPECT_FALSE(h.readCache.get(cardPath).has_value());
}

TEST(CacheScrubOnRemoval, ReinsertScrubsPreviousCardPathCache)
{
    AgentLikeHarness h;
    const std::string firstPath = h.insert("Acme CL 0", {0x3B, 0x01});
    h.cache.putCan(firstPath, Secret{"111111"});
    h.readCache.put(firstPath, makeSnapshot());

    // A new card swapped in without an intervening CardRemoved: the model
    // mints a fresh path, the tracker fires onKeyRemoved for the old path.
    const std::string secondPath = h.insert("Acme CL 0", {0x3B, 0x02});
    EXPECT_NE(firstPath, secondPath);

    EXPECT_FALSE(h.cache.hasCan(firstPath)) << "the previous card's CAN must be scrubbed on swap";
    EXPECT_FALSE(h.readCache.get(firstPath).has_value());

    // The new card's cache (under its own path) is independent and untouched.
    h.cache.putCan(secondPath, Secret{"222222"});
    EXPECT_TRUE(h.cache.hasCan(secondPath));
}
