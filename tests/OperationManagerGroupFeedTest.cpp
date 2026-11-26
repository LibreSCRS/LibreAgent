// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// IdentityGroupFeed is the background read's record of the groups it has read
// and the list of relays that follow it. A follower must see every group
// exactly once, in order, however its attach falls between two records.
//
// Every wait is bounded; a failure says so instead of hanging.
#include "operations/GroupRelay.h"
#include "operations/IdentityGroupFeed.h"

#include <LibreSCRS/Agent/operations/Seams.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

GroupSnapshot group(const std::string& key)
{
    return {key, "group." + key, key, {{"f", "field.f", "F", FieldType::Text, "VALUE-" + key, {}}}};
}

class KeySink final : public GroupSink
{
public:
    void groupReady(const GroupSnapshot& g) noexcept override
    {
        std::lock_guard lock(m_mutex);
        m_keys.push_back(g.groupKey);
        if (onGroup) {
            onGroup(g.groupKey);
        }
    }
    [[nodiscard]] std::vector<std::string> keys()
    {
        std::lock_guard lock(m_mutex);
        return m_keys;
    }
    std::function<void(const std::string&)> onGroup;

private:
    std::mutex m_mutex;
    std::vector<std::string> m_keys;
};

using Keys = std::vector<std::string>;

} // namespace

TEST(OperationManagerGroupFeed, AttachIsRefusedBeforeTheReadBeginsAndAfterItEnds)
{
    IdentityGroupFeed feed("card-X");
    KeySink sink;
    EXPECT_FALSE(feed.attach(std::make_shared<GroupRelay>(sink))) << "attached before beginRead";

    feed.beginRead();
    auto relay = std::make_shared<GroupRelay>(sink);
    EXPECT_TRUE(feed.attach(relay));

    feed.close();
    EXPECT_FALSE(feed.attach(std::make_shared<GroupRelay>(sink))) << "attached after close";
    EXPECT_EQ(feed.cardKey(), "card-X");
}

TEST(OperationManagerGroupFeed, ReplayAndLiveGroupsArriveOnceAndInOrder)
{
    IdentityGroupFeed feed("card-X");
    feed.beginRead();
    feed.record(group("g1"));
    feed.record(group("g2"));

    KeySink sink;
    auto relay = std::make_shared<GroupRelay>(sink);
    ASSERT_TRUE(feed.attach(relay));
    feed.record(group("g3")); // live while the relay is still parked
    EXPECT_TRUE(sink.keys().empty()) << "a parked relay emitted";

    relay->release();
    EXPECT_EQ(sink.keys(), (Keys{"g1", "g2", "g3"}));
    feed.record(group("g4")); // live after the release: drained by record itself
    EXPECT_EQ(sink.keys(), (Keys{"g1", "g2", "g3", "g4"}));
}

TEST(OperationManagerGroupFeed, TheRecordIsGoneAfterClose)
{
    IdentityGroupFeed feed("card-X");
    feed.beginRead();
    feed.record(group("g1"));
    feed.close();

    // A reopened read must not replay what the closed one recorded.
    feed.beginRead();
    KeySink sink;
    auto relay = std::make_shared<GroupRelay>(sink);
    ASSERT_TRUE(feed.attach(relay));
    relay->release();
    EXPECT_TRUE(sink.keys().empty()) << "a group survived the close";
}

// Draining happens outside the feed's lock: a sink that calls back into the feed
// would deadlock a feed that drained under it.
TEST(OperationManagerGroupFeed, ASinkMayCallBackIntoTheFeed)
{
    IdentityGroupFeed feed("card-X");
    feed.beginRead();
    KeySink sink;
    sink.onGroup = [&](const std::string&) { feed.close(); };
    auto relay = std::make_shared<GroupRelay>(sink);
    ASSERT_TRUE(feed.attach(relay));
    relay->release();

    auto done = std::async(std::launch::async, [&] { feed.record(group("g1")); });
    if (done.wait_for(5s) != std::future_status::ready) {
        ADD_FAILURE() << "record deadlocked on a sink that called back into the feed";
        std::fflush(nullptr);
        std::_Exit(1);
    }
    EXPECT_EQ(sink.keys(), (Keys{"g1"}));
}

// The race the feed exists to close: attach() on one thread while record() runs
// on another. Whatever the interleaving, the follower gets each group once and in
// order -- no gap between the replay and the live groups, no duplicate.
TEST(OperationManagerGroupFeed, AttachRacingRecordNeitherLosesNorRepeatsAGroup)
{
    constexpr int kGroups = 60;
    for (int round = 0; round < 200; ++round) {
        IdentityGroupFeed feed("card-X");
        feed.beginRead();
        KeySink sink;
        auto relay = std::make_shared<GroupRelay>(sink);
        std::atomic<bool> go{false};
        std::atomic<bool> attached{false};

        std::thread producer([&] {
            while (!go.load()) {
                std::this_thread::yield();
            }
            for (int i = 1; i <= kGroups; ++i) {
                feed.record(group("g" + std::to_string(i)));
                if (i == kGroups / 2) {
                    std::this_thread::yield();
                }
            }
        });
        std::thread follower([&] {
            while (!go.load()) {
                std::this_thread::yield();
            }
            for (int spin = round % 7; spin > 0; --spin) {
                std::this_thread::yield();
            }
            attached.store(feed.attach(relay));
            relay->release();
        });
        go.store(true);
        producer.join();
        follower.join();
        relay->drain();

        ASSERT_TRUE(attached.load()) << "the feed was open for the whole round";
        Keys expected;
        for (int i = 1; i <= kGroups; ++i) {
            expected.push_back("g" + std::to_string(i));
        }
        ASSERT_EQ(sink.keys(), expected) << "round " << round;
    }
}
