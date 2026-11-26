// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// GroupRelay is the serial executor that emits one attached operation's groups:
// parked until released, one emitter at a time, nothing called under its lock,
// and a close that never waits for an emit in progress. Each case asserts what a
// naive implementation (emit under the lock, close by waiting) would get wrong.
//
// Every wait is bounded; a failure says so instead of hanging.
#include "operations/GroupRelay.h"

#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
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

constexpr auto kBound = 5s;

GroupSnapshot group(const std::string& key)
{
    return {key, "group." + key, key, {{"f", "field.f", "F", FieldType::Text, "VALUE-" + key, {}}}};
}

class Latch
{
public:
    void open()
    {
        {
            std::lock_guard lock(m_mutex);
            m_open = true;
        }
        m_cv.notify_all();
    }
    [[nodiscard]] bool wait()
    {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, kBound, [this] { return m_open; });
    }
    [[nodiscard]] bool isOpen()
    {
        std::lock_guard lock(m_mutex);
        return m_open;
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_open{false};
};

// Records the keys it was given, notices two calls overlapping, and can park the
// first call on a latch.
class RecordingSink final : public GroupSink
{
public:
    void groupReady(const GroupSnapshot& g) noexcept override
    {
        if (inside.fetch_add(1) != 0) {
            overlapped.store(true);
        }
        {
            std::lock_guard lock(m_mutex);
            m_keys.push_back(g.groupKey);
            m_threads.push_back(std::this_thread::get_id());
        }
        if (parkFirst && !parked.exchange(true)) {
            entered.open();
            (void)hold.wait();
        }
        inside.fetch_sub(1);
    }
    [[nodiscard]] std::vector<std::string> keys()
    {
        std::lock_guard lock(m_mutex);
        return m_keys;
    }
    [[nodiscard]] std::vector<std::thread::id> threads()
    {
        std::lock_guard lock(m_mutex);
        return m_threads;
    }

    std::atomic<int> inside{0};
    std::atomic<bool> overlapped{false};
    bool parkFirst{false};
    std::atomic<bool> parked{false};
    Latch entered; ///< the parked call is inside the sink
    Latch hold;    ///< opened by the test to let it return

private:
    std::mutex m_mutex;
    std::vector<std::string> m_keys;
    std::vector<std::thread::id> m_threads;
};

using Keys = std::vector<std::string>;

} // namespace

// 1. Parked: nothing is emitted until release(); then in order.
TEST(OperationManagerGroupRelay, ParkedRelayEmitsNothingUntilReleased)
{
    RecordingSink sink;
    GroupRelay relay(sink);
    relay.enqueue(group("g1"));
    relay.enqueue(group("g2"));
    relay.drain();
    EXPECT_TRUE(sink.keys().empty()) << "a parked relay emitted";
    EXPECT_FALSE(relay.delivered("g1"));

    relay.release();
    EXPECT_EQ(sink.keys(), (Keys{"g1", "g2"}));
    EXPECT_TRUE(relay.delivered("g1"));
    EXPECT_TRUE(relay.delivered("g2"));
    EXPECT_FALSE(relay.delivered("g3"));

    relay.enqueue(group("g3"));
    relay.drain();
    EXPECT_EQ(sink.keys(), (Keys{"g1", "g2", "g3"}));
}

// 2. A close from another thread does not wait for an emit in progress, runs its
//    action exactly once and only after the last group, and stops all emitting.
TEST(OperationManagerGroupRelay, CloseDuringAnEmitReturnsAtOnceAndRunsItsActionAfterTheEmit)
{
    RecordingSink sink;
    sink.parkFirst = true;
    GroupRelay relay(sink);
    relay.enqueue(group("g1"));
    relay.enqueue(group("g2")); // still pending when the close comes: must never be emitted

    std::thread emitter([&] { relay.release(); });
    ASSERT_TRUE(sink.entered.wait()) << "the emit never started";

    std::atomic<int> actionRuns{0};
    std::thread::id actionThread;
    std::atomic<bool> actionRanBeforeEmitEnded{false};
    const auto start = std::chrono::steady_clock::now();
    relay.closeThen([&] {
        actionRanBeforeEmitEnded.store(!sink.hold.isOpen());
        actionThread = std::this_thread::get_id();
        actionRuns.fetch_add(1);
    });
    const auto took = std::chrono::steady_clock::now() - start;
    EXPECT_LT(took, 1s) << "closeThen waited for the emit";
    EXPECT_EQ(actionRuns.load(), 0) << "the action ran while a group was being emitted";

    const auto emitterId = emitter.get_id();
    sink.hold.open();
    emitter.join();

    EXPECT_EQ(actionRuns.load(), 1) << "the deferred action must run exactly once";
    EXPECT_FALSE(actionRanBeforeEmitEnded.load());
    EXPECT_EQ(actionThread, emitterId) << "the deferred action runs on the draining thread";
    EXPECT_EQ(sink.keys(), (Keys{"g1"})) << "a group pending at close was emitted";

    relay.enqueue(group("g3"));
    relay.drain();
    EXPECT_EQ(sink.keys(), (Keys{"g1"})) << "the sink was called after close";
    EXPECT_FALSE(sink.overlapped.load());
}

// 3. No emit in progress: the action runs at once, on the calling thread.
TEST(OperationManagerGroupRelay, CloseWithNoEmitRunsTheActionOnTheCaller)
{
    RecordingSink sink;
    GroupRelay relay(sink);
    relay.enqueue(group("g1"));
    int runs = 0;
    std::thread::id ranOn;
    relay.closeThen([&] {
        ++runs;
        ranOn = std::this_thread::get_id();
    });
    EXPECT_EQ(runs, 1);
    EXPECT_EQ(ranOn, std::this_thread::get_id());
    relay.release();
    EXPECT_TRUE(sink.keys().empty()) << "a group queued before the close was emitted after it";
}

// 4. closeAndWait waits for the emit in progress, and only for that.
TEST(OperationManagerGroupRelay, CloseAndWaitWaitsForTheActiveEmit)
{
    RecordingSink sink;
    sink.parkFirst = true;
    GroupRelay relay(sink);
    relay.enqueue(group("g1"));
    std::thread emitter([&] { relay.release(); });
    ASSERT_TRUE(sink.entered.wait());

    std::atomic<bool> returned{false};
    std::atomic<bool> emitHadEnded{false};
    std::thread closer([&] {
        relay.closeAndWait();
        emitHadEnded.store(sink.inside.load() == 0);
        returned.store(true);
    });
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(returned.load()) << "closeAndWait returned while a group was being emitted";

    sink.hold.open();
    closer.join();
    emitter.join();
    EXPECT_TRUE(emitHadEnded.load());
    EXPECT_TRUE(relay.isClosed());
}

TEST(OperationManagerGroupRelay, CloseAndWaitWithNoEmitReturnsAtOnce)
{
    RecordingSink sink;
    GroupRelay relay(sink);
    relay.enqueue(group("g1"));
    const auto start = std::chrono::steady_clock::now();
    relay.closeAndWait();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
    EXPECT_TRUE(relay.isClosed());
    relay.release();
    EXPECT_TRUE(sink.keys().empty());
}

// 5. Two threads feeding one relay: never two emits at once, nothing lost, nothing twice.
TEST(OperationManagerGroupRelay, ConcurrentEnqueueAndDrainNeverOverlapsOrLosesAGroup)
{
    constexpr int kPerThread = 500;
    RecordingSink sink;
    GroupRelay relay(sink);
    relay.release();
    auto feed = [&](const std::string& prefix) {
        for (int i = 0; i < kPerThread; ++i) {
            relay.enqueue(group(prefix + std::to_string(i)));
            relay.drain();
        }
    };
    std::thread a(feed, "a");
    std::thread b(feed, "b");
    a.join();
    b.join();

    EXPECT_FALSE(sink.overlapped.load()) << "two groups were emitted at the same time";
    const auto keys = sink.keys();
    EXPECT_EQ(keys.size(), static_cast<std::size_t>(2 * kPerThread)) << "a group was lost or emitted twice";
    EXPECT_EQ(std::set<std::string>(keys.begin(), keys.end()).size(), keys.size()) << "a group was emitted twice";
    // Each thread's own groups stay in the order it enqueued them.
    int lastA = -1;
    int lastB = -1;
    for (const auto& key : keys) {
        int& last = key[0] == 'a' ? lastA : lastB;
        const int n = std::stoi(key.substr(1));
        EXPECT_GT(n, last);
        last = n;
    }
}
