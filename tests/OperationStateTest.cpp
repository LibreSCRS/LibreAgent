// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one-shot "the client has read the operation's state" hook: a host that
// must not emit before its client can receive calls noteObserved(); the
// operation installs what to do then with onObserved().
#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>

#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

TEST(OperationState, AnActionInstalledBeforeTheObservationWaitsForIt)
{
    OperationState state;
    int runs = 0;
    state.onObserved([&] { ++runs; });
    EXPECT_EQ(runs, 0);
    state.noteObserved();
    EXPECT_EQ(runs, 1);
}

TEST(OperationState, TheActionRunsOnceHoweverOftenTheStateIsObserved)
{
    OperationState state;
    int runs = 0;
    state.onObserved([&] { ++runs; });
    state.noteObserved();
    state.noteObserved();
    state.noteObserved();
    EXPECT_EQ(runs, 1);
}

TEST(OperationState, AnActionInstalledAfterTheObservationRunsAtOnceOnTheCaller)
{
    OperationState state;
    state.noteObserved();
    std::thread::id ranOn;
    state.onObserved([&] { ranOn = std::this_thread::get_id(); });
    EXPECT_EQ(ranOn, std::this_thread::get_id());
}

TEST(OperationState, NoObservationMeansNoExecution)
{
    OperationState state;
    int runs = 0;
    state.onObserved([&] { ++runs; });
    EXPECT_EQ(runs, 0);
}

// The action may call back into the state (a sink that observes, an op that
// installs again): that deadlocks if it runs under the state's own lock.
TEST(OperationState, TheActionRunsOutsideTheInternalLock)
{
    OperationState state;
    int inner = 0;
    state.onObserved([&] {
        state.noteObserved();
        state.onObserved([&] { ++inner; });
    });
    state.noteObserved();
    EXPECT_EQ(inner, 1);
}

TEST(OperationState, ConcurrentObservationsRunTheActionExactlyOnce)
{
    for (int round = 0; round < 50; ++round) {
        OperationState state;
        std::atomic<int> runs{0};
        state.onObserved([&] { runs.fetch_add(1); });
        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i) {
            threads.emplace_back([&] { state.noteObserved(); });
        }
        for (auto& t : threads) {
            t.join();
        }
        EXPECT_EQ(runs.load(), 1);
    }
}

TEST(OperationState, TheExistingMembersAreStillPlainAtomics)
{
    OperationState state;
    state.phase.store(3);
    state.cancelled.store(true);
    EXPECT_EQ(state.phase.load(), 3u);
    EXPECT_TRUE(state.cancelled.load());
}

namespace {

class BareChannel final : public OperationChannel
{
public:
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus, ErrorCode, std::string_view, std::string_view) noexcept override {}
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }
};

} // namespace

TEST(OperationChannelDefaults, AChannelDoesNotAwaitAnObserverUnlessItSaysSo)
{
    BareChannel channel;
    EXPECT_FALSE(channel.groupsAwaitObserver());
}
