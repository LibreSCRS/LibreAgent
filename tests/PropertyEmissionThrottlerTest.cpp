// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/operations/PropertyEmissionThrottler.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <thread>

using LibreSCRS::Agent::Operations::PropertyEmissionThrottler;
using namespace std::chrono_literals;

TEST(PropertyEmissionThrottler, CoalescesBurstWithinWindow)
{
    constexpr auto window = 100ms;
    std::atomic<int> emits{0};
    PropertyEmissionThrottler throttler([&] { emits.fetch_add(1); }, window);
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 50; ++i) {
        throttler.schedule();
    }
    std::this_thread::sleep_for(250ms);
    // Coalescing invariant: consecutive emits are separated by at least one
    // window (only the very first may fire immediately), so [t0, t1] holds
    // at most elapsed/window + 1 emits NO MATTER how the scheduler stretches
    // this thread — the bound is derived from the measured elapsed time, not
    // from an assumed burst duration. A broken coalescer emits once per
    // schedule() (~50) and always fails. Read the count before taking t1 so
    // the interval covers every counted emit.
    const int observed = emits.load();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    const int maxEmits = static_cast<int>(elapsed / window) + 1;
    EXPECT_GE(observed, 1) << "throttler dropped every emit — schedule path broken";
    EXPECT_LE(observed, maxEmits) << "throttler did not coalesce (got " << observed << " emits in "
                                  << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms)";
}

TEST(PropertyEmissionThrottler, FlushEmitsImmediately)
{
    // No schedule() first: the worker has nothing pending, so the one emit
    // counted here is flush()'s own, and it has to have run on this thread
    // before flush() returned -- that is what "synchronous" means. Nor may
    // flush() leave a request behind: the worker would emit it a window later.
    constexpr auto window = 50ms;
    std::atomic<int> emits{0};
    std::atomic<bool> onCaller{false};
    const auto caller = std::this_thread::get_id();
    PropertyEmissionThrottler throttler(
        [&] {
            emits.fetch_add(1);
            if (std::this_thread::get_id() == caller) {
                onCaller.store(true);
            }
        },
        window);
    throttler.flush();
    EXPECT_EQ(emits.load(), 1);
    EXPECT_TRUE(onCaller.load()) << "flush() returned before emitting on the calling thread";
    std::this_thread::sleep_for(4 * window);
    EXPECT_EQ(emits.load(), 1) << "flush() left a request pending and the worker emitted it";
}

TEST(PropertyEmissionThrottler, FlushAfterScheduleLeavesNothingPending)
{
    // The first schedule() is a leading edge: the worker may emit it at once,
    // before flush() takes the lock. flush() emits anyway -- its callers use it
    // after a state change nobody scheduled (a phase, the spinner), so it
    // cannot skip because the worker just emitted. One emit or two is that
    // race, and the worker's emit may even run after flush() returns, having
    // been committed before it. What holds in every order: flush() emitted
    // once, on this thread, and the worker emitted the one request at most
    // once -- nothing is left pending for a second, trailing emit.
    constexpr auto window = 50ms;
    std::atomic<int> onCaller{0};
    std::atomic<int> onWorker{0};
    const auto caller = std::this_thread::get_id();
    PropertyEmissionThrottler throttler(
        [&] {
            if (std::this_thread::get_id() == caller) {
                onCaller.fetch_add(1);
            } else {
                onWorker.fetch_add(1);
            }
        },
        window);
    throttler.schedule();
    throttler.flush();
    EXPECT_EQ(onCaller.load(), 1) << "flush() must emit exactly once, on the calling thread, before it returns";
    std::this_thread::sleep_for(4 * window);
    EXPECT_EQ(onCaller.load(), 1);
    EXPECT_LE(onWorker.load(), 1) << "the worker emitted one schedule() " << onWorker.load() << " times";
}

TEST(PropertyEmissionThrottler, NoEmitsWithoutSchedule)
{
    std::atomic<int> emits{0};
    PropertyEmissionThrottler throttler([&] { emits.fetch_add(1); }, 50ms);
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(emits.load(), 0) << "throttler must not emit spontaneously";
}

TEST(PropertyEmissionThrottler, DestructorJoinsCleanly)
{
    std::atomic<int> emits{0};
    {
        PropertyEmissionThrottler throttler([&] { emits.fetch_add(1); }, 100ms);
        throttler.schedule();
        // dtor must request_stop + join — no hang, no crash on destruction
        // even with a pending schedule.
    }
    SUCCEED();
}
