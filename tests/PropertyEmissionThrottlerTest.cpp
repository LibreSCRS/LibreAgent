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
    std::atomic<int> emits{0};
    PropertyEmissionThrottler throttler([&] { emits.fetch_add(1); }, 100ms);
    throttler.schedule();
    throttler.flush(); // synchronous: by the time flush() returns the emit has fired
    EXPECT_EQ(emits.load(), 1);
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
