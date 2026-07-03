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
    std::atomic<int> emits{0};
    PropertyEmissionThrottler throttler([&] { emits.fetch_add(1); }, 100ms);
    for (int i = 0; i < 50; ++i) {
        throttler.schedule();
    }
    std::this_thread::sleep_for(250ms);
    // Burst of 50 schedules within one 100 ms window must coalesce to AT
    // MOST ~3 emits (one per window across 250 ms). Allow some slack for
    // scheduler jitter; the upper bound is the load-bearing assertion.
    const int observed = emits.load();
    EXPECT_GE(observed, 1) << "throttler dropped every emit — schedule path broken";
    EXPECT_LE(observed, 4) << "throttler did not coalesce (got " << observed << " emits)";
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
