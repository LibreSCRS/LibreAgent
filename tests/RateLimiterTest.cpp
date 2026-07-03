// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Deterministic exercise of the sign rate-limiter via an injected clock. No
// wall-clock dependency, no sleeps.
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/Identity.h>
#include <gtest/gtest.h>
#include <chrono>

using namespace LibreSCRS::Agent::Operations;
using LibreSCRS::Agent::CallerToken;
using namespace std::chrono_literals;

namespace {
struct FakeClock
{
    std::chrono::steady_clock::time_point now{};
    void advance(std::chrono::steady_clock::duration d)
    {
        now += d;
    }
};
} // namespace

TEST(RateLimiter, AllowsUpToWindowCapThenDenies)
{
    FakeClock clk;
    RateLimiter rl([&clk] { return clk.now; });
    for (std::size_t i = 0; i < RateLimiter::kMaxPerWindow; ++i) {
        EXPECT_TRUE(rl.allow(CallerToken{"client"})) << "attempt " << i;
    }
    EXPECT_FALSE(rl.allow(CallerToken{"client"})) << "the (N+1)th attempt within the window is denied";
}

TEST(RateLimiter, SeparateCallersAreIndependent)
{
    FakeClock clk;
    RateLimiter rl([&clk] { return clk.now; });
    for (std::size_t i = 0; i < RateLimiter::kMaxPerWindow; ++i) {
        EXPECT_TRUE(rl.allow(CallerToken{"a"}));
    }
    EXPECT_FALSE(rl.allow(CallerToken{"a"}));
    EXPECT_TRUE(rl.allow(CallerToken{"b"})) << "a different caller has its own budget";
}

TEST(RateLimiter, WindowSlidesSoOldAttemptsAgeOut)
{
    FakeClock clk;
    RateLimiter rl([&clk] { return clk.now; });
    for (std::size_t i = 0; i < RateLimiter::kMaxPerWindow; ++i) {
        EXPECT_TRUE(rl.allow(CallerToken{"client"}));
    }
    EXPECT_FALSE(rl.allow(CallerToken{"client"}));
    // Past the window AND past any backoff the denial started: attempts age out.
    clk.advance(RateLimiter::kWindow + RateLimiter::kMaxBackoff + 1s);
    EXPECT_TRUE(rl.allow(CallerToken{"client"}));
}

TEST(RateLimiter, ContinuedAbuseGrowsBackoffPastTheWindow)
{
    FakeClock clk;
    RateLimiter rl([&clk] { return clk.now; });
    for (std::size_t i = 0; i < RateLimiter::kMaxPerWindow; ++i) {
        EXPECT_TRUE(rl.allow(CallerToken{"client"})); // fills the window at t=0
    }
    EXPECT_FALSE(rl.allow(CallerToken{"client"})); // t=0: denial #1 -> base backoff (2s)
    // Keep hammering late in the window: each denial escalates the backoff.
    clk.advance(59s);
    EXPECT_FALSE(rl.allow(CallerToken{"client"})); // t=59s: window still full -> backoff grows (~4s, until ~63s)
    // Past the window so the t=0 attempts age out, but still inside the escalated
    // backoff: the backoff is now the binding constraint.
    clk.advance(2s); // t=61s
    EXPECT_FALSE(rl.allow(CallerToken{"client"}));
    // Past the escalated backoff: recovered.
    clk.advance(RateLimiter::kMaxBackoff);
    EXPECT_TRUE(rl.allow(CallerToken{"client"}));
}
