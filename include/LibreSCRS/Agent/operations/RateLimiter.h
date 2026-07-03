// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // CallerToken
#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <mutex>

namespace LibreSCRS::Agent::Operations {

// Per-caller request throttle for the Card1.Sign entry. Under the agent's
// default-allow authorization posture + single-prompt PIN-as-consent, an unbounded
// caller could drive reflexive-PIN phishing; this caps sign attempts per caller
// and converts a flood into a hard error (Error.RateLimited) rather than yet
// another prompt.
//
// Keyed by the caller's UNIQUE D-Bus name (":1.42") — reuse-immune for the
// connection lifetime (the same TOCTOU-safe handle the Authorizer uses), so it
// cannot be spoofed and survives PID reuse. ctor-DI'd with a clock so tests
// drive time deterministically (no singleton, no wall-clock dependency).
//
// Policy: at most kMaxPerWindow attempts per kWindow; exceeding it starts an
// exponential backoff (kBaseBackoff doubling per consecutive denial, capped at
// kMaxBackoff). A denied caller stays denied until the backoff elapses. A caller
// that stays under the limit decays its backoff back to zero.
class RateLimiter
{
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    static constexpr std::size_t kMaxPerWindow = 5;
    static constexpr auto kWindow = std::chrono::seconds{60};
    static constexpr auto kBaseBackoff = std::chrono::seconds{2};
    static constexpr auto kMaxBackoff = std::chrono::seconds{60};
    // Sweep idle caller entries once the table exceeds this many tracked callers.
    // Unique D-Bus names are never reused, so without a bound the table would grow
    // forever across a long-lived daemon's lifetime; the sweep keeps it bounded
    // without per-call O(n) cost.
    static constexpr std::size_t kSweepThreshold = 1024;

    // Default ctor uses steady_clock::now. The clock overload is for tests.
    RateLimiter();
    explicit RateLimiter(Clock clock);

    // Records and judges one attempt by @p callerKey. Returns true when the
    // attempt is within policy (the attempt is counted), false when it must be
    // rejected (caller is over the window limit or inside a backoff). The
    // caller (the Card1.Sign path) maps false to Error.RateLimited.
    [[nodiscard]] bool allow(const CallerToken& callerKey);

private:
    struct CallerState
    {
        std::deque<std::chrono::steady_clock::time_point> recent; // attempts within the window
        int backoffLevel{0};
        std::chrono::steady_clock::time_point backoffUntil{}; // epoch == no active backoff
    };

    Clock m_clock;
    std::mutex m_mutex;
    std::map<CallerToken, CallerState> m_callers;
};

} // namespace LibreSCRS::Agent::Operations
