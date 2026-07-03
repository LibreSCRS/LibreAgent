// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <algorithm>
#include <utility>

namespace LibreSCRS::Agent::Operations {

RateLimiter::RateLimiter() : m_clock([] { return std::chrono::steady_clock::now(); }) {}

RateLimiter::RateLimiter(Clock clock) : m_clock(std::move(clock)) {}

bool RateLimiter::allow(const CallerToken& callerKey)
{
    const auto now = m_clock();
    std::lock_guard lock(m_mutex);

    // Bound the table: when it grows large, drop entries for callers that have
    // gone fully idle (no in-window attempts and no active backoff) — they carry
    // no state worth keeping. Only runs on the rare over-threshold call, so the
    // amortised cost stays low. The current caller is re-inserted below.
    if (m_callers.size() > kSweepThreshold) {
        for (auto it = m_callers.begin(); it != m_callers.end();) {
            const bool windowEmpty = it->second.recent.empty() || (now - it->second.recent.back()) > kWindow;
            const bool backoffElapsed = it->second.backoffUntil <= now;
            if (it->first != callerKey && windowEmpty && backoffElapsed) {
                it = m_callers.erase(it);
            } else {
                ++it;
            }
        }
    }

    auto& s = m_callers[callerKey];

    // Inside an active backoff: reject without counting (the caller must wait).
    if (s.backoffUntil > now) {
        return false;
    }
    // Drop attempts that have aged out of the sliding window.
    while (!s.recent.empty() && (now - s.recent.front()) > kWindow) {
        s.recent.pop_front();
    }
    if (s.recent.size() >= kMaxPerWindow) {
        // Over the window cap: start / extend the exponential backoff and reject.
        s.backoffLevel = std::min(s.backoffLevel + 1, 5);
        auto backoff = kBaseBackoff;
        for (int i = 1; i < s.backoffLevel; ++i) {
            backoff = std::min(backoff * 2, std::chrono::duration_cast<decltype(backoff)>(kMaxBackoff));
        }
        s.backoffUntil = now + backoff;
        return false;
    }
    // Within policy: count the attempt and decay any prior backoff.
    s.recent.push_back(now);
    s.backoffLevel = 0;
    s.backoffUntil = {};
    return true;
}

} // namespace LibreSCRS::Agent::Operations
