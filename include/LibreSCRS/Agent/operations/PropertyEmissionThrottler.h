// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace LibreSCRS::Agent::Operations {

// Coalesces a burst of schedule() requests into at most one emit per
// configured window (default 100 ms). flush() forces an immediate emit
// (used by the worker on phase transitions, even though OperationBase
// also emits inline -- the dual path covers throttler-owned worker
// callsites that do not go through OperationBase setPhase).
class PropertyEmissionThrottler
{
public:
    using EmitFn = std::function<void()>;

    PropertyEmissionThrottler(EmitFn emit, std::chrono::milliseconds window);
    ~PropertyEmissionThrottler();

    PropertyEmissionThrottler(const PropertyEmissionThrottler&) = delete;
    PropertyEmissionThrottler& operator=(const PropertyEmissionThrottler&) = delete;

    // Request a coalesced emit. If an emit has fired within the current
    // window, the request is held and merged with any others that arrive
    // before the window closes.
    void schedule() noexcept;

    // Force an immediate, synchronous emit. Blocks until the emit-callback
    // has returned. Used by worker code that needs the bus to reflect a
    // value immediately (e.g. on phase transition, when a client may be
    // racing to read the new Phase).
    void flush() noexcept;

    // Stop the dispatch thread but keep the object usable: post-stop
    // schedule() is a harmless no-op (no worker to wake) and flush() still
    // emits synchronously. Lets a finished operation reclaim its thread
    // before destruction. Idempotent; the destructor repeats it as a no-op.
    void stop() noexcept;

private:
    void dispatchLoop(std::stop_token st);

    EmitFn m_emit;
    std::chrono::milliseconds m_window;
    std::mutex m_mutex;
    std::condition_variable_any m_cv;
    bool m_pending{false};
    bool m_forceFlush{false};
    std::chrono::steady_clock::time_point m_lastEmit{};
    std::jthread m_worker; // last member: stops + joins first on destruction
};

} // namespace LibreSCRS::Agent::Operations
