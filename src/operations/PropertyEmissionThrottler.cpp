// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/PropertyEmissionThrottler.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <utility>

namespace LibreSCRS::Agent::Operations {

PropertyEmissionThrottler::PropertyEmissionThrottler(EmitFn emit, std::chrono::milliseconds window)
    : m_emit(std::move(emit)), m_window(window), m_worker([this](std::stop_token st) { dispatchLoop(std::move(st)); })
{}

PropertyEmissionThrottler::~PropertyEmissionThrottler()
{
    m_worker.request_stop();
    {
        std::lock_guard lock(m_mutex);
        m_cv.notify_all();
    }
    // m_worker.join() implicit in jthread dtor.
}

void PropertyEmissionThrottler::schedule() noexcept
{
    try {
        {
            std::lock_guard lock(m_mutex);
            m_pending = true;
        }
        m_cv.notify_one();
    } catch (...) {
        // schedule() is noexcept; lost wake-up will be picked up by the
        // next caller or the periodic wake.
    }
}

void PropertyEmissionThrottler::flush() noexcept
{
    EmitFn snapshot;
    try {
        {
            std::lock_guard lock(m_mutex);
            m_pending = true;
            m_forceFlush = true;
            snapshot = m_emit; // snapshot under lock to keep the call thread-safe
            m_lastEmit = std::chrono::steady_clock::now();
            m_pending = false;
            m_forceFlush = false;
        }
        if (snapshot) {
            snapshot();
        }
    } catch (...) {
        // flush() is noexcept; on emit-callback throw we log nothing here —
        // the callback's own emit wrapper handles its logging.
    }
}

void PropertyEmissionThrottler::stop() noexcept
{
    m_worker.request_stop();
    {
        std::lock_guard lock(m_mutex);
        m_cv.notify_all();
    }
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

void PropertyEmissionThrottler::dispatchLoop(std::stop_token st)
{
    std::unique_lock lock(m_mutex);
    while (!st.stop_requested()) {
        m_cv.wait_for(lock, st, m_window, [&] { return m_pending || st.stop_requested(); });
        if (st.stop_requested()) {
            return;
        }
        if (!m_pending) {
            continue;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!m_forceFlush && (now - m_lastEmit) < m_window) {
            // Within the window: sleep until the boundary. Wake early only
            // for a stop request or a flush() that consumed the pending
            // request (visible as m_pending dropping to false); a plain
            // re-schedule keeps m_pending true and changes nothing about
            // when the next emit is due, so it does not end this wait.
            m_cv.wait_until(lock, st, m_lastEmit + m_window, [&] { return !m_pending || m_forceFlush; });
            // Re-evaluate from the top: stop requested, flush consumed the
            // request, or the boundary was reached and the emit is now due.
            continue;
        }
        EmitFn snapshot = m_emit;
        m_pending = false;
        m_forceFlush = false;
        m_lastEmit = now;
        lock.unlock();
        if (snapshot) {
            try {
                snapshot();
            } catch (const std::exception& e) {
                log::warnf("PropertyEmissionThrottler: emit-callback threw: {}", e.what());
            }
        }
        lock.lock();
    }
}

} // namespace LibreSCRS::Agent::Operations
