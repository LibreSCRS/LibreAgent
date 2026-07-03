// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <algorithm>
#include <mutex>

namespace LibreSCRS::Agent::Operations {

bool PromptSerializer::acquire(LibreSCRS::CancelToken token)
{
    // Wake this waiter when the op is cancelled while it is queued. The
    // callback locks m_mutex and notify_all()s so the wait below re-evaluates
    // its predicate and observes token.isCancelled() — locking inside the
    // callback is what makes the wake lost-wakeup-safe.
    //
    // CRITICAL: register BEFORE taking m_mutex. For an already-cancelled
    // token, registerCallback fires the callback SYNCHRONOUSLY on this thread
    // (std::stop_callback semantics); if we held m_mutex here the callback's
    // lock_guard would self-deadlock on the non-recursive mutex. Registering
    // first means the synchronous fire finds m_mutex free; the wait predicate
    // still catches the already-cancelled case before parking.
    //
    // registerCallback mutates the token, so we hold our own copy by value
    // (copies share cancellation state per the LM CancelToken contract). The
    // Registration is destroyed at scope exit, which blocks until any in-flight
    // callback returns — safe because the callback never re-enters acquire().
    //
    // notify_all (not notify_one): a notify_one might wake a waiter other than
    // the cancelled one, so wake everyone and let the predicates decide.
    auto registration = token.registerCallback([this] {
        std::lock_guard guard(m_mutex);
        m_cv.notify_all();
    });

    std::unique_lock lock(m_mutex);

    // FIFO admission: append our ticket and wait until we are at the head of
    // the queue AND the slot is free. An explicit waiter queue (rather than a
    // running counter) keeps the sequence contiguous when a queued waiter
    // cancels mid-wait: removing our node from the middle leaves no gap that
    // could wedge the holder or the genuine next-in-line.
    const std::uint64_t myTicket = m_nextTicket++;
    m_waiters.push_back(myTicket);

    const auto atHead = [&] { return !m_waiters.empty() && m_waiters.front() == myTicket; };

    m_cv.wait(lock, [&] { return token.isCancelled() || (!m_held && atHead()); });

    // Cancellation wins unconditionally: a cancelled op must NEVER raise a
    // dialog, even if the slot happened to be free when we woke. Surrender our
    // ticket (wherever it sits in the queue) and let the genuine next-in-line
    // proceed. The holder and other waiters are untouched.
    if (token.isCancelled()) {
        auto it = std::find(m_waiters.begin(), m_waiters.end(), myTicket);
        if (it != m_waiters.end()) {
            m_waiters.erase(it);
        }
        m_cv.notify_all();
        return false;
    }

    // We hold the slot. Pop our (head) node and mark the slot taken.
    m_waiters.pop_front();
    m_held = true;
    return true;
}

void PromptSerializer::release()
{
    std::lock_guard lock(m_mutex);
    m_held = false;
    m_cv.notify_all();
}

bool PromptSerializer::hasPendingPrompt() const noexcept
{
    std::lock_guard lock(m_mutex);
    return m_held || !m_waiters.empty();
}

} // namespace LibreSCRS::Agent::Operations
