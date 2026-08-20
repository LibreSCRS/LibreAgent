// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <algorithm>
#include <mutex>

namespace LibreSCRS::Agent::Operations {

bool PromptSerializer::acquire(const std::string& key, LibreSCRS::CancelToken token)
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
    // Tickets are drawn from ONE counter across all keys: they only ever need
    // to be unique and ordered within their own gate, and a single counter
    // keeps that true without per-key bookkeeping.
    const std::uint64_t myTicket = m_nextTicket++;
    Gate& gate = m_gates[key];
    gate.waiters.push_back(myTicket);

    // Re-look-up the gate on every predicate evaluation rather than capturing
    // the reference: this waiter parks and wakes repeatedly, and another key's
    // release may erase ITS entry from the same map in between. Erasing a
    // different key never invalidates this one's node (std::map references are
    // stable), so holding `gate` across the wait would in fact be safe — but
    // the lookup is trivial and it keeps the invariant local rather than
    // depending on the container's reference-stability guarantee.
    const auto atHead = [&] {
        const auto it = m_gates.find(key);
        return it != m_gates.end() && !it->second.waiters.empty() && it->second.waiters.front() == myTicket;
    };
    const auto slotFree = [&] {
        const auto it = m_gates.find(key);
        return it == m_gates.end() || !it->second.held;
    };

    m_cv.wait(lock, [&] { return token.isCancelled() || (slotFree() && atHead()); });

    // Cancellation wins unconditionally: a cancelled op must NEVER raise a
    // dialog, even if the slot happened to be free when we woke. Surrender our
    // ticket (wherever it sits in the queue) and let the genuine next-in-line
    // proceed. The holder and other waiters are untouched.
    if (token.isCancelled()) {
        const auto git = m_gates.find(key);
        if (git != m_gates.end()) {
            auto& waiters = git->second.waiters;
            auto it = std::find(waiters.begin(), waiters.end(), myTicket);
            if (it != waiters.end()) {
                waiters.erase(it);
            }
            // Drop an idle gate so the map cannot grow once per card ever seen.
            if (waiters.empty() && !git->second.held) {
                m_gates.erase(git);
            }
        }
        m_cv.notify_all();
        return false;
    }

    // We hold this key's slot. Pop our (head) node and mark the slot taken.
    Gate& mine = m_gates[key];
    mine.waiters.pop_front();
    mine.held = true;
    return true;
}

void PromptSerializer::release(const std::string& key)
{
    std::lock_guard lock(m_mutex);
    const auto it = m_gates.find(key);
    if (it != m_gates.end()) {
        it->second.held = false;
        // Nobody queued for this card: forget it, so a long-lived agent does
        // not accumulate one gate per card it has ever seen.
        if (it->second.waiters.empty()) {
            m_gates.erase(it);
        }
    }
    m_cv.notify_all();
}

bool PromptSerializer::hasPendingPrompt() const noexcept
{
    std::lock_guard lock(m_mutex);
    // ANY key: the shutdown drain needs "is anyone prompting or queued", not
    // "is this card prompting".
    return std::any_of(m_gates.begin(), m_gates.end(),
                       [](const auto& kv) { return kv.second.held || !kv.second.waiters.empty(); });
}

PromptSerializer::LivePromptGuard PromptSerializer::registerLivePrompt(const std::string& cardKey, std::string promptId)
{
    // An empty id means nothing was minted, so there is nothing a dismissal
    // could name -- registering it would put an unaddressable entry in the set
    // the shutdown path iterates.
    if (promptId.empty()) {
        return {};
    }
    {
        std::lock_guard lock(m_mutex);
        m_livePrompts[promptId] = cardKey;
    }
    return LivePromptGuard{this, std::move(promptId)};
}

void PromptSerializer::forgetLivePrompt(const std::string& promptId)
{
    std::lock_guard lock(m_mutex);
    m_livePrompts.erase(promptId);
}

std::vector<std::string> PromptSerializer::liveIdsFor(const std::string& cardKey) const
{
    std::lock_guard lock(m_mutex);
    std::vector<std::string> out;
    for (const auto& [id, key] : m_livePrompts) {
        if (key == cardKey) {
            out.push_back(id);
        }
    }
    return out;
}

std::vector<std::string> PromptSerializer::liveIds() const
{
    std::lock_guard lock(m_mutex);
    std::vector<std::string> out;
    out.reserve(m_livePrompts.size());
    for (const auto& [id, key] : m_livePrompts) {
        out.push_back(id);
    }
    return out;
}

} // namespace LibreSCRS::Agent::Operations
