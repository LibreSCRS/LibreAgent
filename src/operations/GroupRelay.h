// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/Seams.h> // GroupSink
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <utility>

namespace LibreSCRS::Agent::Operations {

// The serial executor that emits the groups of ONE operation attached to another
// operation's read. Shared (shared_ptr) between the group feed that fills it and
// the attached operation that owns the sink.
//
// Three threads can touch it: the reader's thread (a group arrives), a bus thread
// (the client has read the state: release), and whichever thread ends the
// operation (cancel, card removed, a wedged reader). The emit calls into a host
// channel, which can be serialised against the very thread that wants to end the
// operation, so NOTHING here is called under the lock and the ending side never
// waits for an emit: closeThen() hands its action to the emitter when one is in
// progress. Only the worker thread, which is about to run the operation itself,
// may wait (closeAndWait).
//
// The sink is called only for groups taken while the relay is open. A group
// already being emitted when the close comes finishes; the deferred action runs
// after it, so the sink's owner stays alive until then.
//
// Thread-safety: every member is safe from any thread.
class GroupRelay
{
public:
    explicit GroupRelay(GroupSink& sink) noexcept;
    ~GroupRelay();

    GroupRelay(const GroupRelay&) = delete;
    GroupRelay& operator=(const GroupRelay&) = delete;

    // Queue a group (taken by value; zeroized if the relay is closed). Never emits.
    void enqueue(GroupSnapshot group);
    // Lift the park, then drain().
    void release();
    // Emit what is queued, one group at a time, unless parked, closed or another
    // thread is already emitting (that thread picks up what was queued).
    void drain();
    // Close, drop what is queued, and run @p action once: at once on the caller
    // when nothing is being emitted, otherwise on the emitting thread after its
    // current group. Never waits.
    void closeThen(std::function<void()> action);
    // Close, drop what is queued, and wait for an emit in progress to end. For the
    // worker thread only.
    void closeAndWait();
    [[nodiscard]] bool isClosed() const;
    // True once a group with this key has been handed to the sink.
    [[nodiscard]] bool delivered(const std::string& groupKey) const;

private:
    // Requires m_mutex held.
    void closeLocked();

    GroupSink& m_sink;
    mutable std::mutex m_mutex;
    std::condition_variable m_idle;
    std::deque<GroupSnapshot> m_pending;
    std::set<std::string> m_delivered;
    std::function<void()> m_deferred;
    bool m_parked{true};
    bool m_draining{false};
    bool m_closed{false};
};

// Header-only, like the other small internal helpers here: a relay needs no
// translation unit of its own.
inline GroupRelay::GroupRelay(GroupSink& sink) noexcept : m_sink(sink) {}

inline GroupRelay::~GroupRelay()
{
    std::lock_guard lock(m_mutex);
    for (auto& group : m_pending) {
        cleanseGroup(group);
    }
}

inline void GroupRelay::closeLocked()
{
    m_closed = true;
    for (auto& group : m_pending) {
        cleanseGroup(group);
    }
    m_pending.clear();
}

inline void GroupRelay::enqueue(GroupSnapshot group)
{
    std::lock_guard lock(m_mutex);
    if (m_closed) {
        cleanseGroup(group);
        return;
    }
    m_pending.push_back(std::move(group));
}

inline void GroupRelay::release()
{
    {
        std::lock_guard lock(m_mutex);
        m_parked = false;
    }
    drain();
}

inline void GroupRelay::drain()
{
    std::unique_lock lock(m_mutex);
    if (m_parked || m_draining || m_closed) {
        return;
    }
    m_draining = true;
    while (!m_pending.empty() && !m_closed) {
        GroupSnapshot group = std::move(m_pending.front());
        m_pending.pop_front();
        std::string key = group.groupKey;
        lock.unlock();
        m_sink.groupReady(group);
        cleanseGroup(group);
        lock.lock();
        m_delivered.insert(std::move(key));
    }
    m_draining = false;
    // The waiter first: it is released by this, never by the action, and the
    // action may be what makes the sink's owner go away.
    m_idle.notify_all();
    auto action = std::exchange(m_deferred, {});
    lock.unlock();
    if (action) {
        action();
    }
}

inline void GroupRelay::closeThen(std::function<void()> action)
{
    {
        std::lock_guard lock(m_mutex);
        closeLocked();
        if (m_draining) {
            if (m_deferred) {
                m_deferred = [first = std::move(m_deferred), second = std::move(action)] {
                    first();
                    second();
                };
            } else {
                m_deferred = std::move(action);
            }
            return;
        }
    }
    if (action) {
        action();
    }
}

inline void GroupRelay::closeAndWait()
{
    std::unique_lock lock(m_mutex);
    closeLocked();
    m_idle.wait(lock, [this] { return !m_draining; });
}

inline bool GroupRelay::isClosed() const
{
    std::lock_guard lock(m_mutex);
    return m_closed;
}

inline bool GroupRelay::delivered(const std::string& groupKey) const
{
    std::lock_guard lock(m_mutex);
    return m_delivered.contains(groupKey);
}

} // namespace LibreSCRS::Agent::Operations
