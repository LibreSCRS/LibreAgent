// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "operations/GroupRelay.h"
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// The groups a background identity read has produced so far, and the relays of
// the operations that follow it. Owned by the background operation (shared_ptr),
// filled from the reader's thread, joined by the manager under the worker lock.
//
// Recording a group and queueing it to every relay is one step under the feed's
// lock, and so is attach() (replay of what is recorded, then enrolment): a
// follower that attaches between two records gets the earlier ones from the
// replay and the later ones live, none twice and none missed. Emitting is never
// done here under the lock -- record() drains the relays it queued to after
// releasing it, from a snapshot of the list.
//
// Lock order: the feed's, then a relay's. A relay never calls into the feed.
//
// Thread-safety: every member is safe from any thread.
class IdentityGroupFeed
{
public:
    explicit IdentityGroupFeed(std::string cardKey) : m_cardKey(std::move(cardKey)) {}
    ~IdentityGroupFeed()
    {
        close();
    }

    IdentityGroupFeed(const IdentityGroupFeed&) = delete;
    IdentityGroupFeed& operator=(const IdentityGroupFeed&) = delete;

    [[nodiscard]] const std::string& cardKey() const noexcept
    {
        return m_cardKey;
    }

    // The read starts: from here followers may attach. Not called on the
    // "already cached" path, which reads nothing.
    void beginRead()
    {
        std::lock_guard lock(m_mutex);
        m_open = true;
    }

    // A group the read produced: record it, queue it to every relay, and drain
    // those relays outside the lock. Ignored when the read is not open.
    void record(const GroupSnapshot& group)
    {
        std::vector<std::shared_ptr<GroupRelay>> targets;
        {
            std::lock_guard lock(m_mutex);
            if (!m_open) {
                return;
            }
            m_recorded.push_back(group);
            std::erase_if(m_relays, [](const std::shared_ptr<GroupRelay>& relay) { return relay->isClosed(); });
            targets.reserve(m_relays.size());
            for (const auto& relay : m_relays) {
                relay->enqueue(group);
                targets.push_back(relay);
            }
        }
        for (const auto& relay : targets) {
            relay->drain();
        }
    }

    // Enrol @p relay: false when the read is not open (not begun, or ended).
    // Queues everything recorded so far; emits nothing.
    [[nodiscard]] bool attach(std::shared_ptr<GroupRelay> relay)
    {
        std::lock_guard lock(m_mutex);
        if (!m_open) {
            return false;
        }
        for (const auto& group : m_recorded) {
            relay->enqueue(group);
        }
        m_relays.push_back(std::move(relay));
        return true;
    }

    // The read ended, however it ended: stop recording, forget the followers
    // (they keep what they were already queued) and zeroize the record.
    void close() noexcept
    {
        std::lock_guard lock(m_mutex);
        m_open = false;
        m_relays.clear();
        cleanseGroups(m_recorded);
        m_recorded.clear();
    }

private:
    const std::string m_cardKey;
    std::mutex m_mutex;
    bool m_open{false};
    std::vector<GroupSnapshot> m_recorded;
    std::vector<std::shared_ptr<GroupRelay>> m_relays;
};

} // namespace LibreSCRS::Agent::Operations
