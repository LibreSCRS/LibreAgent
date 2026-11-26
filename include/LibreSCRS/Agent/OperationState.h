// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <utility>

namespace LibreSCRS::Agent::Operations {

// Shared atomic state bridging the bus thread (read by adaptor) and the
// worker thread (written by OperationBase). Constructed BEFORE the
// adaptor so the same shared_ptr can be handed to both at adaptor ctor
// time — no post-construction rebind, no window where Cancel could be
// silently dropped between adaptor publication and worker wire-up.
struct OperationState
{
    std::atomic<std::uint32_t> phase{0};
    std::atomic<std::uint32_t> watchdogTimeoutSec{60};
    std::atomic<bool> cancelled{false};
    // Terminal-property mirrors of the Finished signal. Populated by
    // OperationBase::finish() BEFORE the wire signal fires. A client that
    // learns the op path only from a method return — and therefore may
    // subscribe to Finished after a fast op already emitted it — reads
    // these within the cleanup grace window to recover the missed result.
    // completed gates the others: when false they are meaningless.
    std::atomic<bool> completed{false};
    std::atomic<std::uint32_t> terminalStatus{0};
    std::atomic<std::uint32_t> terminalErrorCode{0};

    // The client has read this operation's state (its path is known to it and its
    // signal subscription is in place). A host whose signals are lost when sent
    // before that point calls noteObserved() from the place that proves it; an
    // operation that wants to emit only after it installs the action with
    // onObserved(). One shot: the first noteObserved() runs the installed action;
    // an action installed once the state has been observed runs at once, on the
    // caller. At most one action is held (a later install replaces an earlier one
    // that has not run). The action always runs outside the internal lock, so it
    // may call back into this state.
    void noteObserved() noexcept
    {
        std::function<void()> action;
        {
            std::lock_guard lock(observedMutex);
            if (observed) {
                return;
            }
            observed = true;
            action = std::exchange(onObservedAction, {});
        }
        if (action) {
            action();
        }
    }
    void onObserved(std::function<void()> action)
    {
        {
            std::lock_guard lock(observedMutex);
            if (!observed) {
                onObservedAction = std::move(action);
                return;
            }
        }
        if (action) {
            action();
        }
    }

    // Guarded by observedMutex; public only so the struct stays an aggregate.
    std::mutex observedMutex;
    bool observed{false};
    std::function<void()> onObservedAction;
};

} // namespace LibreSCRS::Agent::Operations
