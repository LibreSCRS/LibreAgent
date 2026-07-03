// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/CancelToken.h>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>

namespace LibreSCRS::Agent::Operations {

// Process-wide gate that admits AT MOST ONE live prompter interaction at a
// time, agent-wide.
//
// The agent runs one worker thread per reader, so two readers can drive two
// credential prompts concurrently. The design mandates a single live prompt:
// the user must never face two stacked PIN/CAN dialogs, because that breaks
// consent integrity (which secret authorizes which artifact?). This gate
// serializes ONLY the prompter round-trip; the per-reader card I/O stays
// parallel — workers contend on this gate only when they actually need to
// raise a dialog (a cache hit never touches it).
//
// Fairness: tickets are served FIFO (first waiter in, first served), so a
// second worker that arrives while the first is prompting blocks until the
// first prompt resolves, then proceeds — no starvation, no LIFO surprise.
//
// Cancellation: the wait is interruptible. A worker queued behind a live
// prompt observes its own CancelToken; if the op is cancelled (client
// CancelCurrent, watchdog timeout, reader removal — all of which trip the
// op's CancelSource) the queued worker breaks out of the wait, surrenders its
// ticket, and runs the on-cancel path WITHOUT ever calling the prompter. The
// in-flight holder is unaffected (its own dialog is dismissed via the
// prompter's CancelCurrent on its own cancel path).
class PromptSerializer
{
public:
    PromptSerializer() = default;

    PromptSerializer(const PromptSerializer&) = delete;
    PromptSerializer& operator=(const PromptSerializer&) = delete;
    PromptSerializer(PromptSerializer&&) = delete;
    PromptSerializer& operator=(PromptSerializer&&) = delete;

    // Run @p doPrompt while holding the single agent-wide prompt slot, after
    // waiting (FIFO) for any earlier prompt to finish. The gate is held ONLY
    // across @p doPrompt — typically the one blocking prompter D-Bus call.
    //
    // Cancellation: if @p token is cancelled while this caller is still queued
    // (i.e. before it acquires the slot), the call returns @p onCancelled()
    // without running @p doPrompt. Once @p doPrompt has started it runs to
    // completion (the prompter's own CancelCurrent handles in-dialog cancel);
    // this method only governs the QUEUED wait.
    //
    // @tparam Fn      invocable returning the prompt result type R
    // @tparam OnCancel invocable returning the same R, used when the queued
    //                  wait is cut short by cancellation
    // @return the value @p doPrompt produced, or @p onCancelled() if the
    //         queued wait was cancelled before the slot was acquired.
    template <typename Fn, typename OnCancel>
    auto serialize(const LibreSCRS::CancelToken& token, Fn&& doPrompt, OnCancel&& onCancelled) -> decltype(doPrompt());

    // True iff a prompt slot is currently HELD (a worker is inside doPrompt) or a
    // waiter is queued behind the gate. The backend's shutdown drain loops its
    // cross-connection prompt cancel until this reads false (or a bounded cap), so
    // every prompting/queued worker JOINS rather than falling to the zombie path.
    [[nodiscard]] bool hasPendingPrompt() const noexcept;

private:
    // Acquire the single prompt slot, FIFO. Returns true once this caller
    // holds the slot; false if @p token was cancelled while queued (in which
    // case the caller's ticket has already been withdrawn and the slot is
    // NOT held). Takes the token BY VALUE: registerCallback mutates it, and a
    // copy shares cancellation state with the source. Defined in the .cpp —
    // the cancellation-aware wait has no template dependency, so it lives
    // out-of-line to keep the header thin.
    [[nodiscard]] bool acquire(LibreSCRS::CancelToken token);

    // Release the slot held by the current caller and wake the next waiter.
    void release();

    mutable std::mutex m_mutex;
    std::condition_variable_any m_cv;
    // FIFO admission queue of outstanding tickets, front = next to be served.
    // m_nextTicket hands out a fresh ticket on each entry. A waiter proceeds
    // when it is at the front AND the slot is free. An explicit queue (over a
    // bare running counter) keeps the sequence contiguous when a queued waiter
    // cancels mid-wait — its node is simply erased, leaving no unservable gap.
    std::uint64_t m_nextTicket{0};
    std::deque<std::uint64_t> m_waiters;
    bool m_held{false};
};

template <typename Fn, typename OnCancel>
auto PromptSerializer::serialize(const LibreSCRS::CancelToken& token, Fn&& doPrompt, OnCancel&& onCancelled)
    -> decltype(doPrompt())
{
    if (!acquire(token)) {
        // Cancelled while queued: never raise the dialog.
        return onCancelled();
    }
    // RAII release so an exception escaping doPrompt still frees the slot and
    // wakes the next waiter (doPrompt is the agent's own prompter call, which
    // does not throw in production, but the gate must not deadlock if it ever
    // does).
    struct SlotGuard
    {
        PromptSerializer* self;
        ~SlotGuard()
        {
            self->release();
        }
    } guard{this};
    return doPrompt();
}

} // namespace LibreSCRS::Agent::Operations
