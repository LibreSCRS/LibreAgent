// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/PromptIdMinter.h>
#include <LibreSCRS/Agent/value/ReaderLabels.h>
#include <LibreSCRS/CancelToken.h>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

/// Which reader holds the card @p cardKey names, as the prompt chrome needs it.
/// Supplied by the platform backend: the card key is the backend's own
/// per-insertion identifier and only the backend holds both the reader roster
/// and that inverse. The DERIVATION stays neutral (readerIdentities); this seam
/// carries only the lookup.
///
/// @since 4.3
using ReaderIdentityForCard = std::function<LibreSCRS::Agent::ReaderIdentity(const std::string& cardKey)>;

// Gate that admits AT MOST ONE live prompter interaction PER CARD.
//
// The agent runs one worker thread per reader, so two readers can drive two
// credential prompts concurrently, and they are meant to: a dialog raised for
// one reader must never stall — or kill — a read on another. This gate was
// originally agent-wide, and that is exactly what went wrong in practice. The
// per-operation watchdog arms on entry to Authenticating, BEFORE a worker
// queues here, so an unanswered dialog on one reader did not merely delay the
// others: after the watchdog budget elapsed their operations died with
// WatchdogTimeout and their pages went with them. One card left waiting for a
// CAN cost the user every other card in the machine.
//
// So the slot is keyed by card. Two DIFFERENT cards prompt concurrently; two
// operations on the SAME card still serialize, which is the case that actually
// needs it — one card cannot meaningfully answer two dialogs at once, and a
// second dialog for the same card is always a bug or a race.
//
// Consent integrity across concurrent dialogs therefore rests on each dialog
// naming its reader and its artifact, since more than one can now be on screen.
// That labelling is load-bearing: it is what tells the holder which secret
// authorizes which artifact.
//
// This gate serializes ONLY the prompter round-trip; the per-reader card I/O
// stays parallel — workers contend here only when they actually need to raise
// a dialog (a cache hit never touches it).
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

    // Run @p doPrompt while holding the prompt slot for @p key, after waiting
    // (FIFO within that key) for any earlier prompt on the SAME key to finish.
    // A prompt under a different key is not waited for at all. The slot is held
    // ONLY across @p doPrompt — typically the one blocking prompter D-Bus call.
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
    auto serialize(const std::string& key, const LibreSCRS::CancelToken& token, Fn&& doPrompt, OnCancel&& onCancelled)
        -> decltype(doPrompt());

    // True iff ANY key's prompt slot is currently HELD (a worker is inside
    // doPrompt) or has a waiter queued behind it. The backend's shutdown drain loops its
    // cross-connection prompt cancel until this reads false (or a bounded cap), so
    // every prompting/queued worker JOINS rather than falling to the zombie path.
    [[nodiscard]] bool hasPendingPrompt() const noexcept;

    // The agent's ONE prompt-id minter. It belongs to this gate because the gate
    // is agent-lifetime (which is what makes the run nonce mean "this run"), is
    // already injected wherever a prompt can be raised, and its per-card slots
    // are what those ids address.
    [[nodiscard]] PromptIdMinter& idMinter() noexcept
    {
        return m_idMinter;
    }

    // Set ONCE by the backend during construction, before any operation can
    // run: the resolver is read from reader worker threads and never
    // re-assigned, so no synchronisation is needed on the pointer itself.
    void setReaderIdentityResolver(ReaderIdentityForCard fn)
    {
        m_readerIdentityFor = std::move(fn);
    }

    // Empty identity when no backend supplied a resolver, or when the card has
    // gone. A dialog that names no reader is honest; one that names the wrong
    // reader is the failure this design exists to remove.
    [[nodiscard]] LibreSCRS::Agent::ReaderIdentity readerIdentityFor(const std::string& cardKey) const
    {
        return m_readerIdentityFor ? m_readerIdentityFor(cardKey) : LibreSCRS::Agent::ReaderIdentity{};
    }

    // Keeps @p promptId listed as raised-and-unanswered for @p cardKey until the
    // returned guard dies. Move-only: the registration is a resource, and a copy
    // would leave a phantom id behind once one copy unwound.
    class LivePromptGuard
    {
    public:
        LivePromptGuard() = default;
        LivePromptGuard(PromptSerializer* owner, std::string promptId) : m_owner(owner), m_promptId(std::move(promptId))
        {}
        LivePromptGuard(LivePromptGuard&& other) noexcept
            : m_owner(std::exchange(other.m_owner, nullptr)), m_promptId(std::move(other.m_promptId))
        {}
        LivePromptGuard& operator=(LivePromptGuard&&) = delete;
        LivePromptGuard(const LivePromptGuard&) = delete;
        LivePromptGuard& operator=(const LivePromptGuard&) = delete;
        ~LivePromptGuard()
        {
            if (m_owner != nullptr) {
                m_owner->forgetLivePrompt(m_promptId);
            }
        }

    private:
        PromptSerializer* m_owner{nullptr};
        std::string m_promptId;
    };

    [[nodiscard]] LivePromptGuard registerLivePrompt(const std::string& cardKey, std::string promptId);

    // Ids raised for @p cardKey and not yet answered -- what an operation's
    // cancel hook addresses. At most one in practice (the gate admits one prompt
    // per card); a vector so a shutdown race cannot drop one on the floor.
    [[nodiscard]] std::vector<std::string> liveIdsFor(const std::string& cardKey) const;

    // Every outstanding id, for shutdown: the agent cancels what it actually
    // raised instead of reading a boolean and then dismissing blind.
    [[nodiscard]] std::vector<std::string> liveIds() const;

private:
    // Drop @p promptId from the live set. Called only by LivePromptGuard.
    void forgetLivePrompt(const std::string& promptId);

    // Acquire the single prompt slot, FIFO. Returns true once this caller
    // holds the slot; false if @p token was cancelled while queued (in which
    // case the caller's ticket has already been withdrawn and the slot is
    // NOT held). Takes the token BY VALUE: registerCallback mutates it, and a
    // copy shares cancellation state with the source. Defined in the .cpp —
    // the cancellation-aware wait has no template dependency, so it lives
    // out-of-line to keep the header thin.
    [[nodiscard]] bool acquire(const std::string& key, LibreSCRS::CancelToken token);

    // Release the slot held by the current caller for @p key and wake the next
    // waiter on that key.
    void release(const std::string& key);

    // One gate per key. FIFO admission queue of outstanding tickets, front =
    // next to be served. A waiter proceeds when it is at the front AND that
    // key's slot is free. An explicit queue (over a bare running counter) keeps
    // the sequence contiguous when a queued waiter cancels mid-wait — its node
    // is simply erased, leaving no unservable gap.
    struct Gate
    {
        std::deque<std::uint64_t> waiters;
        bool held{false};
    };

    mutable std::mutex m_mutex;
    // ONE condition variable for every key. Waiters re-check their own key's
    // predicate, so a wake meant for another key is a spurious wake they simply
    // ignore. Prompts are rare and few, so the cost is nil and it keeps the
    // cancellation callback (which cannot know its key's gate still exists)
    // trivially correct.
    std::condition_variable_any m_cv;
    std::uint64_t m_nextTicket{0};
    std::map<std::string, Gate> m_gates;
    PromptIdMinter m_idMinter;
    ReaderIdentityForCard m_readerIdentityFor;
    // promptId -> the card whose slot it was raised under. Keyed by id because
    // the dismissal arrives with an id and nothing else.
    std::map<std::string, std::string> m_livePrompts;
};

template <typename Fn, typename OnCancel>
auto PromptSerializer::serialize(const std::string& key, const LibreSCRS::CancelToken& token, Fn&& doPrompt,
                                 OnCancel&& onCancelled) -> decltype(doPrompt())
{
    if (!acquire(key, token)) {
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
        const std::string& key;
        ~SlotGuard()
        {
            self->release(key);
        }
    } guard{this, key};
    return doPrompt();
}

} // namespace LibreSCRS::Agent::Operations
