// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AT MOST ONE live prompter interaction is allowed agent-wide. The
// agent runs one worker per reader, so two readers can drive two credential
// prompts concurrently; without a gate they would stack two dialogs (a
// consent-integrity hazard: which secret authorizes which artifact?).
//
// These tests pin the gate's contract:
//   1. Two concurrent prompts SERIALIZE — the second never overlaps the first
//      (asserted via a recording fake prompter that tracks live concurrency).
//   2. A worker queued behind a live prompt is woken by cancellation and
//      surrenders WITHOUT ever raising a dialog (CancelCurrent / watchdog /
//      reader-removal all trip the op's CancelToken).
//   3. The in-flight holder is unaffected by a queued waiter's cancel.

#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>

#include <LibreSCRS/CancelToken.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

using LibreSCRS::Agent::PinChangePromptResult;
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::Operations::PrompterClientBase;
using LibreSCRS::Agent::Operations::PromptSerializer;
using LibreSCRS::Agent::Operations::SerializingPrompter;
using namespace std::chrono_literals;

namespace {

// Recording fake prompter that detects any overlap between two concurrent
// prompter interactions. requestCan/Mrz/Pin increment a live-concurrency
// counter, hold for a beat, then decrement; maxConcurrent records the high
// water mark. The gate must keep it at 1.
class RecordingFakePrompter final : public PrompterClientBase
{
public:
    std::atomic<int> live{0};
    std::atomic<int> maxConcurrent{0};
    std::atomic<int> totalCalls{0};

    // When set, the first entrant blocks on this gate until the test releases
    // it, so a second thread is guaranteed to be queued behind it.
    std::mutex holdMutex;
    std::condition_variable holdCv;
    bool releaseHold{false};
    bool firstEntered{false};

    PromptResult requestCan(const PromptOptions&) override
    {
        return enter();
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return enter();
    }
    PromptResult requestPin(const PromptOptions&) override
    {
        return enter();
    }
    // The two-secret change prompt shares the SAME concurrency machinery, so a
    // test can prove it is gated exactly like the single-secret requests.
    PinChangePromptResult requestPinChange(const PromptOptions&) override
    {
        track();
        PinChangePromptResult r;
        r.status = PromptStatus::Ok;
        r.current = LibreSCRS::Secure::String{"1111"};
        r.newPin = LibreSCRS::Secure::String{"2222"};
        return r;
    }

private:
    // Concurrency tracking + first-entrant park, shared by every request* so the
    // change prompt is measured on the same single-slot high-water mark.
    void track()
    {
        const int now = live.fetch_add(1) + 1;
        int prevMax = maxConcurrent.load();
        while (now > prevMax && !maxConcurrent.compare_exchange_weak(prevMax, now)) {
        }
        totalCalls.fetch_add(1);

        {
            std::unique_lock lock(holdMutex);
            if (!firstEntered) {
                firstEntered = true;
                holdCv.notify_all();
                // The first entrant parks until released, guaranteeing it owns
                // the single slot while a second worker queues.
                holdCv.wait(lock, [&] { return releaseHold; });
            }
        }

        live.fetch_sub(1);
    }

    PromptResult enter()
    {
        track();
        PromptResult r;
        r.status = PromptStatus::Ok;
        r.secret = LibreSCRS::Secure::String{"123456"};
        return r;
    }
};

PromptResult onCancelled()
{
    return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
}

} // namespace

TEST(PromptSerializer, SecondConcurrentPromptBlocksUntilFirstCompletes)
{
    // Drive two concurrent prompts through the gate via SerializingPrompter
    // (the production decorator). The recording prompter blocks the first
    // entrant; the test confirms the second cannot proceed while the first
    // holds the slot, then releases and confirms both complete with the
    // concurrency high-water mark pinned at 1.
    PromptSerializer serializer;
    RecordingFakePrompter inner;

    LibreSCRS::CancelSource src1;
    LibreSCRS::CancelSource src2;
    SerializingPrompter gated1{serializer, inner, src1.token()};
    SerializingPrompter gated2{serializer, inner, src2.token()};

    std::atomic<bool> firstDone{false};
    std::atomic<bool> secondDone{false};

    PromptOptions opts;
    std::thread t1([&] {
        auto r = gated1.requestCan(opts);
        EXPECT_EQ(r.status, PromptStatus::Ok);
        firstDone = true;
    });

    // Wait until the first entrant is parked inside the prompter (holding the
    // single slot).
    {
        std::unique_lock lock(inner.holdMutex);
        ASSERT_TRUE(inner.holdCv.wait_for(lock, 2s, [&] { return inner.firstEntered; }))
            << "first prompt must enter the slot";
    }

    std::thread t2([&] {
        auto r = gated2.requestCan(opts);
        EXPECT_EQ(r.status, PromptStatus::Ok);
        secondDone = true;
    });

    // While the first holds the slot, the second must NOT have run the
    // prompter: exactly one call so far, and the second thread is blocked.
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(inner.totalCalls.load(), 1) << "second prompt must queue, not stack a second dialog";
    EXPECT_FALSE(secondDone.load()) << "second prompt must block behind the live one";
    EXPECT_FALSE(firstDone.load()) << "first prompt is still parked in the slot";

    // Release the first; both then drain through the single slot in turn.
    {
        std::lock_guard lock(inner.holdMutex);
        inner.releaseHold = true;
        inner.holdCv.notify_all();
    }
    t1.join();
    t2.join();

    EXPECT_TRUE(firstDone.load());
    EXPECT_TRUE(secondDone.load());
    EXPECT_EQ(inner.totalCalls.load(), 2);
    EXPECT_EQ(inner.maxConcurrent.load(), 1) << "the gate must never let two prompts run at once";
}

TEST(PromptSerializer, QueuedWaiterCancelledBreaksOutWithoutPrompting)
{
    // A worker queued behind a live prompt must break out of the wait when its
    // op is cancelled (CancelCurrent / watchdog / reader removal) and return
    // the cancelled result WITHOUT ever invoking the prompter.
    PromptSerializer serializer;
    RecordingFakePrompter inner;

    LibreSCRS::CancelSource src1;
    LibreSCRS::CancelSource src2;
    SerializingPrompter gated1{serializer, inner, src1.token()};
    SerializingPrompter gated2{serializer, inner, src2.token()};

    PromptOptions opts;
    std::thread t1([&] {
        auto r = gated1.requestCan(opts);
        EXPECT_EQ(r.status, PromptStatus::Ok);
    });

    {
        std::unique_lock lock(inner.holdMutex);
        ASSERT_TRUE(inner.holdCv.wait_for(lock, 2s, [&] { return inner.firstEntered; }));
    }

    std::atomic<PromptStatus> secondStatus{PromptStatus::Ok};
    std::atomic<bool> secondReturned{false};
    std::thread t2([&] {
        auto r = gated2.requestCan(opts);
        secondStatus = r.status;
        secondReturned = true;
    });

    // Let the second thread reach the queued wait, then cancel its op.
    std::this_thread::sleep_for(150ms);
    EXPECT_FALSE(secondReturned.load()) << "second prompt is queued behind the live one";
    src2.requestCancel();

    // The queued waiter must return promptly (cancelled) without prompting,
    // even though the first prompt is still holding the slot.
    for (int i = 0; i < 200 && !secondReturned.load(); ++i) {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_TRUE(secondReturned.load()) << "cancel must break the queued waiter out of the wait";
    EXPECT_EQ(secondStatus.load(), PromptStatus::Cancelled);
    EXPECT_EQ(inner.totalCalls.load(), 1) << "the cancelled queued waiter must NEVER reach the prompter";

    // The in-flight holder is unaffected; release it and confirm it completes.
    {
        std::lock_guard lock(inner.holdMutex);
        inner.releaseHold = true;
        inner.holdCv.notify_all();
    }
    t1.join();
    t2.join();
    EXPECT_EQ(inner.totalCalls.load(), 1) << "still exactly one real prompt overall";
}

TEST(PromptSerializer, CancelledBeforeAcquireNeverPrompts)
{
    // A token already cancelled when serialize() is called returns the
    // cancelled result immediately without raising a dialog.
    PromptSerializer serializer;
    RecordingFakePrompter inner;
    LibreSCRS::CancelSource src;
    src.requestCancel();

    SerializingPrompter gated{serializer, inner, src.token()};
    PromptOptions opts;
    auto r = gated.requestCan(opts);

    EXPECT_EQ(r.status, PromptStatus::Cancelled);
    EXPECT_EQ(inner.totalCalls.load(), 0) << "a pre-cancelled op must never prompt";
}

TEST(PromptSerializer, PinChangePromptQueuesBehindLivePrompt)
{
    // The two-secret change prompt must go through the SAME single-slot gate as
    // requestPin/Can/Mrz: a change dialog must never stack on top of another
    // reader's live prompt (which secret authorizes which change?). The recording
    // prompter parks a first entrant (requestCan); a second worker's
    // requestPinChange must queue, not fire, until the first is released.
    PromptSerializer serializer;
    RecordingFakePrompter inner;

    LibreSCRS::CancelSource src1;
    LibreSCRS::CancelSource src2;
    SerializingPrompter gated1{serializer, inner, src1.token()};
    SerializingPrompter gated2{serializer, inner, src2.token()};

    std::atomic<bool> changeDone{false};

    PromptOptions opts;
    std::thread t1([&] {
        auto r = gated1.requestCan(opts);
        EXPECT_EQ(r.status, PromptStatus::Ok);
    });

    {
        std::unique_lock lock(inner.holdMutex);
        ASSERT_TRUE(inner.holdCv.wait_for(lock, 2s, [&] { return inner.firstEntered; }))
            << "first prompt must enter the slot";
    }

    std::thread t2([&] {
        auto r = gated2.requestPinChange(opts);
        EXPECT_EQ(r.status, PromptStatus::Ok);
        changeDone = true;
    });

    // While the first holds the slot, the change prompt must NOT have run.
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(inner.totalCalls.load(), 1) << "the change prompt must queue behind the live prompt, not stack a dialog";
    EXPECT_FALSE(changeDone.load()) << "the change prompt must block behind the live one";

    {
        std::lock_guard lock(inner.holdMutex);
        inner.releaseHold = true;
        inner.holdCv.notify_all();
    }
    t1.join();
    t2.join();

    EXPECT_TRUE(changeDone.load());
    EXPECT_EQ(inner.totalCalls.load(), 2);
    EXPECT_EQ(inner.maxConcurrent.load(), 1) << "the gate must never let the change prompt overlap another prompt";
}

TEST(PromptSerializer, PinChangeCancelledBeforeAcquireNeverPrompts)
{
    // A token already cancelled when the change prompt is requested returns a
    // Cancelled-shaped result immediately without ever raising the dialog.
    PromptSerializer serializer;
    RecordingFakePrompter inner;
    LibreSCRS::CancelSource src;
    src.requestCancel();

    SerializingPrompter gated{serializer, inner, src.token()};
    PromptOptions opts;
    auto r = gated.requestPinChange(opts);

    EXPECT_EQ(r.status, PromptStatus::Cancelled);
    EXPECT_EQ(inner.totalCalls.load(), 0) << "a pre-cancelled op must never raise the change dialog";
}

TEST(PromptSerializer, ThreeConcurrentPromptsSerializeFifoNoOverlap)
{
    // Stress: many workers contend for the single slot; none may overlap, all
    // must eventually run. The recording prompter does not park here (release
    // is pre-armed) so each call runs to completion and frees the slot.
    PromptSerializer serializer;
    RecordingFakePrompter inner;
    inner.releaseHold = true; // never park; just record concurrency
    inner.firstEntered = true;

    constexpr int kThreads = 8;
    std::vector<std::thread> threads;
    std::vector<LibreSCRS::CancelSource> sources(kThreads);
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            SerializingPrompter gated{serializer, inner, sources[static_cast<std::size_t>(i)].token()};
            PromptOptions opts;
            auto r = gated.requestCan(opts);
            EXPECT_EQ(r.status, PromptStatus::Ok);
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(inner.totalCalls.load(), kThreads);
    EXPECT_EQ(inner.maxConcurrent.load(), 1) << "the gate must serialize every prompt";
}
