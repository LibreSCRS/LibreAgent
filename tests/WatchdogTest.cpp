// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Watchdog producer: when a phase transition crosses into Authenticating
// (3) or Reading (4), OperationBase arms a per-op timer. On expiry the
// op finishes with ErrorCode::WatchdogTimeout AND trips the cancel flag
// so a cooperating doWork() exits in bounded time.

#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/CancelToken.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

struct CapturedFinish
{
    std::atomic<std::uint32_t> status{99};
    std::atomic<std::uint32_t> errorCode{99};
    std::atomic<int> count{0};
};

class CapturingChannel final : public OperationChannel
{
public:
    explicit CapturingChannel(CapturedFinish& slot) : m_slot(slot) {}
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view, std::string_view) noexcept override
    {
        m_slot.status.store(static_cast<std::uint32_t>(s), std::memory_order_release);
        m_slot.errorCode.store(static_cast<std::uint32_t>(e), std::memory_order_release);
        m_slot.count.fetch_add(1, std::memory_order_acq_rel);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    CapturedFinish& m_slot;
};

// Op that enters Reading, then waits on the cancel token for up to 5 s.
// The watchdog (1 s) fires first, calls finish + cancel; the cancel poll
// inside doWork observes the cancel and returns -- so the worker thread
// is released without leaking.
class SlowReadingOp final : public OperationBase
{
public:
    SlowReadingOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
        : OperationBase(std::move(a), std::move(s))
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
        for (int i = 0; i < 500; ++i) {
            if (isCancelled() || token().isCancelled()) {
                // Seeing cancel does NOT mean the watchdog's finish() has run:
                // cancel is tripped first and is what wakes this loop, so this
                // call can reach the once_flag first. The timeout survives
                // because the watchdog latches its verdict before cancelling,
                // not because of any ordering between the two finishes.
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(10ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

// Op that reacts to the cancel the watchdog trips as fast as it can and then
// finishes with its OWN Cancelled outcome, deliberately racing the watchdog to
// the once_flag and trying to win. Where SlowReadingOp polls every 10 ms and so
// usually loses that race, this one spins, so it usually wins it -- which is the
// interleaving that used to publish a watchdog timeout as a plain cancellation.
class RacingCancelOp final : public OperationBase
{
public:
    RacingCancelOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
        : OperationBase(std::move(a), std::move(s))
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (!isCancelled() && !token().isCancelled() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
    }
};

// --- The watchdog covers MACHINE time only ---------------------------------
//
// The watchdog exists because SCardTransmit is issued with no timeout at all:
// a wedged card would otherwise freeze a reader worker forever and the client
// would never receive a terminal result. That job is machine time. Human time
// belongs to the prompt's own deadline, and the three ops below pin the
// boundary between the two.

// Enters Authenticating (arming the 1 s watchdog), then AwaitingConsent, and
// stays there far longer than the budget -- the holder typing a CAN. It must
// reach its own Ok finish, not a WatchdogTimeout.
class ConsentWaitingOp final : public OperationBase
{
public:
    ConsentWaitingOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
        : OperationBase(std::move(a), std::move(s))
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
        setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        std::this_thread::sleep_for(2500ms); // the human types
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

// Burns most of the budget in Authenticating, spends a long time in
// AwaitingConsent, then enters Reading and wedges. Records when Reading was
// entered so the test can prove the re-arm granted a FULL budget rather than
// the ~200 ms remainder left before consent.
class ConsentThenWedgedReadOp final : public OperationBase
{
public:
    ConsentThenWedgedReadOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s,
                            std::atomic<std::int64_t>& readingEnteredMs)
        : OperationBase(std::move(a), std::move(s)), m_readingEnteredMs(readingEnteredMs)
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
        std::this_thread::sleep_for(800ms); // most of the 1 s budget
        setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        std::this_thread::sleep_for(2000ms); // the human types, unmeasured
        m_readingEnteredMs.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
                .count(),
            std::memory_order_release);
        setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
        for (int i = 0; i < 500; ++i) { // wedged card: wait to be killed
            if (isCancelled() || token().isCancelled()) {
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(10ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }

private:
    std::atomic<std::int64_t>& m_readingEnteredMs;
};

// Cycles consent five times under a budget long enough that nothing fires, so
// the arm COUNT is the only thing under test.
class ConsentCyclingOp final : public OperationBase
{
public:
    ConsentCyclingOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
        : OperationBase(std::move(a), std::move(s))
    {}

protected:
    void doWork() override
    {
        for (int i = 0; i < 5; ++i) {
            setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
            setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        }
        setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

} // namespace

// The regression this file exists to hold: a hung operation the watchdog killed
// must reach the caller as a TIMEOUT, not as an ordinary cancellation. Reported
// as Cancelled/None it is indistinguishable from the user cancelling, and the
// error code that exists to tell those apart is gone.
TEST(Watchdog, TimeoutOutranksACancelledFinishThatWinsTheRace)
{
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u, std::memory_order_release);

    RacingCancelOp op(std::make_unique<CapturingChannel>(slot), state);
    std::jthread runner([&op] { op.runOnWorker(); });

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (slot.count.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }

    EXPECT_EQ(slot.count.load(std::memory_order_acquire), 1) << "exactly one Finished emission expected";
    EXPECT_EQ(slot.status.load(std::memory_order_acquire), static_cast<std::uint32_t>(OperationStatus::Error))
        << "a watchdog timeout must not be downgraded to Cancelled by the doWork it woke";
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout))
        << "the timeout's error code must survive whichever finish() won the once_flag";
}

TEST(Watchdog, ReadingPhaseFiresTimeoutAndCancelsOp)
{
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u); // 1-second timeout

    SlowReadingOp op(std::make_unique<CapturingChannel>(slot), state);

    // Run on a separate thread because runOnWorker blocks until doWork
    // returns (which only happens after the watchdog trips cancel).
    std::jthread runner([&op] { op.runOnWorker(); });

    // Wait for the finish event. With a 1-second watchdog and a 10 ms
    // cancel-poll cadence, the finish should fire well within 2 s.
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (slot.count.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }

    EXPECT_EQ(slot.count.load(std::memory_order_acquire), 1)
        << "exactly one Finished emission expected (once_flag gate)";
    EXPECT_EQ(slot.status.load(std::memory_order_acquire), static_cast<std::uint32_t>(OperationStatus::Error))
        << "watchdog timeout reports Error";
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout));
    EXPECT_TRUE(op.isCancelled()) << "watchdog must trip cancel for cooperating doWork";
}

TEST(Watchdog, AuthenticatingPhaseAlsoArmsWatchdog)
{
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u);

    // Custom op variant that enters Authenticating and waits.
    class AuthOp final : public OperationBase
    {
    public:
        AuthOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
            : OperationBase(std::move(a), std::move(s))
        {}

    protected:
        void doWork() override
        {
            setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
            for (int i = 0; i < 500; ++i) {
                if (isCancelled() || token().isCancelled()) {
                    finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                    return;
                }
                std::this_thread::sleep_for(10ms);
            }
            finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
        }
    };

    AuthOp op(std::make_unique<CapturingChannel>(slot), state);
    std::jthread runner([&op] { op.runOnWorker(); });

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (slot.count.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout));
}

TEST(Watchdog, HungTimestampIsBoundedByTheArmFromItsOneMachinePhaseEntry)
{
    // A hung TSA: the signer arms the watchdog at Authenticating, emits Signing,
    // then (declaratively) Timestamping, and blocks — modelling a timestamp round
    // -trip that never returns. The whole sign+timestamp runs after the
    // Authenticating arm, so the budget that arm started bounds it; entering
    // Signing or Timestamping must NOT arm or extend the timer (D-g). The op
    // finishes WatchdogTimeout within that budget.
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u);

    class HungTsaOp final : public OperationBase
    {
    public:
        HungTsaOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
            : OperationBase(std::move(a), std::move(s))
        {}

    protected:
        void doWork() override
        {
            // Mirror the sign flow's post-consent phase sequence.
            setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
            setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating)); // arms the one-shot timer
            setPhase(static_cast<std::uint32_t>(OperationPhase::Signing));
            setPhase(static_cast<std::uint32_t>(OperationPhase::Timestamping)); // must NOT re-arm
            // Block as a hung TSA round-trip would, cooperating with the cancel
            // the watchdog trips.
            for (int i = 0; i < 500; ++i) {
                if (isCancelled() || token().isCancelled()) {
                    finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                    return;
                }
                std::this_thread::sleep_for(10ms);
            }
            finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
        }
    };

    HungTsaOp op(std::make_unique<CapturingChannel>(slot), state);
    std::jthread runner([&op] { op.runOnWorker(); });

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (slot.count.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_EQ(slot.count.load(std::memory_order_acquire), 1);
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout))
        << "a hung TSA after Authenticating must be bounded by the existing watchdog";
    EXPECT_TRUE(op.isCancelled());
    // Arm-count proof, under the contract "one arm per MACHINE-PHASE ENTRY"
    // (which replaced "exactly once per operation" when entry into
    // AwaitingConsent became a disarm): this op enters the arm-set exactly once,
    // at Authenticating, so across AwaitingConsent -> Authenticating -> Signing
    // -> Timestamping exactly ONE transition passed the arm-phase filter. This
    // exercises the real armWatchdogIfNeeded filter (no logic duplicated in the
    // test); it WOULD be 2 if Signing or Timestamping were added to the arm-set,
    // so the "these phases do not arm" half stays genuinely proven (the
    // CAS-gated single fire alone could not distinguish that regression). Ops
    // that return to a machine phase after each prompt arm once per return —
    // see EachConsentCycleArmsOnceAndTimersNeverStack.
    EXPECT_EQ(op.watchdogArmAttempts(), 1u)
        << "one machine-phase entry (Authenticating); Signing/Timestamping must not arm";
}

TEST(Watchdog, EarlyFinishCancelsWatchdog)
{
    // If doWork finishes before the watchdog expires, the watchdog must
    // not fire — finish() takes a snapshot via the once_flag, and the
    // watchdog cv-notify path observes m_finished and exits without
    // calling finishWatchdogTimeout.
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(5u); // 5-second timeout (well past the doWork sleep)

    class QuickOp final : public OperationBase
    {
    public:
        QuickOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
            : OperationBase(std::move(a), std::move(s))
        {}

    protected:
        void doWork() override
        {
            setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
            std::this_thread::sleep_for(100ms);
            finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
        }
    };

    QuickOp op(std::make_unique<CapturingChannel>(slot), state);
    op.runOnWorker();

    EXPECT_EQ(slot.count.load(std::memory_order_acquire), 1);
    EXPECT_EQ(slot.status.load(std::memory_order_acquire), static_cast<std::uint32_t>(OperationStatus::Ok))
        << "quick op must finish Ok, not WatchdogTimeout";
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::None));
}

TEST(Watchdog, WatchdogFinishUnderCancelledShutdownElidesTheWireEmitButSetsTerminalMirrors)
{
    // An abandoned typed op whose per-op watchdog is still armed fires
    // finishWatchdogTimeout() -> finish() AFTER the backend began teardown (its
    // shutdown token cancelled). finish() must ELIDE the wire emit (the reply
    // channel's adaptor is racing the connection destruction) yet still populate the
    // terminal-property mirrors so a same-process observer stays coherent. This
    // mutation-covers the `!shutdownRequested()` gate on the watchdog->finish emit:
    // drop it and the elided emitFinished would fire (count == 1).
    struct Latch
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool released{false};
        void release()
        {
            {
                std::lock_guard lock(mutex);
                released = true;
            }
            cv.notify_all();
        }
        void waitForRelease()
        {
            std::unique_lock lock(mutex);
            cv.wait(lock, [this] { return released; });
        }
    };

    // Non-cooperating op: enters Reading (arms the watchdog) then blocks on a latch,
    // deliberately ignoring the cancel token — so the WATCHDOG is what finishes it,
    // not a cooperative cancel poll. Modelling a wedged, abandoned worker.
    class WedgedReadingOp final : public OperationBase
    {
    public:
        WedgedReadingOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s, Latch& latch,
                        std::atomic<bool>& entered)
            : OperationBase(std::move(a), std::move(s)), m_latch(latch), m_entered(entered)
        {}

    protected:
        void doWork() override
        {
            setPhase(static_cast<std::uint32_t>(OperationPhase::Reading)); // arms the one-shot watchdog
            m_entered.store(true, std::memory_order_release);
            m_latch.waitForRelease();
        }

    private:
        Latch& m_latch;
        std::atomic<bool>& m_entered;
    };

    Latch latch;
    std::atomic<bool> entered{false};
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u);

    WedgedReadingOp op(std::make_unique<CapturingChannel>(slot), state, latch, entered);
    LibreSCRS::CancelSource shutdown; // the agent-wide shutdown-cancel source
    op.bindShutdownToken(shutdown.token());

    std::jthread runner([&op] { op.runOnWorker(); });

    const auto enterDeadline = std::chrono::steady_clock::now() + 2s;
    while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < enterDeadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "op never entered the wedge";

    // Model quiesce: cancel the shutdown token so the watchdog's finish is elided.
    shutdown.requestCancel();

    // Wait for the watchdog (1 s) to fire and finish the op.
    const auto finishDeadline = std::chrono::steady_clock::now() + 3s;
    while (!op.isFinished() && std::chrono::steady_clock::now() < finishDeadline) {
        std::this_thread::sleep_for(20ms);
    }
    ASSERT_TRUE(op.isFinished()) << "the armed watchdog never finished the wedged op";

    // Wire emit ELIDED under the cancelled shutdown token...
    EXPECT_EQ(slot.count.load(std::memory_order_acquire), 0)
        << "finish() must elide the wire emit while the shutdown token is cancelled";
    // ...but the terminal-property mirrors are populated regardless, so a
    // same-process observer recovers the WatchdogTimeout terminal state.
    EXPECT_TRUE(op.completed()) << "the terminal mirrors must be set even when the emit is elided";
    EXPECT_EQ(op.terminalErrorCode(), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout));
    EXPECT_EQ(op.terminalStatus(), static_cast<std::uint32_t>(OperationStatus::Error));

    latch.release(); // let the wedged worker unwind cleanly
}

TEST(Watchdog, ZeroTimeoutDisablesWatchdog)
{
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(0u); // disabled

    class QuickOp final : public OperationBase
    {
    public:
        QuickOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
            : OperationBase(std::move(a), std::move(s))
        {}

    protected:
        void doWork() override
        {
            setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
            std::this_thread::sleep_for(100ms);
            finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
        }
    };

    QuickOp op(std::make_unique<CapturingChannel>(slot), state);
    op.runOnWorker();
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::None))
        << "watchdog must not fire when watchdogTimeoutSec is 0";
}

TEST(Watchdog, AwaitingConsentDisarmsTheTimerSoAHolderIsNeverMeasured)
{
    // Before the disarm existed this FAILED: Authenticating armed a one-shot
    // timer that kept running through consent, so a holder slower than the
    // budget lost the read -- with one reader and no concurrency involved at
    // all.
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u, std::memory_order_release);

    ConsentWaitingOp op(std::make_unique<CapturingChannel>(slot), state);
    std::jthread runner([&op] { op.runOnWorker(); });

    // The op sleeps 2.5 s in consent; wait well past that so a missing finish
    // is a real failure rather than an impatient deadline.
    const auto deadline = std::chrono::steady_clock::now() + 6s;
    while (slot.count.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }

    ASSERT_EQ(slot.count.load(std::memory_order_acquire), 1) << "the op never finished";
    EXPECT_EQ(slot.status.load(std::memory_order_acquire), static_cast<std::uint32_t>(OperationStatus::Ok));
    EXPECT_NE(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout))
        << "the watchdog fired while the operation was waiting on a human";
    EXPECT_FALSE(op.isCancelled()) << "a timed-out watchdog trips cancel; the holder must not be cancelled";
}

TEST(Watchdog, LeavingConsentReArmsWithAFullBudgetNotTheRemainder)
{
    CapturedFinish slot;
    std::atomic<std::int64_t> readingEnteredMs{0};
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(1u, std::memory_order_release);

    ConsentThenWedgedReadOp op(std::make_unique<CapturingChannel>(slot), state, readingEnteredMs);
    std::jthread runner([&op] { op.runOnWorker(); });

    // 800 ms + 2000 ms of op time before Reading is even entered, then a fresh
    // 1 s budget on top: poll at 10 ms so the observed finish instant is close
    // enough to the real one for the margin below to mean something.
    const auto deadline = std::chrono::steady_clock::now() + 8s;
    while (slot.count.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    const auto finishedAtMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();

    ASSERT_EQ(slot.count.load(std::memory_order_acquire), 1) << "the op never finished";
    // It must still fire -- a wedged card is exactly what it is for.
    EXPECT_EQ(slot.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout));
    // Guard against a vacuous pass: if the timer fired back in consent, Reading
    // was never reached, the recorded instant is still 0, and the elapsed check
    // below would compare against the steady_clock epoch and "pass".
    ASSERT_NE(readingEnteredMs.load(std::memory_order_acquire), 0)
        << "the watchdog fired before Reading was ever entered -- it was still timing the human";
    // And it must have measured from the RE-ARM, not carried the ~200 ms left
    // over from before consent. If the remainder were carried, the card's
    // allowance would depend on how long the holder took to type -- the failure
    // mode that made "just enlarge the watchdog" the wrong fix.
    EXPECT_GE(finishedAtMs - readingEnteredMs.load(std::memory_order_acquire), 900)
        << "the re-arm carried the remainder instead of a fresh budget";
}

TEST(Watchdog, EachConsentCycleArmsOnceAndTimersNeverStack)
{
    // Six arms: five Authenticating entries from the loop, one final Reading.
    // A larger count means a disarm returned without joining and timer threads
    // are stacking -- the hazard the original one-shot comment guarded against.
    CapturedFinish slot;
    auto state = std::make_shared<OperationState>();
    state->watchdogTimeoutSec.store(60u, std::memory_order_release);

    ConsentCyclingOp op(std::make_unique<CapturingChannel>(slot), state);
    op.runOnWorker(); // nothing blocks: the budget is far longer than the op

    EXPECT_EQ(slot.status.load(std::memory_order_acquire), static_cast<std::uint32_t>(OperationStatus::Ok));
    EXPECT_EQ(op.watchdogArmAttempts(), 6u);
}
