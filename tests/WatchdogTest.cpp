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
                // The watchdog's finish() has already run; the once_flag
                // gate makes this a no-op, so the WatchdogTimeout
                // errorCode survives.
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(10ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

} // namespace

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

TEST(Watchdog, HungTimestampAfterAuthenticatingIsBoundedAndTimestampingDoesNotReArm)
{
    // A hung TSA: the signer arms the watchdog at Authenticating, emits Signing,
    // then (declaratively) Timestamping, and blocks — modelling a timestamp round
    // -trip that never returns. The whole sign+timestamp runs after the
    // Authenticating arm, so the EXISTING one-shot watchdog bounds it; entering
    // Timestamping must NOT re-arm or extend the timer (D-g). The op finishes
    // WatchdogTimeout within the budget.
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
    // Non-re-arm proof: across AwaitingConsent -> Authenticating -> Signing ->
    // Timestamping, exactly ONE transition passed the arm-phase filter. This
    // exercises the real armWatchdogIfNeeded filter (no logic duplicated in the
    // test); it WOULD be 2 if Timestamping were added to the arm-set, so the
    // "does not re-arm" half is now genuinely proven (the CAS-gated single fire
    // alone could not distinguish that regression).
    EXPECT_EQ(op.watchdogArmAttempts(), 1u) << "only Authenticating armed; Timestamping must not re-arm";
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
