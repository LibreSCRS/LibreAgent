// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Zombie-worker recovery: a non-cooperating doWork() (the canonical case
// being SCardTransmit, which is uncancellable on Linux/pcsclite) wedges
// the per-reader worker jthread. Because the jthread joins on
// destruction, a naive removeReader()/~OperationManager() would then
// wedge the BUS thread waiting on a worker that never returns.
//
// The recovery contract: on removeReader() of a reader whose in-flight
// op has NOT finished (isFinished() == false), the manager must ABANDON
// the wedged worker to a never-joined zombie list (detach the thread so
// the process tolerates the leaked thread until exit) and return
// promptly. The watchdog still trips cancel + finishes the op with
// WatchdogTimeout so the wire surface reports a terminal state. Neither
// removeReader() nor ~OperationManager() may ever block on a wedged
// worker.

#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>

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

// Captured finish observation. Lives in the test frame (NOT owned by the
// adaptor) so it survives the op's eventual destruction — which, for an
// abandoned op, happens on the zombie thread at an unspecified later time
// (or never, before process exit). Heap-allocated + shared so the test
// frame can outlive the op safely.
struct ObservationSlots
{
    std::atomic<std::uint32_t> status{99};
    std::atomic<std::uint32_t> errorCode{99};
    std::atomic<int> finishCount{0};
};

class CapturingChannel final : public OperationChannel
{
public:
    explicit CapturingChannel(std::shared_ptr<ObservationSlots> slots) : m_slots(std::move(slots)) {}
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view, std::string_view) noexcept override
    {
        m_slots->status.store(static_cast<std::uint32_t>(s), std::memory_order_release);
        m_slots->errorCode.store(static_cast<std::uint32_t>(e), std::memory_order_release);
        m_slots->finishCount.fetch_add(1, std::memory_order_acq_rel);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    std::shared_ptr<ObservationSlots> m_slots;
};

// A latch the test releases at teardown so the abandoned worker thread is
// not leaked for the whole process lifetime under the test harness. In
// production the latch is the uncancellable SCardTransmit; here the test
// owns it so it can let the zombie thread exit cleanly after the
// assertions, keeping the test sanitizer-clean.
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

// Non-cooperating op: doWork() enters Reading (so the watchdog arms) then
// blocks on the latch, deliberately IGNORING the cancel token. This
// models an uncancellable SCardTransmit. The op only returns once the
// test releases the latch at teardown.
class WedgedOp final : public OperationBase
{
public:
    WedgedOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s, Latch& latch,
             std::atomic<bool>& entered)
        : OperationBase(std::move(a), std::move(s)), m_latch(latch), m_entered(entered)
    {}

protected:
    void doWork() override
    {
        // Arm the watchdog by entering Reading, then block forever on the
        // latch without ever polling the cancel token.
        setPhase(static_cast<std::uint32_t>(OperationPhase::Reading));
        m_entered.store(true, std::memory_order_release);
        m_latch.waitForRelease();
        // Reached only after teardown releases the latch. finish() here is
        // a no-op because the watchdog already finished the op (once_flag).
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
    }

private:
    Latch& m_latch;
    std::atomic<bool>& m_entered;
};

const ObjectId kReaderId{42};

} // namespace

// removeReader() of a reader whose in-flight op is wedged in a
// non-cooperating doWork() must return promptly (NOT join the wedged
// worker). The op still terminates with WatchdogTimeout via the per-op
// watchdog. The wedged worker is abandoned to the zombie list.
TEST(ZombieWorkerDrain, RemoveReaderDoesNotBlockOnWedgedWorker)
{
    Latch latch;
    auto slots = std::make_shared<ObservationSlots>();
    std::atomic<bool> entered{false};

    {
        OperationManager mgr; // bus-less unit-test mode

        auto state = std::make_shared<OperationState>();
        state->watchdogTimeoutSec.store(1u); // bounded test watchdog

        mgr.enqueueForTest(
            kReaderId, std::make_unique<WedgedOp>(std::make_unique<CapturingChannel>(slots), state, latch, entered));

        // Wait until the worker is actually wedged inside doWork().
        const auto enterDeadline = std::chrono::steady_clock::now() + 2s;
        while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < enterDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "worker never entered doWork()";

        // removeReader() must return promptly — it must NOT join the wedged
        // worker. Time the call; with the abandon path it returns in
        // milliseconds, without it the test would hang here forever.
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReaderId);
        const auto elapsed = std::chrono::steady_clock::now() - t0;
        EXPECT_LT(elapsed, 500ms) << "removeReader blocked on the wedged worker (saw "
                                  << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms)";

        // The op must reach a terminal state via the watchdog even though
        // doWork() never cooperated. The watchdog (1 s) fires and finishes
        // with WatchdogTimeout.
        const auto finishDeadline = std::chrono::steady_clock::now() + 3s;
        while (slots->finishCount.load(std::memory_order_acquire) == 0 &&
               std::chrono::steady_clock::now() < finishDeadline) {
            std::this_thread::sleep_for(20ms);
        }
        EXPECT_GE(slots->finishCount.load(std::memory_order_acquire), 1) << "wedged op never reached a terminal state";
        EXPECT_EQ(slots->errorCode.load(std::memory_order_acquire),
                  static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout))
            << "abandoned op must finish with WatchdogTimeout";

        // ~OperationManager() must also be non-blocking even with the
        // wedged op still parked on the latch. Time the manager destruction
        // (scope exit below) by releasing the latch only AFTER the dtor.
        const auto t1 = std::chrono::steady_clock::now();
        // (dtor runs at the closing brace.)
        (void)t1;
    }

    // If we got here, ~OperationManager() returned without joining the
    // zombie. Release the latch so the abandoned worker thread can exit
    // cleanly (keeps the test sanitizer-clean rather than leaking a thread
    // for the whole test-process lifetime).
    latch.release();
    // Give the freed zombie thread a moment to unwind before the test
    // frame (and the shared ObservationSlots / state) goes away. The op +
    // adaptor destruct on the zombie thread.
    std::this_thread::sleep_for(100ms);
}

// Post-watchdog window: the per-op watchdog runs on its own thread and
// finishes the op (isFinished() == true) while doWork() is STILL wedged in
// a non-cooperating, uncancellable call. removeReader() must remain
// non-blocking in this window too — the abandon decision must key on the
// worker still executing doWork() (inFlight not yet cleared), NOT on
// isFinished(). Keying on isFinished() here would skip both the grace and
// the abandon and fall through to a join that re-wedges on the still-stuck
// worker. This is the window the original drain test never covered.
TEST(ZombieWorkerDrain, RemoveReaderNonBlockingAfterWatchdogFinishWhileDoWorkWedged)
{
    Latch latch;
    auto slots = std::make_shared<ObservationSlots>();
    std::atomic<bool> entered{false};

    {
        OperationManager mgr; // bus-less unit-test mode

        auto state = std::make_shared<OperationState>();
        state->watchdogTimeoutSec.store(1u); // bounded test watchdog

        mgr.enqueueForTest(
            kReaderId, std::make_unique<WedgedOp>(std::make_unique<CapturingChannel>(slots), state, latch, entered));

        const auto enterDeadline = std::chrono::steady_clock::now() + 2s;
        while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < enterDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "worker never entered doWork()";

        // Wait until the watchdog has already FIRED — the op is finished on
        // the wire — while doWork() is still parked on the (unreleased)
        // latch. This is the post-watchdog window: isFinished() == true but
        // the worker thread has NOT cleared inFlight.
        const auto finishDeadline = std::chrono::steady_clock::now() + 3s;
        while (slots->finishCount.load(std::memory_order_acquire) == 0 &&
               std::chrono::steady_clock::now() < finishDeadline) {
            std::this_thread::sleep_for(10ms);
        }
        ASSERT_GE(slots->finishCount.load(std::memory_order_acquire), 1) << "watchdog never finished the wedged op";
        ASSERT_EQ(slots->errorCode.load(std::memory_order_acquire),
                  static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout))
            << "op must have finished via the watchdog, not cooperatively";
        // doWork() is still blocked on the latch (we never released it), so
        // the worker is unambiguously still inside doWork() with inFlight
        // set, even though isFinished() == true.

        // removeReader() must STILL return promptly. With the buggy
        // isFinished()-gated decision it would skip the abandon and join the
        // wedged worker, hanging here forever. With the inFlight-gated
        // decision it abandons and returns in milliseconds.
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReaderId);
        const auto elapsed = std::chrono::steady_clock::now() - t0;
        EXPECT_LT(elapsed, 1s) << "removeReader blocked on the post-watchdog wedged worker (saw "
                               << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms)";

        // ~OperationManager() (scope exit below) must also be non-blocking
        // with the op already finished via the watchdog but doWork() still
        // wedged.
    }

    // Reaching here means both removeReader() and ~OperationManager()
    // returned without joining the zombie. Release the latch so the
    // abandoned worker can unwind cleanly.
    latch.release();
    std::this_thread::sleep_for(100ms);
}

// ~OperationManager() with a still-wedged in-flight op (never removed
// first) must also be non-blocking: it abandons the worker rather than
// joining it.
TEST(ZombieWorkerDrain, DestructorDoesNotBlockOnWedgedWorker)
{
    Latch latch;
    auto slots = std::make_shared<ObservationSlots>();
    std::atomic<bool> entered{false};

    std::chrono::steady_clock::duration dtorElapsed{};
    {
        auto mgr = std::make_unique<OperationManager>(); // bus-less

        auto state = std::make_shared<OperationState>();
        state->watchdogTimeoutSec.store(1u);

        mgr->enqueueForTest(
            kReaderId, std::make_unique<WedgedOp>(std::make_unique<CapturingChannel>(slots), state, latch, entered));

        const auto enterDeadline = std::chrono::steady_clock::now() + 2s;
        while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < enterDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "worker never entered doWork()";

        const auto t0 = std::chrono::steady_clock::now();
        mgr.reset(); // runs ~OperationManager()
        dtorElapsed = std::chrono::steady_clock::now() - t0;
    }

    EXPECT_LT(dtorElapsed, 500ms) << "~OperationManager blocked on the wedged worker (saw "
                                  << std::chrono::duration_cast<std::chrono::milliseconds>(dtorElapsed).count()
                                  << " ms)";

    latch.release();
    std::this_thread::sleep_for(100ms);
}
