// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Worker-scheduling test for OperationManager. Uses Fake operations
// (CountingOp) so the test focuses on per-reader serialisation +
// cross-reader parallelism + cleanup-grace timing.

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/presence/CardResolutionPolicy.h>

#include "fakes/FakeOperationChannel.h"
#include "fakes/PinStubPlugin.h" // BasePinPlugin

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

class CountingChannel final : public OperationChannel
{
public:
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus, ErrorCode, std::string_view, std::string_view) noexcept override
    {
        finished.store(true);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }
    std::atomic<bool> finished{false};
};

class CountingOp final : public OperationBase
{
public:
    CountingOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s, std::atomic<int>& counter,
               std::chrono::milliseconds work)
        : OperationBase(std::move(a), std::move(s)), m_counter(counter), m_work(work)
    {}

protected:
    void doWork() override
    {
        std::this_thread::sleep_for(m_work);
        m_counter.fetch_add(1);
        finish(OperationStatus::Ok, ErrorCode::None, "ok", "ok");
    }

private:
    std::atomic<int>& m_counter;
    std::chrono::milliseconds m_work;
};

auto makeCountingOp(std::atomic<int>& counter, std::chrono::milliseconds work)
{
    return std::make_unique<CountingOp>(std::make_unique<CountingChannel>(), std::make_shared<OperationState>(),
                                        counter, work);
}

// An op that parks in doWork until released, but cooperates with cancel so the
// worker can JOIN it promptly. Used to hold the worker busy so a second op stays
// queued while the test tears the reader down.
class GatedOp final : public OperationBase
{
public:
    GatedOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s, std::atomic<bool>& running)
        : OperationBase(std::move(a), std::move(s)), m_running(running)
    {}

protected:
    void doWork() override
    {
        m_running.store(true);
        // Cooperate with cancel (the drain path fires requestCancel) so the
        // worker exits its doWork promptly and is joined — never abandoned.
        for (int i = 0; i < 500; ++i) {
            if (isCancelled() || token().isCancelled()) {
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(2ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }

private:
    std::atomic<bool>& m_running;
};

// A queued op that records, at the moment its destructor runs (the FREE point),
// whether its tracking-table entry is still present. The destructive teardown
// must scrub the tables BEFORE freeing the op, so at destruction the path must
// already be ABSENT. A buggy destroy-then-scrub ordering would observe it still
// present. This proves scrub-before-free ORDER, not merely eventual scrub.
class FreeProbeOp final : public OperationBase
{
public:
    FreeProbeOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s, std::function<void()> onDestroy)
        : OperationBase(std::move(a), std::move(s)), m_onDestroy(std::move(onDestroy))
    {}

    ~FreeProbeOp() override
    {
        if (m_onDestroy) {
            m_onDestroy();
        }
    }

protected:
    void doWork() override
    {
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }

private:
    std::function<void()> m_onDestroy;
};

// Models the synchronous-probe op (Pkcs11_1.{CertDer,SignRaw,Decrypt}): it
// wedges in an UNCANCELLABLE doWork (ignores the cancel token, like a stuck
// SCardTransmit) and a separate "bus" thread parks on its completion latch.
// onAbandoned() must release that latch the moment abandonOrJoin detaches the
// wedged worker — otherwise the bus thread hangs until doWork returns (never).
struct WaiterLatch
{
    std::mutex mutex;
    std::condition_variable cv;
    bool done{false};
    void wait()
    {
        std::unique_lock lk(mutex);
        cv.wait(lk, [this] { return done; });
    }
    [[nodiscard]] bool isDone()
    {
        std::lock_guard lk(mutex);
        return done;
    }
    void signal() noexcept
    {
        {
            std::lock_guard lk(mutex);
            if (done) {
                return;
            }
            done = true;
        }
        cv.notify_all();
    }
};

class WedgedProbeOp final : public OperationBase
{
public:
    WedgedProbeOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s,
                  std::shared_ptr<WaiterLatch> latch, std::atomic<bool>& running, std::atomic<bool>& release)
        : OperationBase(std::move(a), std::move(s)), m_latch(std::move(latch)), m_running(running), m_release(release)
    {}

    // The abandon path releases the parked bus thread immediately.
    void onAbandoned() noexcept override
    {
        m_latch->signal();
    }

protected:
    void doWork() override
    {
        m_running.store(true);
        // Wedge: ignore the cancel token (uncancellable, like SCardTransmit on
        // Linux) until the test explicitly frees us, so the worker is detached as
        // a zombie rather than joined.
        while (!m_release.load()) {
            std::this_thread::sleep_for(2ms);
        }
        m_latch->signal(); // the detached worker's eventual completion (idempotent)
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }

private:
    std::shared_ptr<WaiterLatch> m_latch;
    std::atomic<bool>& m_running;
    std::atomic<bool>& m_release;
};

} // namespace

TEST(OperationManager, SingleReaderSerialisesQueue)
{
    OperationManager mgr; // bus-less unit-test mode
    std::atomic<int> completed{0};

    mgr.enqueueForTest(ObjectId{1}, makeCountingOp(completed, 50ms));
    mgr.enqueueForTest(ObjectId{1}, makeCountingOp(completed, 50ms));
    mgr.enqueueForTest(ObjectId{1}, makeCountingOp(completed, 50ms));

    // 3 × 50 ms serially = ~150 ms. Cross-reader test below proves parallel.
    const auto start = std::chrono::steady_clock::now();
    while (completed.load() < 3 && (std::chrono::steady_clock::now() - start) < 1s) {
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_EQ(completed.load(), 3);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_GE(elapsed, 120ms) << "single-reader queue must serialise (saw "
                              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms)";
}

TEST(OperationManager, CrossReaderRunsInParallel)
{
    OperationManager mgr;
    std::atomic<int> completed{0};

    mgr.enqueueForTest(ObjectId{1}, makeCountingOp(completed, 200ms));
    mgr.enqueueForTest(ObjectId{2}, makeCountingOp(completed, 200ms));

    const auto start = std::chrono::steady_clock::now();
    while (completed.load() < 2 && (std::chrono::steady_clock::now() - start) < 1s) {
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_EQ(completed.load(), 2);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, 380ms) << "cross-reader ops must run in parallel (saw "
                              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms)";
}

TEST(OperationManager, RemoveReaderCancelsQueuedOps)
{
    OperationManager mgr;
    std::atomic<int> completed{0};
    mgr.enqueueForTest(ObjectId{1}, makeCountingOp(completed, 500ms));
    mgr.enqueueForTest(ObjectId{1}, makeCountingOp(completed, 500ms));
    std::this_thread::sleep_for(50ms); // give worker time to pick up first op
    mgr.removeReader(ObjectId{1});
    // Worker stop + drain — must not hang.
    std::this_thread::sleep_for(200ms);
    EXPECT_GE(completed.load(), 0) << "no hang on removeReader";
}

// workerFor returns a shared_ptr COPY so a worker handle obtained by a
// bus-thread caller (enqueue*) survives a concurrent
// removeReader that drops the worker from m_workers + abandonOrJoin frees its
// ref — closing the use-after-free of worker.mutex / worker.holder in the
// window between workerFor
// releasing m_workersMutex and the caller finishing its queue push. With the
// pre-fix unique_ptr ownership the storage was freed under the caller's handle.
TEST(OperationManager, WorkerStorageSurvivesConcurrentRemoval)
{
    OperationManager mgr; // bus-less unit-test mode
    EXPECT_TRUE(mgr.workerSurvivesRemovalForTest(ObjectId{1}))
        << "the worker handle must outlive removeReader (no UAF in the workerFor->push gap)";
}

// A thread parked on an in-flight op's completion latch must be released when
// the op's wedged worker is abandoned (detached to the zombie list), NOT left
// hanging until the uncancellable doWork finally returns. abandonOrJoin ->
// inFlight->onAbandoned() signals the latch immediately.
TEST(OperationManager, AbandonReleasesParkedWaiter)
{
    OperationManager mgr; // bus-less unit-test mode
    auto latch = std::make_shared<WaiterLatch>();
    std::atomic<bool> running{false};
    std::atomic<bool> release{false};

    auto op = std::make_unique<WedgedProbeOp>(std::make_unique<CountingChannel>(), std::make_shared<OperationState>(),
                                              latch, running, release);
    mgr.enqueueForTest(ObjectId{1}, std::move(op));

    // Wait for the op to enter its uncancellable doWork.
    for (int i = 0; i < 200 && !running.load(); ++i) {
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_TRUE(running.load()) << "the wedged op never started";

    // A "bus thread" parks on the latch, like an op that exposes an external waiter.
    std::atomic<bool> waiterReleased{false};
    std::thread waiter([&] {
        std::unique_lock lk(latch->mutex);
        latch->cv.wait(lk, [&] { return latch->done; });
        waiterReleased.store(true);
    });

    // removeReader abandons the wedged worker (it ignores cancel) -> onAbandoned
    // -> latch released, even though doWork is STILL running (release == false).
    mgr.removeReader(ObjectId{1});

    // The waiter must wake promptly (the abandon grace is ~250ms; allow margin),
    // BEFORE we ever free the wedged doWork.
    for (int i = 0; i < 250 && !waiterReleased.load(); ++i) {
        std::this_thread::sleep_for(2ms);
    }
    EXPECT_TRUE(waiterReleased.load()) << "the parked waiter was not released on abandon (bus-thread hang)";

    waiter.join();
    // Now let the detached worker's doWork unwind so the test process exits clean.
    release.store(true);
    std::this_thread::sleep_for(20ms);
}

// On card removal the per-reader shared CardSession (which may hold a live PACE
// channel) must be closed so the NEXT operation on that reader re-opens and
// re-resolves candidates against whatever card is present next. Drive a
// worker-thread acquire, invalidate the session, then drive a second acquire and
// assert the factory re-opened (counter bumped) and the session handle differs.
TEST(OperationManager, InvalidateReaderSessionReopensOnNextAcquire)
{
    OperationManager mgr; // bus-less unit-test mode

    // Counting SessionFactory: each call returns a fresh detached CardSession
    // and bumps an atomic open-counter. Set BEFORE any enqueue so the worker's
    // lazily-built holder captures it.
    std::atomic<int> opens{0};
    mgr.setSessionFactoryForTest(
        [&opens](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            opens.fetch_add(1);
            return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
        });

    // First acquire on the worker thread: opens the session once and records the
    // handle. Synchronise on a flag the probe sets (no sleep-race).
    std::atomic<void*> firstSession{nullptr};
    // Held so the allocator cannot hand the freed block to the re-opened session:
    // without it the address comparison below tests the allocator, not the holder.
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> keepFirstAlive;
    std::atomic<bool> firstDone{false};
    mgr.enqueueHolderProbeForTest(ObjectId{1}, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            keepFirstAlive = a->session;
            firstSession.store(a->session.get());
        }
        firstDone.store(true);
    });
    {
        const auto start = std::chrono::steady_clock::now();
        while (!firstDone.load() && (std::chrono::steady_clock::now() - start) < 2s) {
            std::this_thread::sleep_for(2ms);
        }
    }
    ASSERT_TRUE(firstDone.load());
    ASSERT_EQ(opens.load(), 1) << "first acquire opens once";
    ASSERT_NE(firstSession.load(), nullptr);

    // Invalidate the reader's session from the caller (monitor/bus) thread. The
    // worker honours it between ops on its own thread.
    mgr.invalidateReaderSession(ObjectId{1});

    // Wait until the invalidate has actually been processed by polling on its
    // observable effect: the NEXT acquire re-opens (opens counter goes from 1
    // to 2). Drive a second worker-thread acquire and synchronise on its flag.
    std::atomic<void*> secondSession{nullptr};
    std::atomic<bool> secondDone{false};
    mgr.enqueueHolderProbeForTest(ObjectId{1}, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            secondSession.store(a->session.get());
        }
        secondDone.store(true);
    });
    {
        const auto start = std::chrono::steady_clock::now();
        while (!secondDone.load() && (std::chrono::steady_clock::now() - start) < 2s) {
            std::this_thread::sleep_for(2ms);
        }
    }
    ASSERT_TRUE(secondDone.load());
    EXPECT_EQ(opens.load(), 2) << "invalidate forces the next acquire to re-open the session";
    EXPECT_NE(secondSession.load(), firstSession.load()) << "a fresh session handle after re-open";
}

// A destructive reader teardown (removeReader -> abandonOrJoin queue drain, then
// the workerLoop exit drain) destroys the queued ops WITHOUT routing them
// through the cleanup-grace queue. The op-tracking tables (m_byId /
// m_senderToOps / m_opToSender) must be scrubbed for those ops so a later
// cancel / dispatchClientDisconnect cannot dereference a freed
// OperationBase*. Hold the worker busy with a gated op so a SECOND tracked op
// stays QUEUED, tear the reader down, then assert the queued op's id/sender
// are gone and that cancel / dispatchClientDisconnect are safe no-ops.
TEST(OperationManager, DestructiveTeardownScrubsOpTrackingTables)
{
    OperationManager mgr; // bus-less unit-test mode

    // Op 1: gated, cooperating — keeps the worker thread busy in doWork.
    std::atomic<bool> running{false};
    auto gated =
        std::make_unique<GatedOp>(std::make_unique<CountingChannel>(), std::make_shared<OperationState>(), running);
    const OperationId gatedId{1};
    mgr.enqueueTrackedForTest(ObjectId{1}, std::move(gated), gatedId, CallerToken{":1.100"});

    // Wait until op 1 is actually executing so op 2 is guaranteed to stay queued.
    const auto t0 = std::chrono::steady_clock::now();
    while (!running.load() && (std::chrono::steady_clock::now() - t0) < 2s) {
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_TRUE(running.load()) << "gated op must be in-flight before the second is queued";

    // Op 2: stays QUEUED behind op 1; tracked under its own id + sender.
    std::atomic<int> dummy{0};
    auto queued = makeCountingOp(dummy, 10ms);
    const OperationId queuedId{2};
    mgr.enqueueTrackedForTest(ObjectId{1}, std::move(queued), queuedId, CallerToken{":1.200"});

    // Both ops are tracked before teardown.
    ASSERT_TRUE(mgr.isIdTrackedForTest(gatedId));
    ASSERT_TRUE(mgr.isIdTrackedForTest(queuedId));
    ASSERT_TRUE(mgr.isSenderTrackedForTest(CallerToken{":1.200"}));
    ASSERT_TRUE(mgr.isOpSenderTrackedForTest(queuedId));

    // Destructive teardown: drains + clears the queue (op 2) and joins the
    // cooperating in-flight op (op 1).
    mgr.removeReader(ObjectId{1});

    // The queued op is destroyed by the destructive teardown (abandonOrJoin's
    // queue drain) WITHOUT routing through cleanup-grace — it is exactly the
    // path the scrub targets. It must be fully scrubbed from all three tables.
    EXPECT_FALSE(mgr.isIdTrackedForTest(queuedId)) << "queued op's m_byId entry scrubbed";
    EXPECT_FALSE(mgr.isOpSenderTrackedForTest(queuedId)) << "queued op's m_opToSender entry scrubbed";
    EXPECT_FALSE(mgr.isSenderTrackedForTest(CallerToken{":1.200"})) << "queued op's sender set scrubbed (now empty)";

    // The in-flight gated op (op 1) completes normally and — in PRODUCTION — is
    // scrubbed via cleanup-grace (m_bus + cleanupLoop). This bus-less harness has
    // no cleanup thread, so its m_byId entry intentionally is not asserted here;
    // the fix under test is the destructive QUEUED-op teardown above.

    // These would dereference a freed OperationBase* (the queued op) in the buggy
    // version; with the tables scrubbed they are safe no-ops (no entry to deref).
    mgr.cancel(queuedId);
    mgr.dispatchClientDisconnect(CallerToken{":1.200"});
    SUCCEED() << "no stale-op deref after a destructive teardown";
}

// Proves the SCRUB-BEFORE-FREE ORDER (not just eventual scrub) on the queued-op
// teardown path. The previous test calls cancel AFTER removeReader fully
// returns, so it passes even if the scrub ran AFTER the queued op was freed —
// leaving a cross-thread UAF window (teardown on the PC/SC monitor thread,
// cancel on the transport event-loop thread). Here the queued op records, AT
// THE MOMENT OF ITS OWN DESTRUCTION (the free point), whether its m_byId entry
// is still tracked. The fix scrubs the tables while the op is still alive, so at
// destruction the path must already be ABSENT. With a destroy-then-scrub
// ordering this assertion FAILS (the op observes itself still tracked when it is
// freed) — fail-first confirmed.
TEST(OperationManager, DestructiveTeardownScrubsBeforeFreeingQueuedOp)
{
    OperationManager mgr; // bus-less unit-test mode

    // Op 1: gated, cooperating — keeps the worker thread busy in doWork so op 2
    // stays QUEUED (it is the queued-op teardown path that is under test).
    std::atomic<bool> running{false};
    auto gated =
        std::make_unique<GatedOp>(std::make_unique<CountingChannel>(), std::make_shared<OperationState>(), running);
    const OperationId gatedId{1};
    mgr.enqueueTrackedForTest(ObjectId{1}, std::move(gated), gatedId, CallerToken{":1.100"});

    const auto t0 = std::chrono::steady_clock::now();
    while (!running.load() && (std::chrono::steady_clock::now() - t0) < 2s) {
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_TRUE(running.load()) << "gated op must be in-flight before the second is queued";

    // Op 2: stays QUEUED. Its destructor records whether it is still tracked in
    // m_byId at the instant it is freed. trackedAtFree==false => scrub already
    // ran (correct); ==true => freed while still tracked (the UAF window).
    const OperationId queuedId{2};
    std::atomic<int> destroyed{0};
    std::atomic<bool> trackedAtFree{false};
    auto probe =
        std::make_unique<FreeProbeOp>(std::make_unique<CountingChannel>(), std::make_shared<OperationState>(), [&] {
            trackedAtFree.store(mgr.isIdTrackedForTest(queuedId));
            destroyed.fetch_add(1);
        });
    mgr.enqueueTrackedForTest(ObjectId{1}, std::move(probe), queuedId, CallerToken{":1.200"});

    ASSERT_TRUE(mgr.isIdTrackedForTest(queuedId));

    // Destructive teardown: drains + frees the queued op (op 2). The scrub MUST
    // precede the free; the op's destructor observes the table state at free.
    mgr.removeReader(ObjectId{1});

    ASSERT_EQ(destroyed.load(), 1) << "the queued op must have been freed by the teardown drain";
    EXPECT_FALSE(trackedAtFree.load())
        << "queued op was still in m_byId when it was freed — scrub ran AFTER free (UAF window)";
}

// The NORMAL-completion route (op runs to a terminal, enters the 5 s cleanup-grace
// queue, then ages out) must scrub ALL THREE tracking tables — not just m_byId. The
// pre-fix cleanupLoop erased ONLY m_byId inline and never touched m_senderToOps /
// m_opToSender, so those sender maps grew UNBOUNDED for a session-lifetime client
// connection (a resource leak): every completed client op left a permanent entry.
// Run a tracked op to completion under the PRODUCTION manager (so it lands in the
// cleanup-grace queue), then age it out via the real cleanup-scrub route and assert
// every table is empty. Pre-fix, the two sender-map assertions FAIL.
TEST(OperationManager, NormalCompletionCleanupScrubsSenderTables)
{
    OperationManager mgr{nullptr}; // production ctor: m_production + cleanup-grace worker
    std::atomic<int> completed{0};
    const OperationId id{1};
    const CallerToken sender{":1.500"};
    mgr.enqueueTrackedForTest(ObjectId{1}, makeCountingOp(completed, 5ms), id, sender);

    // Wait for the op to run to its terminal (the worker then pushes it, in
    // production mode, into the cleanup-grace queue).
    const auto start = std::chrono::steady_clock::now();
    while (completed.load() < 1 && (std::chrono::steady_clock::now() - start) < 2s) {
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_EQ(completed.load(), 1) << "the tracked op must complete via the normal route";

    // The sender is recorded from enqueue time, independent of the finish push.
    ASSERT_TRUE(mgr.isSenderTrackedForTest(sender));
    ASSERT_TRUE(mgr.isOpSenderTrackedForTest(id));

    // Age the finished op out through the REAL cleanup-scrub route (grace 0). Poll
    // the sweep so we do not race the worker's push of the completed op into the
    // cleanup-grace queue; once it lands, the sweep ages it out + scrubs the tables.
    const auto sweepStart = std::chrono::steady_clock::now();
    while (mgr.isIdTrackedForTest(id) && (std::chrono::steady_clock::now() - sweepStart) < 2s) {
        mgr.runCleanupSweepForTest();
        if (mgr.isIdTrackedForTest(id)) {
            std::this_thread::sleep_for(2ms);
        }
    }

    EXPECT_FALSE(mgr.isIdTrackedForTest(id)) << "m_byId scrubbed by the normal cleanup route";
    EXPECT_FALSE(mgr.isOpSenderTrackedForTest(id))
        << "m_opToSender scrubbed by the normal cleanup route (pre-fix: leaked)";
    EXPECT_FALSE(mgr.isSenderTrackedForTest(sender))
        << "m_senderToOps scrubbed by the normal cleanup route (pre-fix: leaked)";
}

namespace {

// Counting factory shared by the hold tests: every open (logical or hold) is a
// fresh detached session. Tests that must tell the two apart observe the
// holder through a worker-thread probe, never through the count alone,
// because the idle sweep renews the hold (release + re-acquire) every period.
void installCountingFactory(OperationManager& mgr, std::atomic<int>& opens)
{
    mgr.setSessionFactoryForTest(
        [&opens](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            opens.fetch_add(1);
            return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
        });
}

// Run @p probe on reader 1's worker thread and wait (bounded) for it.
void probeOnWorker(OperationManager& mgr, std::function<void(CardSessionHolder&)> probe)
{
    std::atomic<bool> done{false};
    mgr.enqueueHolderProbeForTest(ObjectId{1}, [&, probe = std::move(probe)](CardSessionHolder& h) {
        probe(h);
        done.store(true);
    });
    const auto start = std::chrono::steady_clock::now();
    while (!done.load() && (std::chrono::steady_clock::now() - start) < 2s) {
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_TRUE(done.load()) << "worker probe did not run within 2 s";
}

} // namespace

// setReaderHold routes to the per-reader worker and the worker applies it on
// its own thread BEFORE the next queued op, so a probe enqueued after the call
// observes the hold state deterministically.
// With no session on the reader the hold is opened through the factory: it is
// then the reader's one connection.
TEST(OperationManager, SetReaderHoldRoutesAndApplies)
{
    // Everything a worker-thread lambda captures by reference is declared
    // BEFORE the manager, so it outlives the workers the manager joins.
    std::atomic<int> opens{0};
    OperationManager mgr; // bus-less unit-test mode
    installCountingFactory(mgr, opens);

    EXPECT_FALSE(mgr.isReaderHeldForTest(ObjectId{1})) << "no worker yet";
    mgr.setReaderHold(ObjectId{1}, true); // no worker: must be a silent no-op
    EXPECT_FALSE(mgr.isReaderHeldForTest(ObjectId{1})) << "no worker: nothing stored";

    probeOnWorker(mgr, [](CardSessionHolder&) {}); // materialise the worker
    EXPECT_EQ(opens.load(), 0) << "materialising the worker opens nothing";

    mgr.setReaderHold(ObjectId{1}, true);
    EXPECT_TRUE(mgr.isReaderHeldForTest(ObjectId{1}));
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 1) << "the hold was applied before the next queued op";
    EXPECT_EQ(opens.load(), 1) << "the hold opened exactly once through the factory";

    mgr.setReaderHold(ObjectId{1}, false);
    EXPECT_FALSE(mgr.isReaderHeldForTest(ObjectId{1}));
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 0) << "the hold was released before the next queued op";

    EXPECT_FALSE(mgr.isReaderHeldForTest(ObjectId{2})) << "an unrelated reader is untouched";
}

// Card removal (invalidateReaderSession) releases the hold on the worker
// thread: there is nothing left to keep powered.
TEST(OperationManager, CardRemovedReleasesHold)
{
    std::atomic<int> opens{0};
    OperationManager mgr;
    installCountingFactory(mgr, opens);

    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    ASSERT_EQ(held.load(), 1);

    mgr.invalidateReaderSession(ObjectId{1});
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 0) << "invalidate released the hold before the next op";
    EXPECT_TRUE(mgr.isReaderHeldForTest(ObjectId{1}))
        << "the FLAG is the host's to clear (its card-removed hook calls setReaderHold(false) first); "
           "the worker only dropped the handle";
}

namespace {

// One sweep, observed deterministically. probeOnWorker wakes the worker and
// restarts its bounded wait, so the sweep can only fire in the quiet stretch
// after the LAST probe: with a 200 ms period, sleeping 300 ms leaves a 100 ms
// window in which exactly one sweep has run and the next has not.
constexpr auto kSweepPeriod = 200ms;
constexpr auto kAfterOneSweep = 300ms;

// A fake steady clock the test advances, shared by every holder the manager
// builds. Nanoseconds in an atomic so the worker thread reads it safely.
struct FakeHolderClock
{
    std::atomic<std::int64_t> ns{0};
    CardSessionHolder::Clock fn()
    {
        return [this] { return std::chrono::steady_clock::time_point{std::chrono::nanoseconds{ns.load()}}; };
    }
    void advance(std::chrono::nanoseconds d)
    {
        ns.fetch_add(d.count());
    }
};

} // namespace

namespace {

// Counts the sessions the factory opened and the ones that have since closed.
//
// The factory is injected, so a test can own what it hands out: each session
// goes back wrapped in an aliasing shared_ptr whose control block runs a
// release hook. The last owner letting go -- normally the holder's own reset()
// -- is therefore the event that counts a close, the way a PC/SC handle is
// released.
class HandleCensus
{
public:
    SessionFactory factory()
    {
        return
            [this](const std::string& r)
                -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
                auto owner = std::make_shared<Owned>(LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r), this);
                {
                    const std::lock_guard lock(m_mutex);
                    ++m_opens;
                }
                return std::shared_ptr<LibreSCRS::SmartCard::CardSession>{owner, owner->session.get()};
            };
    }

    [[nodiscard]] int opens() const
    {
        const std::lock_guard lock(m_mutex);
        return m_opens;
    }
    [[nodiscard]] int closes() const
    {
        const std::lock_guard lock(m_mutex);
        return m_closes;
    }

private:
    struct Owned
    {
        Owned(std::shared_ptr<LibreSCRS::SmartCard::CardSession> s, HandleCensus* c) : session(std::move(s)), census(c)
        {}
        ~Owned()
        {
            census->release();
        }
        std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
        HandleCensus* census;
    };

    void release()
    {
        const std::lock_guard lock(m_mutex);
        ++m_closes;
    }

    mutable std::mutex m_mutex;
    int m_opens = 0;
    int m_closes = 0;
};

} // namespace

// With the hold wanted, the idle sweep demotes the reader's one session into
// the hold: the same connection stays open, emptied of every secret, and the
// next operation promotes it back. The reader never carries two connections,
// and never none.
TEST(OperationManager, SweepWithHoldDemotesTheIdleSession)
{
    HandleCensus census;
    FakeHolderClock clock;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> first;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            first = a->session;
        }
    });
    ASSERT_NE(first, nullptr);
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 0) << "no second connection while the session stands";
    ASSERT_EQ(census.opens(), 1);

    clock.advance(CardSessionHolder::kIdleClose);
    std::this_thread::sleep_for(kAfterOneSweep);

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> second;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held.store(h.hasHoldForTest() ? 1 : 0);
        auto b = h.acquire();
        if (b) {
            second = b->session;
        }
    });
    EXPECT_EQ(held.load(), 1) << "the idle session became the hold";
    EXPECT_EQ(second, first) << "the next operation reused the same connection";
    EXPECT_EQ(census.opens(), 1) << "no connection was opened for the hold or after it";
}

// Without the hold the sweep closes an idle session, and leaves an active one
// alone.
TEST(OperationManager, SweepWithoutHoldClosesTheIdleSession)
{
    std::atomic<int> opens{0};
    FakeHolderClock clock;
    OperationManager mgr;
    installCountingFactory(mgr, opens);
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> first;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            first = a->session;
        }
    });
    ASSERT_NE(first, nullptr);

    clock.advance(5s);
    std::this_thread::sleep_for(kAfterOneSweep);
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> second;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        auto b = h.acquire();
        if (b) {
            second = b->session;
        }
    });
    EXPECT_EQ(second, first) << "an active session is not closed";

    clock.advance(CardSessionHolder::kIdleClose);
    std::this_thread::sleep_for(kAfterOneSweep);
    std::atomic<int> held{-1};
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> third;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held.store(h.hasHoldForTest() ? 1 : 0);
        auto c = h.acquire();
        if (c) {
            third = c->session;
        }
    });
    EXPECT_EQ(held.load(), 0);
    ASSERT_NE(third, nullptr);
    EXPECT_NE(third, first) << "the idle session was closed and the next acquire re-opened it";
    EXPECT_EQ(opens.load(), 2);
}

// A hold asked for while a session is in use takes no connection of its own:
// it is applied by the first sweep that finds that session idle, as a demote.
TEST(OperationManager, HoldRequestedDuringASessionIsAppliedByDemoteAtIdle)
{
    std::atomic<int> opens{0};
    FakeHolderClock clock;
    OperationManager mgr;
    installCountingFactory(mgr, opens);
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());

    probeOnWorker(mgr, [](CardSessionHolder& h) { (void)h.acquire(); });
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 0);
    EXPECT_TRUE(mgr.isReaderHeldForTest(ObjectId{1})) << "the request stands; the demote applies it";

    clock.advance(CardSessionHolder::kIdleClose);
    std::this_thread::sleep_for(kAfterOneSweep);
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 1) << "the first sweep with that session idle demoted it";
    EXPECT_EQ(opens.load(), 1);
}

namespace {

// A clock that hands out a scripted sequence of instants, one per read, and
// repeats the last one forever. It exists to make the number of READS visible
// in the outcome: a sweep that consults the clock twice can be handed two
// instants that straddle the idle boundary, which a sweep that consults it once
// cannot see.
class ScriptedClock
{
public:
    explicit ScriptedClock(std::vector<std::chrono::milliseconds> script) : m_script(std::move(script)) {}

    CardSessionHolder::Clock fn()
    {
        return [this] {
            const std::lock_guard lock(m_mutex);
            const auto at = std::min(m_next, m_script.size() - 1);
            ++m_next;
            return std::chrono::steady_clock::time_point{m_script[at]};
        };
    }
    [[nodiscard]] std::size_t reads() const
    {
        const std::lock_guard lock(m_mutex);
        return m_next;
    }

private:
    mutable std::mutex m_mutex;
    std::vector<std::chrono::milliseconds> m_script;
    std::size_t m_next = 0;
};

} // namespace

// One sweep, one instant: the sweep reads the clock once and decides from that
// one reading whether the session is idle. At 44'999 ms it is not, so it is
// neither demoted nor closed; a second reading (45'000 ms) would have found it
// idle in the same sweep.
//
//   read 1  0 ms       acquire() -> the session's last-used stamp is 0 ms.
//   read 2  44'999 ms  the sweep: still in use.
//   read 3  45'000 ms  spent only if the sweep reads the clock a second time.
TEST(OperationManager, SweepDecidesOnOneInstant)
{
    constexpr auto kWidePeriod = 500ms;
    constexpr auto kAfterOneWideSweep = 750ms;

    HandleCensus census;
    ScriptedClock clock{{0ms, 44'999ms, 45'000ms}};
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kWidePeriod);
    mgr.setHolderClockForTest(clock.fn());

    probeOnWorker(mgr, [](CardSessionHolder& h) { (void)h.acquire(); });
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    ASSERT_EQ(held.load(), 0);
    ASSERT_EQ(clock.reads(), 1U) << "the hold request reads no clock while a session stands";

    std::this_thread::sleep_for(kAfterOneWideSweep);

    std::atomic<std::size_t> readsAfterSweep{0};
    std::atomic<int> opensAfter{0};
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held.store(h.hasHoldForTest() ? 1 : 0);
        readsAfterSweep.store(clock.reads());
        (void)h.acquire();
        opensAfter.store(census.opens());
    });

    EXPECT_EQ(readsAfterSweep.load(), 2U) << "one sweep, and it read the clock once";
    EXPECT_EQ(held.load(), 0) << "at 44'999 ms the session is still in use: not demoted";
    EXPECT_EQ(opensAfter.load(), 1) << "and not closed";
}

namespace {

using Cap = LibreSCRS::Plugin::CardCapabilities;

// A composite card: its ATR names the PKI plugin, and the live probe on the
// held session finds the eMRTD applet beside it. resolvePlugin ignores the ATR
// on purpose, so an ATR-only shortcut would find the PKI plugin on any card.
class CompositeResolver final : public CapabilityResolver
{
public:
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> /*atr*/) const noexcept override
    {
        return pki;
    }
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t> /*atr*/, LibreSCRS::SmartCard::CardSession& /*session*/) override
    {
        candidateCalls.fetch_add(1);
        return {pki, emrtd};
    }

    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> pki = std::make_shared<BasePinPlugin>("pki", Cap::PKI);
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> emrtd =
        std::make_shared<BasePinPlugin>("emrtd", Cap::IdentityData | Cap::EmrtdCrypto);
    std::atomic<int> candidateCalls{0};
};

constexpr std::uint32_t kCompositeCaps = static_cast<std::uint32_t>(Cap::PKI | Cap::IdentityData | Cap::EmrtdCrypto);

using Resolution = std::expected<CapabilityResolver::CardResolution, LibreSCRS::SmartCard::OpenError>;

// A resolution no holder produces, so a probe that never wrote its result
// cannot pass for one that did.
Resolution unwritten()
{
    return std::unexpected{LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                           LibreSCRS::Auth::ErrorKeys::genericComm(),
                                                           std::string{"never written"}}};
}

} // namespace

// A card no plugin serves keeps nothing open: the insertion probe finds no
// candidate and the holder closes the session before the probe returns, so the
// reader is not held for kIdleClose by a card the agent cannot use. The probe's
// answer is a definitive one -- no capabilities, no pre-read auth -- not an
// open failure, so a host has no reason to open the card again.
TEST(OperationManager, UnservedCardSessionClosesRightAfterProbing)
{
    HandleCensus census;
    OperationManager mgr; // bus-less: the holder resolves no candidate
    mgr.setSessionFactoryForTest(census.factory());

    auto probed = unwritten();
    probeOnWorker(mgr, [&](CardSessionHolder& h) { probed = h.fullResolution(); });

    EXPECT_EQ(census.opens(), 1) << "the probe opened the card once";
    EXPECT_EQ(census.closes(), 1) << "and closed it before returning: no plugin serves this card";
    ASSERT_TRUE(probed.has_value()) << "an unserved card is an answer, not a failure to open";
    EXPECT_TRUE(probed->candidates.empty());
    EXPECT_EQ(probed->capabilities, 0U);
    EXPECT_EQ(probed->preReadAuth, LibreSCRS::Auth::PreReadAuthMethod::None);
}

// A card two plugins serve keeps BOTH: the capabilities come from every
// candidate the live probe on the held session found, never from the ATR's
// one plugin, and that session stays open for the operations that follow.
TEST(OperationManager, CompositeCardKeepsTheUnionOfEveryProbedPlugin)
{
    HandleCensus census;
    CompositeResolver resolver;
    OperationManager mgr{&resolver};
    mgr.setSessionFactoryForTest(census.factory());

    auto probed = unwritten();
    probeOnWorker(mgr, [&](CardSessionHolder& h) { probed = h.fullResolution(); });

    EXPECT_GE(resolver.candidateCalls.load(), 1) << "the live probe ran on the held session";
    ASSERT_TRUE(probed.has_value());
    EXPECT_EQ(probed->candidates.size(), 2U);
    EXPECT_EQ(probed->capabilities, kCompositeCaps) << "the union of the PKI and the eMRTD plugin, not the ATR's one";
    EXPECT_EQ(census.opens(), 1);
    EXPECT_EQ(census.closes(), 0) << "a card a plugin serves keeps its session after the probe";
}

// The insertion probe can be refused -- another process holds the card
// exclusively. The probe then reports the open failure itself, which is what
// tells a host to ask again, and the reader is not left broken: the first
// client operation opens the card itself and the resolution it yields is the
// full one.
TEST(OperationManager, RefusedInsertionProbeReportsTheOpenErrorAndNextOperationReopens)
{
    std::atomic<int> opens{0};
    CompositeResolver resolver;
    OperationManager mgr{&resolver};
    mgr.setSessionFactoryForTest(
        [&opens](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            if (opens.fetch_add(1) == 0) {
                return std::unexpected{LibreSCRS::SmartCard::OpenError{
                    LibreSCRS::SmartCard::OpenError::Kind::SessionRefused, LibreSCRS::Auth::ErrorKeys::genericComm(),
                    std::string{"SCARD_E_SHARING_VIOLATION"}}};
            }
            return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
        });

    auto refused = unwritten();
    probeOnWorker(mgr, [&](CardSessionHolder& h) { refused = h.fullResolution(); });
    EXPECT_EQ(opens.load(), 1);
    ASSERT_FALSE(refused.has_value()) << "a refused probe resolves nothing and says so";
    EXPECT_EQ(refused.error().kind, LibreSCRS::SmartCard::OpenError::Kind::SessionRefused)
        << "the factory's own error, not a stand-in";
    EXPECT_EQ(refused.error().diagnosticDetail, std::optional<std::string>{"SCARD_E_SHARING_VIOLATION"});

    bool operationOpened = false;
    auto republished = unwritten();
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        operationOpened = h.acquire().has_value();
        republished = h.fullResolution();
    });
    EXPECT_TRUE(operationOpened) << "the first client operation opens the card";
    EXPECT_EQ(opens.load(), 2) << "through the factory, once";
    ASSERT_TRUE(republished.has_value());
    EXPECT_EQ(republished->capabilities, kCompositeCaps) << "and the resolution it yields is the full one";
}

// A seam that throws has not said what the card is either, so the probe
// reports it the way it reports a failed open: the host asks again.
TEST(OperationManager, AThrowingInsertionProbeIsReportedAsAnOpenError)
{
    OperationManager mgr;
    mgr.setSessionFactoryForTest(
        [](const std::string&)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            throw std::runtime_error{"the factory threw"};
        });

    std::optional<Resolution> probed;
    probeOnWorker(mgr, [&](CardSessionHolder& h) { probed = h.fullResolution(); });
    ASSERT_TRUE(probed.has_value());
    EXPECT_FALSE(probed->has_value()) << "a throwing seam is not an unserved card";
}

namespace {

// Set only on reader A's worker thread, around the open that stands in for a
// card call that takes long: the factory runs on the thread that called
// acquire(), so this tells reader A's open from reader B's.
thread_local bool tlSlowOpen = false;

} // namespace

// Readers do not wait for each other. Reader A's card call -- an open that
// stands in for a session grant or a slow transmit -- does not return until
// reader B has run 200 operations, each opening and closing its card. Had B's
// operations queued behind A's call, none of them could finish while A is
// still inside it. No clock decides the verdict: A is released by B's last
// operation, and the waits below only bound a failing run.
TEST(OperationManager, ReaderBIsNotDelayedByReaderA)
{
    constexpr int kOperations = 200;
    const ObjectId readerA{1};
    const ObjectId readerB{2};

    std::mutex m;
    std::condition_variable cv;
    bool aInSlowCall = false;
    bool releaseA = false;
    std::atomic<bool> aDone{false};
    std::atomic<int> bDone{0};
    OperationManager mgr;
    mgr.setSessionFactoryForTest(
        [&](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            if (tlSlowOpen) {
                std::unique_lock lock(m);
                aInSlowCall = true;
                cv.notify_all();
                cv.wait_for(lock, 10s, [&] { return releaseA; });
            }
            return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
        });

    mgr.enqueueHolderProbeForTest(readerA, [&](CardSessionHolder& h) {
        tlSlowOpen = true;
        (void)h.acquire();
        tlSlowOpen = false;
        aDone.store(true);
    });
    {
        std::unique_lock lock(m);
        ASSERT_TRUE(cv.wait_for(lock, 5s, [&] { return aInSlowCall; })) << "reader A never entered its slow call";
    }

    for (int i = 0; i < kOperations; ++i) {
        mgr.enqueueHolderProbeForTest(readerB, [&](CardSessionHolder& h) {
            (void)h.acquire();
            h.invalidate();
            bDone.fetch_add(1);
        });
    }
    const auto start = std::chrono::steady_clock::now();
    while (bDone.load() < kOperations && std::chrono::steady_clock::now() - start < 5s) {
        std::this_thread::sleep_for(2ms);
    }
    const bool aStillInItsCall = !aDone.load();
    const int bFinished = bDone.load();
    {
        const std::lock_guard lock(m);
        releaseA = true;
    }
    cv.notify_all();

    EXPECT_EQ(bFinished, kOperations) << "reader B's operations waited for reader A's call";
    EXPECT_TRUE(aStillInItsCall) << "reader A's call ended before reader B finished: the case proved nothing";

    // Reader A's worker must finish before the manager goes: an abandoned
    // worker would outlive the factory's captures on this stack.
    const auto doneBy = std::chrono::steady_clock::now();
    while (!aDone.load() && std::chrono::steady_clock::now() - doneBy < 5s) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(aDone.load());
}

// ---- Background slot -------------------------------------------------------

namespace {

// Ordered record of what ran and what was destroyed, shared with the fake ops.
struct Journal
{
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::string> events;
    bool gateOpen{false};

    void add(std::string e)
    {
        {
            const std::lock_guard lock(mutex);
            events.push_back(std::move(e));
        }
        cv.notify_all();
    }
    [[nodiscard]] bool waitFor(const std::string& e, std::chrono::milliseconds limit = 5s)
    {
        std::unique_lock lock(mutex);
        return cv.wait_for(lock, limit, [&] { return std::find(events.begin(), events.end(), e) != events.end(); });
    }
    [[nodiscard]] bool has(const std::string& e)
    {
        const std::lock_guard lock(mutex);
        return std::find(events.begin(), events.end(), e) != events.end();
    }
    [[nodiscard]] std::vector<std::string> snapshot()
    {
        const std::lock_guard lock(mutex);
        return events;
    }
    void openGate()
    {
        {
            const std::lock_guard lock(mutex);
            gateOpen = true;
        }
        cv.notify_all();
    }
    void waitGate()
    {
        std::unique_lock lock(mutex);
        cv.wait_for(lock, 10s, [&] { return gateOpen; });
    }
};

// Records "<name>" when run and "~<name>" when destroyed; optionally blocks
// in doWork until the journal's gate opens ("<name>:start" marks the entry).
class JournalOp final : public OperationBase
{
public:
    JournalOp(std::shared_ptr<Journal> journal, std::string name, bool gated = false)
        : OperationBase(std::make_unique<CountingChannel>(), std::make_shared<OperationState>()),
          m_journal(std::move(journal)), m_name(std::move(name)), m_gated(gated)
    {}
    ~JournalOp() override
    {
        m_journal->add("~" + m_name);
    }

protected:
    void doWork() override
    {
        m_journal->add(m_name + ":start");
        if (m_gated) {
            m_journal->waitGate();
        }
        m_journal->add(m_name);
        finish(OperationStatus::Ok, ErrorCode::None, "ok", "ok");
    }

private:
    std::shared_ptr<Journal> m_journal;
    std::string m_name;
    bool m_gated;
};

std::unique_ptr<OperationBase> journalOp(const std::shared_ptr<Journal>& j, std::string name, bool gated = false)
{
    return std::make_unique<JournalOp>(j, std::move(name), gated);
}

} // namespace

TEST(OperationManagerBackground, BackgroundWaitsForTheQueue)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    const ObjectId reader{1};
    mgr.enqueueForTest(reader, journalOp(j, "A", true));
    ASSERT_TRUE(j->waitFor("A:start"));
    mgr.setBackgroundForTest(reader, journalOp(j, "slot"), 0ms);
    mgr.enqueueForTest(reader, journalOp(j, "B"));
    j->openGate();
    ASSERT_TRUE(j->waitFor("slot"));
    const auto ev = j->snapshot();
    const auto pos = [&](const std::string& e) { return std::find(ev.begin(), ev.end(), e) - ev.begin(); };
    EXPECT_LT(pos("A"), pos("B"));
    EXPECT_LT(pos("B"), pos("slot")) << "the slot must wait for the queued op";
}

TEST(OperationManagerBackground, BackgroundWaitsForItsSettle)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    mgr.setBackgroundForTest(ObjectId{1}, journalOp(j, "late"), 30s);
    mgr.setBackgroundForTest(ObjectId{2}, journalOp(j, "now"), 0ms);
    ASSERT_TRUE(j->waitFor("now"));
    std::this_thread::sleep_for(300ms);
    EXPECT_FALSE(j->has("late"));
    EXPECT_TRUE(mgr.hasBackgroundForTest(ObjectId{1}));
    EXPECT_FALSE(mgr.hasBackgroundForTest(ObjectId{2}));
}

TEST(OperationManagerBackground, BackgroundReplacedIsDestroyedUnrun)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    const ObjectId reader{1};
    mgr.setBackgroundForTest(reader, journalOp(j, "first"), 30s);
    mgr.setBackgroundForTest(reader, journalOp(j, "second"), 30s);
    EXPECT_TRUE(j->has("~first"));
    EXPECT_FALSE(j->has("first:start"));
    EXPECT_FALSE(j->has("~second"));
    EXPECT_TRUE(mgr.hasBackgroundForTest(reader));
    EXPECT_EQ(mgr.backgroundRequestsForTest(reader), 2U);
}

TEST(OperationManagerBackground, InvalidateDropsTheBackground)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    const ObjectId reader{1};
    mgr.setBackgroundForTest(reader, journalOp(j, "slot"), 30s);
    mgr.invalidateReaderSession(reader);
    ASSERT_TRUE(j->waitFor("~slot"));
    EXPECT_FALSE(mgr.hasBackgroundForTest(reader));
    EXPECT_FALSE(j->has("slot:start"));
}

TEST(OperationManagerBackground, RemoveReaderDropsTheBackground)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    const ObjectId reader{1};
    mgr.setBackgroundForTest(reader, journalOp(j, "slot"), 30s);
    mgr.removeReader(reader);
    EXPECT_TRUE(j->has("~slot"));
    EXPECT_FALSE(j->has("slot:start"));
    EXPECT_FALSE(mgr.hasBackgroundForTest(reader));
}

TEST(OperationManagerBackground, BackgroundOnAStoppedWorkerIsDestroyedUnrun)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    EXPECT_TRUE(mgr.backgroundOnStoppedWorkerRefusedForTest(ObjectId{1}, journalOp(j, "slot")));
    EXPECT_TRUE(j->has("~slot"));
    EXPECT_FALSE(j->has("slot:start"));
}

TEST(OperationManagerBackground, OpArrivingDuringBackgroundRunsAfterIt)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr;
    const ObjectId reader{1};
    mgr.setBackgroundForTest(reader, journalOp(j, "slot", true), 0ms);
    ASSERT_TRUE(j->waitFor("slot:start"));
    mgr.enqueueForTest(reader, journalOp(j, "B"));
    std::this_thread::sleep_for(100ms);
    EXPECT_FALSE(j->has("B:start")) << "the queued op must wait for the running slot";
    j->openGate();
    ASSERT_TRUE(j->waitFor("B"));
    const auto ev = j->snapshot();
    EXPECT_LT(std::find(ev.begin(), ev.end(), "slot") - ev.begin(), std::find(ev.begin(), ev.end(), "B") - ev.begin());
}

TEST(OperationManagerBackground, BackgroundIsOutsideTheQueueCap)
{
    auto j = std::make_shared<Journal>();
    OperationManager mgr(nullptr); // production ctor: the cap lives in enqueueOnReaderWorker
    const ObjectId reader{1};
    ASSERT_TRUE(mgr.enqueueOnReaderWorker(reader, "r", [j](CardSessionHolder&) {
        j->add("A:start");
        j->waitGate();
    }));
    ASSERT_TRUE(j->waitFor("A:start"));
    for (std::size_t i = 0; i < kMaxQueuedOpsPerReader; ++i) {
        ASSERT_TRUE(mgr.enqueueOnReaderWorker(reader, "r", [](CardSessionHolder&) {}));
    }
    EXPECT_FALSE(mgr.enqueueOnReaderWorker(reader, "r", [](CardSessionHolder&) {})) << "the queue is at its cap";
    mgr.setBackground(reader, [j](CardSessionHolder*) { return journalOp(j, "slot"); }, 0ms);
    EXPECT_TRUE(mgr.hasBackgroundForTest(reader));
    j->openGate();
    EXPECT_TRUE(j->waitFor("slot"));
}

TEST(OperationManagerBackground, SetBackgroundWithoutAWorkerCreatesNone)
{
    OperationManager mgr(nullptr);
    int factoryCalls = 0;
    mgr.setBackground(
        ObjectId{9},
        [&](CardSessionHolder*) {
            ++factoryCalls;
            return std::unique_ptr<OperationBase>{};
        },
        0ms);
    EXPECT_EQ(factoryCalls, 0) << "no worker: the factory must not even run";
    EXPECT_FALSE(mgr.hasBackgroundForTest(ObjectId{9}));
    EXPECT_EQ(mgr.backgroundRequestsForTest(ObjectId{9}), 0U);

    OperationManager bare; // not the production ctor
    EXPECT_THROW(bare.setBackground(
                     ObjectId{9}, [](CardSessionHolder*) { return std::unique_ptr<OperationBase>{}; }, 0ms),
                 std::logic_error);
}

// ---------------------------------------------------------------------------
// Hold suspension: while the system sleeps nothing may take a connection, and
// after wake the hold comes back only on a sweep, one period later at the
// earliest.
// ---------------------------------------------------------------------------
namespace {
// Shorter than kSweepPeriod: these tests count sweeps over several periods
// ("none while suspended", "not before holdNotBefore") rather than landing
// between exactly two, so a fast period keeps them quick.
constexpr auto kSuspendSweep = 100ms;

// Poll until @p done holds or @p limit passes.
template <class Pred>
bool waitUntil(Pred done, std::chrono::milliseconds limit = 2000ms)
{
    const auto start = std::chrono::steady_clock::now();
    while (!done() && (std::chrono::steady_clock::now() - start) < limit) {
        std::this_thread::sleep_for(2ms);
    }
    return done();
}

bool holdPresent(OperationManager& mgr)
{
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    return held.load() == 1;
}
} // namespace

TEST(OperationManager, HoldIsNotRetakenWhileSuspended)
{
    HandleCensus census;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kSuspendSweep);
    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setReaderHold(ObjectId{1}, true);
    ASSERT_TRUE(holdPresent(mgr));
    ASSERT_EQ(census.opens(), 1);

    mgr.setHoldsSuspended(true);
    mgr.invalidateReaderSession(ObjectId{1});
    EXPECT_FALSE(holdPresent(mgr)) << "the invalidate dropped the hold";
    std::this_thread::sleep_for(kSuspendSweep * 6);
    EXPECT_FALSE(holdPresent(mgr)) << "no sweep took it back while suspended";
    EXPECT_EQ(census.opens(), 1) << "nothing was opened while suspended";
    EXPECT_TRUE(mgr.isReaderHeldForTest(ObjectId{1})) << "the host's flag is untouched";
}

TEST(OperationManager, ResumeRetakesTheHoldOnAFreshConnection)
{
    HandleCensus census;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kSuspendSweep);
    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setReaderHold(ObjectId{1}, true);
    ASSERT_TRUE(holdPresent(mgr));

    mgr.setHoldsSuspended(true);
    mgr.invalidateReaderSession(ObjectId{1});
    ASSERT_FALSE(holdPresent(mgr));
    ASSERT_EQ(census.closes(), 1) << "the old connection is gone";

    std::this_thread::sleep_for(kSuspendSweep * 3);
    ASSERT_EQ(census.opens(), 1) << "still nothing opened while suspended";

    const auto lifted = std::chrono::steady_clock::now();
    mgr.invalidateReaderSession(ObjectId{1}); // the order the core uses: invalidate, then lift
    mgr.setHoldsSuspended(false);
    ASSERT_TRUE(waitUntil([&] { return census.opens() == 2; })) << "the sweep took the hold back";
    EXPECT_GE(std::chrono::steady_clock::now() - lifted, kSuspendSweep) << "not before one sweep period";
    std::this_thread::sleep_for(kSuspendSweep * 4);
    EXPECT_EQ(census.opens(), 2) << "exactly one new connection";
    EXPECT_EQ(census.closes(), 1) << "the old one was not reused";
    EXPECT_TRUE(holdPresent(mgr));
}

TEST(OperationManager, HoldWaitsOneSweepAfterResume)
{
    HandleCensus census;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(300ms);
    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setHoldsSuspended(true);

    const auto lifted = std::chrono::steady_clock::now();
    mgr.setHoldsSuspended(false);
    mgr.setReaderHold(ObjectId{1}, true); // step 2 runs at once, inside the wait
    std::this_thread::sleep_for(40ms);
    EXPECT_EQ(census.opens(), 0) << "a hold asked for right after the lift does not open at once";

    ASSERT_TRUE(waitUntil([&] { return census.opens() == 1; })) << "the sweep opens it afterwards";
    EXPECT_GE(std::chrono::steady_clock::now() - lifted, 300ms);
    std::this_thread::sleep_for(700ms);
    EXPECT_EQ(census.opens(), 1) << "exactly once";
}

TEST(OperationManager, OperationWhileSuspendedOpensAndIsNotDemoted)
{
    HandleCensus census;
    FakeHolderClock clock;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());
    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setHoldsSuspended(true);
    mgr.setReaderHold(ObjectId{1}, true);

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> first;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            first = a->session;
        }
    });
    ASSERT_NE(first, nullptr) << "an operation opens a session while suspended";
    ASSERT_EQ(census.opens(), 1);

    clock.advance(CardSessionHolder::kIdleClose);
    std::this_thread::sleep_for(kAfterOneSweep);
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> second;
    bool held = true;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held = h.hasHoldForTest();
        auto b = h.acquire();
        if (b) {
            second = b->session;
        }
    });
    EXPECT_FALSE(held) << "the idle session was closed, not demoted into a hold";
    EXPECT_NE(second, first);
    EXPECT_EQ(census.opens(), 2);
}

TEST(OperationManager, WorkerCreatedWhileSuspendedInheritsIt)
{
    HandleCensus census;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kSuspendSweep);
    EXPECT_FALSE(mgr.holdsSuspended());
    mgr.setHoldsSuspended(true); // no worker exists yet
    EXPECT_TRUE(mgr.holdsSuspended());

    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setReaderHold(ObjectId{1}, true);
    EXPECT_FALSE(holdPresent(mgr));
    std::this_thread::sleep_for(kSuspendSweep * 4);
    EXPECT_EQ(census.opens(), 0) << "the new worker took no hold";

    mgr.setHoldsSuspended(false);
    EXPECT_FALSE(mgr.holdsSuspended());
}

// --- A queued operation reports that it waits ---------------------------------
//
// Ops here carry a FakeOperationChannel with a shared Recording, so the test reads
// the phases the channel was told about from its own handles, whichever thread
// emitted them and whether or not the op is still alive.

namespace {

// Opens its gates on scope exit, so an ASSERT never leaves a worker parked (the
// manager's teardown would abandon it as a zombie holding this frame's state).
// Declare it AFTER the manager: members die in reverse order.
struct LatchOpener
{
    std::vector<std::shared_ptr<WaiterLatch>> gates;
    ~LatchOpener()
    {
        for (const auto& gate : gates) {
            gate->signal();
        }
    }
};

struct RunFlags
{
    std::atomic<bool> started{false};
    std::atomic<bool> returned{false};
};

// One op's observation handles; makes the channel the op will own.
struct Rig
{
    std::shared_ptr<OperationState> state{std::make_shared<OperationState>()};
    std::shared_ptr<FakeOperationChannel::Recording> recording{std::make_shared<FakeOperationChannel::Recording>()};
    std::shared_ptr<RunFlags> flags{std::make_shared<RunFlags>()};

    [[nodiscard]] std::unique_ptr<FakeOperationChannel> channel() const
    {
        auto channel = std::make_unique<FakeOperationChannel>();
        channel->observedState = state;
        channel->recording = recording;
        return channel;
    }
    [[nodiscard]] std::size_t phaseCount(OperationPhase phase) const
    {
        std::lock_guard lock(recording->mutex);
        return static_cast<std::size_t>(
            std::count(recording->phases.begin(), recording->phases.end(), static_cast<std::uint32_t>(phase)));
    }
    [[nodiscard]] std::vector<std::uint32_t> phases() const
    {
        std::lock_guard lock(recording->mutex);
        return recording->phases;
    }
    [[nodiscard]] bool currentPhaseIs(OperationPhase phase) const
    {
        return state->phase.load(std::memory_order_acquire) == static_cast<std::uint32_t>(phase);
    }
};

// Reports Connecting like a real flow, then finishes Ok.
class ProbeOp final : public OperationBase
{
public:
    ProbeOp(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state,
            std::shared_ptr<RunFlags> flags)
        : OperationBase(std::move(channel), std::move(state)), m_flags(std::move(flags))
    {}

protected:
    void doWork() override
    {
        m_flags->started.store(true);
        setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
        m_flags->returned.store(true);
    }

private:
    std::shared_ptr<RunFlags> m_flags;
};

// Parks in doWork on a gate. It ignores the cancel token (a stuck transmit)
// unless `cooperative`, in which case a cancel ends the wait and, when
// `afterCancel` is given, the op then parks on that second gate before it returns.
class ParkedOp final : public OperationBase
{
public:
    ParkedOp(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state,
             std::shared_ptr<RunFlags> flags, std::shared_ptr<WaiterLatch> gate, OperationPhase announce,
             bool cooperative, bool fastWatchdog, std::shared_ptr<WaiterLatch> afterCancel = nullptr)
        : OperationBase(std::move(channel), std::move(state)), m_flags(std::move(flags)), m_gate(std::move(gate)),
          m_afterCancel(std::move(afterCancel)), m_announce(announce), m_cooperative(cooperative)
    {
        if (fastWatchdog) {
            // The budget is whole seconds; fire at the moment of arming instead.
            setWatchdogWaitForTest([](std::unique_lock<std::mutex>&, std::stop_token, std::chrono::seconds,
                                      const std::function<bool()>& stoppedOrFinished) { return stoppedOrFinished(); });
        }
    }

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(m_announce));
        m_flags->started.store(true);
        if (m_cooperative) {
            while (!m_gate->isDone() && !isCancelled() && !token().isCancelled()) {
                std::this_thread::sleep_for(2ms);
            }
            if (m_afterCancel && isCancelled()) {
                m_afterCancel->wait();
            }
        } else {
            m_gate->wait();
        }
        finish(isCancelled() ? OperationStatus::Cancelled : OperationStatus::Ok, ErrorCode::None, "op.done", "done");
        m_flags->returned.store(true);
    }

private:
    std::shared_ptr<RunFlags> m_flags;
    std::shared_ptr<WaiterLatch> m_gate;
    std::shared_ptr<WaiterLatch> m_afterCancel;
    OperationPhase m_announce;
    bool m_cooperative;
};

[[nodiscard]] std::unique_ptr<OperationBase> makeProbe(const Rig& rig)
{
    return std::make_unique<ProbeOp>(rig.channel(), rig.state, rig.flags);
}

[[nodiscard]] std::unique_ptr<OperationBase> makeHeld(const Rig& rig, const std::shared_ptr<WaiterLatch>& gate)
{
    return std::make_unique<ParkedOp>(rig.channel(), rig.state, rig.flags, gate, OperationPhase::Connecting, false,
                                      false);
}

} // namespace

TEST(OperationManagerQueued, AnOperationOnAFreeReaderIsNeverQueued)
{
    OperationManager mgr;
    Rig rig;
    mgr.enqueueForTest(ObjectId{1}, makeProbe(rig));
    ASSERT_TRUE(waitUntil([&] { return rig.flags->returned.load(); }));
    EXPECT_EQ(rig.phaseCount(OperationPhase::Queued), 0u);
}

TEST(OperationManagerQueued, AnOperationBehindARunningOneReportsQueuedOnceBeforeItStarts)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig head;
    Rig behind;
    mgr.enqueueForTest(ObjectId{1}, makeHeld(head, gate));
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(behind));

    EXPECT_TRUE(behind.currentPhaseIs(OperationPhase::Queued)) << "reported while the reader is still busy";
    EXPECT_FALSE(behind.flags->started.load());
    EXPECT_EQ(behind.phaseCount(OperationPhase::Queued), 1u);

    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return behind.flags->returned.load(); }));
    const auto seen = behind.phases();
    ASSERT_FALSE(seen.empty());
    EXPECT_EQ(seen.front(), static_cast<std::uint32_t>(OperationPhase::Queued)) << "Queued comes before Connecting";
    EXPECT_EQ(behind.phaseCount(OperationPhase::Queued), 1u) << "emitted exactly once";
    EXPECT_EQ(behind.phaseCount(OperationPhase::Connecting), 1u);
}

TEST(OperationManagerQueued, AnOperationBehindTheBackgroundReadReportsQueued)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig background;
    Rig behind;
    mgr.setBackgroundForTest(ObjectId{1}, makeHeld(background, gate), std::chrono::steady_clock::duration::zero());
    ASSERT_TRUE(waitUntil([&] { return background.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(behind));

    EXPECT_TRUE(behind.currentPhaseIs(OperationPhase::Queued));
    EXPECT_FALSE(behind.flags->started.load());
    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return behind.flags->returned.load(); }));
}

TEST(OperationManagerQueued, AnOperationBehindTwoReportsQueued)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig head;
    Rig second;
    Rig third;
    mgr.enqueueForTest(ObjectId{1}, makeHeld(head, gate));
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(second));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(third));

    EXPECT_TRUE(second.currentPhaseIs(OperationPhase::Queued));
    EXPECT_TRUE(third.currentPhaseIs(OperationPhase::Queued));
    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return third.flags->returned.load(); }));
    EXPECT_EQ(third.phaseCount(OperationPhase::Queued), 1u);
}

TEST(OperationManagerQueued, AnotherReadersBusyWorkerDoesNotQueueThisReadersOperation)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig busy;
    Rig other;
    mgr.enqueueForTest(ObjectId{1}, makeHeld(busy, gate));
    ASSERT_TRUE(waitUntil([&] { return busy.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{2}, makeProbe(other));

    ASSERT_TRUE(waitUntil([&] { return other.flags->returned.load(); })) << "reader 2 starts at once";
    EXPECT_EQ(other.phaseCount(OperationPhase::Queued), 0u);
    EXPECT_FALSE(busy.flags->returned.load()) << "reader 1 was still held the whole time";
}

// --- Cancel and wedged-reader endings for a queued operation -------------------

namespace {

[[nodiscard]] bool completedAs(const Rig& rig, OperationStatus status, ErrorCode code)
{
    return rig.state->completed.load(std::memory_order_acquire) &&
           rig.state->terminalStatus.load(std::memory_order_acquire) == static_cast<std::uint32_t>(status) &&
           rig.state->terminalErrorCode.load(std::memory_order_acquire) == static_cast<std::uint32_t>(code);
}

[[nodiscard]] bool isComplete(const Rig& rig)
{
    return rig.state->completed.load(std::memory_order_acquire);
}

// Reports Reading (arming the watchdog) and parks ignoring cancel, with the
// watchdog firing at once: the reader's worker is wedged on an operation the
// agent has already given up on.
[[nodiscard]] std::unique_ptr<OperationBase> makeStuckReading(const Rig& rig, const std::shared_ptr<WaiterLatch>& gate)
{
    return std::make_unique<ParkedOp>(rig.channel(), rig.state, rig.flags, gate, OperationPhase::Reading, false, true);
}

} // namespace

TEST(OperationManagerQueued, CancellingAQueuedOperationEndsItAtOnceWhileTheReaderIsHeld)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig head;
    Rig behind;
    mgr.enqueueTrackedForTest(ObjectId{1}, makeHeld(head, gate), OperationId{1}, CallerToken{});
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load(); }));
    mgr.enqueueTrackedForTest(ObjectId{1}, makeProbe(behind), OperationId{2}, CallerToken{});
    ASSERT_TRUE(behind.currentPhaseIs(OperationPhase::Queued));

    mgr.cancel(OperationId{2});

    EXPECT_TRUE(completedAs(behind, OperationStatus::Cancelled, ErrorCode::None))
        << "ended without waiting for the operation ahead";
    EXPECT_FALSE(behind.flags->started.load()) << "it never ran";
    EXPECT_FALSE(mgr.isIdTrackedForTest(OperationId{2})) << "scrubbed from the id table";
    EXPECT_FALSE(isComplete(head)) << "the running operation is untouched";
    EXPECT_FALSE(head.state->cancelled.load());
    mgr.cancel(OperationId{2}); // a second cancel of the same id is a no-op
    mgr.cancel(OperationId{});  // so is an invalid id
    EXPECT_FALSE(isComplete(head));
}

TEST(OperationManagerQueued, CancellingTheRunningOperationOnlyAsksItToStop)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig head;
    Rig behind;
    mgr.enqueueTrackedForTest(ObjectId{1}, makeHeld(head, gate), OperationId{1}, CallerToken{});
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load(); }));
    mgr.enqueueTrackedForTest(ObjectId{1}, makeProbe(behind), OperationId{2}, CallerToken{});

    mgr.cancel(OperationId{1});

    EXPECT_TRUE(head.state->cancelled.load()) << "the cancel flag is tripped, as before";
    EXPECT_FALSE(isComplete(head)) << "it ends when its own doWork does";
    EXPECT_FALSE(isComplete(behind));
    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return behind.flags->returned.load(); }));
    EXPECT_TRUE(completedAs(head, OperationStatus::Cancelled, ErrorCode::None));
    EXPECT_TRUE(completedAs(behind, OperationStatus::Ok, ErrorCode::None));
}

TEST(OperationManagerQueued, AWedgedReadersQueuedOperationsEndAsWatchdogTimeoutOnTheSecondRound)
{
    OperationManager mgr;
    auto stuckGate = std::make_shared<WaiterLatch>();
    auto otherGate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{stuckGate, otherGate}};
    Rig stuck;
    Rig first;
    Rig second;
    Rig otherHead;
    Rig otherBehind;
    mgr.enqueueForTest(ObjectId{1}, makeStuckReading(stuck, stuckGate));
    ASSERT_TRUE(waitUntil([&] { return stuck.flags->started.load() && isComplete(stuck); }))
        << "the watchdog gave up on the operation that holds the reader";
    mgr.enqueueForTest(ObjectId{2}, makeHeld(otherHead, otherGate));
    ASSERT_TRUE(waitUntil([&] { return otherHead.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(first));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(second));
    mgr.enqueueForTest(ObjectId{2}, makeProbe(otherBehind));
    ASSERT_TRUE(first.currentPhaseIs(OperationPhase::Queued));

    mgr.drainWedgedQueuesForTest();
    EXPECT_FALSE(isComplete(first)) << "the first sighting only notes the wedged operation";

    mgr.drainWedgedQueuesForTest();
    EXPECT_TRUE(completedAs(first, OperationStatus::Error, ErrorCode::WatchdogTimeout));
    EXPECT_TRUE(completedAs(second, OperationStatus::Error, ErrorCode::WatchdogTimeout));
    EXPECT_FALSE(first.flags->started.load());

    Rig late;
    mgr.enqueueForTest(ObjectId{1}, makeProbe(late));
    ASSERT_TRUE(late.currentPhaseIs(OperationPhase::Queued)) << "the reader is still wedged: it is queued, not run";
    mgr.drainWedgedQueuesForTest();
    EXPECT_TRUE(completedAs(late, OperationStatus::Error, ErrorCode::WatchdogTimeout));

    EXPECT_FALSE(isComplete(otherBehind)) << "another reader's queue is not touched";
    EXPECT_TRUE(otherBehind.currentPhaseIs(OperationPhase::Queued));

    stuckGate->signal();
    ASSERT_TRUE(waitUntil([&] { return stuck.flags->returned.load(); }));
    otherGate->signal();
    ASSERT_TRUE(waitUntil([&] { return otherBehind.flags->returned.load(); }));
}

TEST(OperationManagerQueued, TheCleanupLoopEndsAWedgedReadersQueueWithinAFewSeconds)
{
    OperationManager mgr{nullptr}; // production: the cleanup loop runs
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig stuck;
    Rig behind;
    mgr.enqueueForTest(ObjectId{1}, makeStuckReading(stuck, gate));
    ASSERT_TRUE(waitUntil([&] { return stuck.flags->started.load() && isComplete(stuck); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(behind));
    ASSERT_TRUE(behind.currentPhaseIs(OperationPhase::Queued));

    EXPECT_TRUE(
        waitUntil([&] { return completedAs(behind, OperationStatus::Error, ErrorCode::WatchdogTimeout); }, 3000ms));
    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return stuck.flags->returned.load(); }));
}

TEST(OperationManagerQueued, AQueueBehindAnOperationTheWatchdogHasNotFiredOnIsLeftAlone)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig head;
    Rig behind;
    // Reading arms a 60 s watchdog that does not fire here.
    mgr.enqueueForTest(ObjectId{1}, std::make_unique<ParkedOp>(head.channel(), head.state, head.flags, gate,
                                                               OperationPhase::Reading, false, false));
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(behind));

    for (int round = 0; round < 3; ++round) {
        mgr.drainWedgedQueuesForTest();
    }
    EXPECT_FALSE(isComplete(behind));
    EXPECT_TRUE(behind.currentPhaseIs(OperationPhase::Queued));

    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return behind.flags->returned.load(); }));
    EXPECT_TRUE(completedAs(behind, OperationStatus::Ok, ErrorCode::None));
}

TEST(OperationManagerQueued, AnOperationAheadThatStopsOnItsOwnAfterTheWatchdogFiredDoesNotCostTheQueue)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    auto afterCancel = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate, afterCancel}};
    Rig head;
    Rig behind;
    // The watchdog fires at once and trips cancel; the op notices, then needs a
    // moment more to unwind (the second gate) before it returns.
    mgr.enqueueForTest(ObjectId{1}, std::make_unique<ParkedOp>(head.channel(), head.state, head.flags, gate,
                                                               OperationPhase::Reading, true, true, afterCancel));
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load() && isComplete(head); }));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(behind));
    ASSERT_TRUE(behind.currentPhaseIs(OperationPhase::Queued));

    mgr.drainWedgedQueuesForTest(); // first round: noted, nothing ended
    EXPECT_FALSE(isComplete(behind));

    afterCancel->signal(); // it unwinds and returns by itself
    ASSERT_TRUE(waitUntil([&] { return head.flags->returned.load(); }));
    ASSERT_TRUE(waitUntil([&] { return behind.flags->returned.load(); })) << "the worker went on to the queued op";
    mgr.drainWedgedQueuesForTest();
    EXPECT_TRUE(completedAs(behind, OperationStatus::Ok, ErrorCode::None)) << "it was run, not ended as timed out";
}

TEST(OperationManagerQueued, OnlyQueuedOperationsAreEndedAndAnInternalProbeStaysInOrder)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig stuck;
    Rig queued;
    std::mutex orderMutex;
    std::vector<int> order;
    const auto note = [&](int tag) {
        return [&order, &orderMutex, tag](CardSessionHolder&) {
            std::lock_guard lock(orderMutex);
            order.push_back(tag);
        };
    };
    mgr.enqueueForTest(ObjectId{1}, makeStuckReading(stuck, gate));
    ASSERT_TRUE(waitUntil([&] { return stuck.flags->started.load() && isComplete(stuck); }));
    mgr.enqueueHolderProbeForTest(ObjectId{1}, note(1));
    mgr.enqueueForTest(ObjectId{1}, makeProbe(queued));
    mgr.enqueueHolderProbeForTest(ObjectId{1}, note(2));
    ASSERT_TRUE(queued.currentPhaseIs(OperationPhase::Queued));

    mgr.drainWedgedQueuesForTest();
    mgr.drainWedgedQueuesForTest();
    EXPECT_TRUE(completedAs(queued, OperationStatus::Error, ErrorCode::WatchdogTimeout));
    {
        std::lock_guard lock(orderMutex);
        EXPECT_TRUE(order.empty()) << "the probes wait for the reader";
    }

    gate->signal();
    ASSERT_TRUE(waitUntil([&] {
        std::lock_guard lock(orderMutex);
        return order.size() == 2;
    }));
    std::lock_guard lock(orderMutex);
    EXPECT_EQ(order, (std::vector<int>{1, 2})) << "both probes ran, in the order they were queued";
}

// --- Card removal ends the waiting on that reader --------------------------------

namespace {

// Waits at a consent prompt until cancelled; the prompter-cancel callback is what
// dismisses the dialog.
class PromptWaitOp final : public OperationBase
{
public:
    PromptWaitOp(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state,
                 std::shared_ptr<RunFlags> flags, std::function<void()> dismissPrompt)
        : OperationBase(std::move(channel), std::move(state), std::move(dismissPrompt)), m_flags(std::move(flags))
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        m_flags->started.store(true);
        while (!isCancelled() && !token().isCancelled()) {
            std::this_thread::sleep_for(2ms);
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
        m_flags->returned.store(true);
    }

private:
    std::shared_ptr<RunFlags> m_flags;
};

} // namespace

TEST(OperationManagerCardRemoved, ARunningOperationAtAPromptIsCancelledAndThePromptDismissed)
{
    OperationManager mgr;
    Rig rig;
    std::atomic<int> dismissed{0};
    mgr.enqueueForTest(ObjectId{1}, std::make_unique<PromptWaitOp>(rig.channel(), rig.state, rig.flags,
                                                                   [&dismissed] { dismissed.fetch_add(1); }));
    ASSERT_TRUE(waitUntil([&] { return rig.flags->started.load(); }));

    releaseReaderOnCardRemoved(mgr, ObjectId{1});

    ASSERT_TRUE(waitUntil([&] { return rig.flags->returned.load(); })) << "the operation ended on the cancel";
    EXPECT_EQ(dismissed.load(), 1) << "the waiting prompt was dismissed exactly once";
}

// The prompt is dismissed over IPC in production, and publish and cancel take the
// worker's mutex on the bus thread: the dismissal must run with that mutex free.
// The callback does what the bus thread would: another thread enqueues on the
// same reader, and the callback waits (bounded) for that to finish while it is
// still running. Nothing in it blocks without a limit, so a dismissal under the
// mutex fails this test instead of hanging it.
TEST(OperationManagerCardRemoved, ThePromptIsDismissedWithTheReadersMutexFree)
{
    OperationManager mgr;
    Rig rig;
    Rig other;
    std::atomic<int> dismissed{0};
    std::atomic<bool> mutexWasFree{false};
    std::jthread enqueuer; // joined at scope end, after the callback is done
    mgr.enqueueForTest(ObjectId{1}, std::make_unique<PromptWaitOp>(rig.channel(), rig.state, rig.flags, [&] {
                           dismissed.fetch_add(1);
                           auto reached = std::make_shared<std::promise<void>>();
                           auto done = reached->get_future();
                           enqueuer = std::jthread([&mgr, &other, reached] {
                               mgr.enqueueForTest(ObjectId{1}, makeProbe(other));
                               reached->set_value();
                           });
                           mutexWasFree.store(done.wait_for(1s) == std::future_status::ready);
                       }));
    ASSERT_TRUE(waitUntil([&] { return rig.flags->started.load(); }));

    mgr.endOperationsOnCardRemoved(ObjectId{1});

    EXPECT_TRUE(mutexWasFree.load()) << "the dismissal ran while the reader's mutex was held";
    EXPECT_EQ(dismissed.load(), 1);
    ASSERT_TRUE(waitUntil([&] { return other.flags->returned.load(); }));
}

TEST(OperationManagerCardRemoved, QueuedOperationsEndAsCardRemovedAndAProbeStaysQueued)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate}};
    Rig head;
    Rig queued;
    std::atomic<bool> probeRan{false};
    mgr.enqueueForTest(ObjectId{1}, makeHeld(head, gate));
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load(); }));
    mgr.enqueueHolderProbeForTest(ObjectId{1}, [&probeRan](CardSessionHolder&) { probeRan.store(true); });
    mgr.enqueueForTest(ObjectId{1}, makeProbe(queued));
    ASSERT_TRUE(queued.currentPhaseIs(OperationPhase::Queued));

    mgr.endOperationsOnCardRemoved(ObjectId{1});

    EXPECT_TRUE(completedAs(queued, OperationStatus::Error, ErrorCode::CardRemoved));
    EXPECT_FALSE(queued.flags->started.load());
    EXPECT_TRUE(head.state->cancelled.load()) << "the running operation is asked to stop";
    EXPECT_FALSE(probeRan.load());
    gate->signal();
    ASSERT_TRUE(waitUntil([&] { return probeRan.load(); })) << "the internal probe was kept and runs after";
}

TEST(OperationManagerCardRemoved, AnotherReadersOperationsAreNotTouched)
{
    OperationManager mgr;
    auto gate = std::make_shared<WaiterLatch>();
    auto otherGate = std::make_shared<WaiterLatch>();
    LatchOpener opener{{gate, otherGate}};
    Rig head;
    Rig otherHead;
    Rig otherQueued;
    mgr.enqueueForTest(ObjectId{1}, makeHeld(head, gate));
    mgr.enqueueForTest(ObjectId{2}, makeHeld(otherHead, otherGate));
    ASSERT_TRUE(waitUntil([&] { return head.flags->started.load() && otherHead.flags->started.load(); }));
    mgr.enqueueForTest(ObjectId{2}, makeProbe(otherQueued));

    mgr.endOperationsOnCardRemoved(ObjectId{1});
    mgr.endOperationsOnCardRemoved(ObjectId{});

    EXPECT_FALSE(otherHead.state->cancelled.load());
    EXPECT_FALSE(isComplete(otherQueued));
    EXPECT_TRUE(otherQueued.currentPhaseIs(OperationPhase::Queued));
    otherGate->signal();
    ASSERT_TRUE(waitUntil([&] { return otherQueued.flags->returned.load(); }));
    EXPECT_TRUE(completedAs(otherQueued, OperationStatus::Ok, ErrorCode::None));
}
