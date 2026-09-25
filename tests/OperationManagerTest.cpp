// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Worker-scheduling test for OperationManager. Uses Fake operations
// (CountingOp) so the test focuses on per-reader serialisation +
// cross-reader parallelism + cleanup-grace timing.

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>

#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>

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
            return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
        });

    // First acquire on the worker thread: opens the session once and records the
    // handle. Synchronise on a flag the probe sets (no sleep-race).
    std::atomic<void*> firstSession{nullptr};
    std::atomic<bool> firstDone{false};
    mgr.enqueueHolderProbeForTest(ObjectId{1}, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
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
            return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
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
//
// This case deliberately keeps the DEFAULT secure-channel probe, which reads
// the held session's own hasLiveSecureChannel(). No session is opened here,
// and a detached one carries no channel either, so the probe answers false and
// the hold is taken exactly as it always was: the skip added for live channels
// does not change what this case asserts.
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

// The assertion an earlier draft of this feature could not make: with a hold in place the
// LOGICAL session still idle-closes (secrets stay bounded by kIdleClose) while
// the hold survives. Deterministic through two seams: a short worker sweep and
// a fake holder clock.
TEST(OperationManager, HoldDoesNotBlockIdleClose)
{
    // The fake clock is called by the worker at EVERY sweep until the manager
    // joins it, so it must be declared before the manager (destroyed after).
    std::atomic<int> opens{0};
    std::atomic<std::int64_t> nowNs{0};
    OperationManager mgr;
    installCountingFactory(mgr, opens);
    mgr.setIdleSweepForTest(20ms);
    mgr.setHolderClockForTest(
        [&nowNs] { return std::chrono::steady_clock::time_point{std::chrono::nanoseconds{nowNs.load()}}; });

    // Logical session opened by a probe; keep the AcquiredCard alive so the
    // session object cannot be freed and its address reused by the re-open.
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
    ASSERT_EQ(held.load(), 1);

    // Past the idle window on the fake clock; let several sweeps run.
    nowNs.store(std::chrono::duration_cast<std::chrono::nanoseconds>(CardSessionHolder::kIdleClose + 1s).count());

    // Poll (bounded to 2 s) rather than sleep a fixed window: the worker needs
    // at least one 20 ms sweep, and a descheduled runner can miss a fixed
    // wait. held must stay 1 on every sweep; stop as soon as the session
    // changes. second starts equal to first (no change observed yet) so the
    // loop condition holds for the first pass.
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> second = first;
    const auto pollStart = std::chrono::steady_clock::now();
    while (second == first && std::chrono::steady_clock::now() - pollStart < 2s) {
        // Sleep BEFORE probing: acquire() stamps the idle clock on every call,
        // even a reused session, so touching the holder before the worker's
        // wait_for has had a genuine 20 ms idle gap would erase the staleness
        // the sweep is looking for. 25 ms comfortably clears that window.
        std::this_thread::sleep_for(25ms);
        probeOnWorker(mgr, [&](CardSessionHolder& h) {
            held.store(h.hasHoldForTest() ? 1 : 0);
            auto b = h.acquire();
            if (b) {
                second = b->session;
            }
        });
        EXPECT_EQ(held.load(), 1) << "the hold survived every sweep";
    }

    ASSERT_NE(second, nullptr);
    EXPECT_NE(second, first) << "the logical session was idle-closed and re-opened despite the hold";
    EXPECT_EQ(held.load(), 1) << "the hold survived the idle sweeps";
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

// The sweep keeps R4 order (release -> acquire -> close-if-idle), so a session
// that is about to be idle-closed is held FIRST: the live secure channel does
// not suppress the hold once that session has stopped being used, and the
// handle-free window stays the one the power hold was measured against.
TEST(OperationManager, SweepWithLiveSmAndIdleSessionTakesHoldThenCloses)
{
    std::atomic<int> opens{0};
    FakeHolderClock clock;
    OperationManager mgr;
    installCountingFactory(mgr, opens);
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());
    mgr.setHolderSmProbeForTest([](const LibreSCRS::SmartCard::CardSession&) { return true; });

    // Hold requested with no session yet: nothing to skip, so it is taken.
    probeOnWorker(mgr, [](CardSessionHolder&) {}); // materialise the worker
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    ASSERT_EQ(held.load(), 1);

    // Now a logical session, which this reader's probe reports as carrying a
    // live secure channel. Keep the AcquiredCard's session alive so its
    // address cannot be reused by the re-open below.
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> first;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            first = a->session;
        }
    });
    ASSERT_NE(first, nullptr);

    // Past the idle window, then exactly one sweep.
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
    EXPECT_EQ(held.load(), 1) << "the idle session was held before it was closed";
    ASSERT_NE(second, nullptr);
    EXPECT_NE(second, first) << "the logical session was idle-closed and the next acquire re-opened it";
}

// The other half of the same predicate: while that session is still ACTIVE the
// sweep leaves the reader alone — no second handle on a card that is already
// powered and mid-channel.
TEST(OperationManager, SweepWithLiveSmAndActiveSessionTakesNoHold)
{
    std::atomic<int> opens{0};
    FakeHolderClock clock;
    OperationManager mgr;
    installCountingFactory(mgr, opens);
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());
    mgr.setHolderSmProbeForTest([](const LibreSCRS::SmartCard::CardSession&) { return true; });

    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    ASSERT_EQ(held.load(), 1);

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> first;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        auto a = h.acquire();
        if (a) {
            first = a->session;
        }
    });
    ASSERT_NE(first, nullptr);

    // Well inside the idle window, then exactly one sweep.
    clock.advance(5s);
    std::this_thread::sleep_for(kAfterOneSweep);

    std::shared_ptr<LibreSCRS::SmartCard::CardSession> second;
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held.store(h.hasHoldForTest() ? 1 : 0);
        auto b = h.acquire();
        if (b) {
            second = b->session;
        }
    });
    EXPECT_EQ(held.load(), 0) << "the sweep released the hold and did not renew it under a live channel";
    EXPECT_EQ(second, first) << "the logical session was not idle-closed";
}

// The host's own route into the same predicate: setReaderHold applies through
// the worker's hold-changed branch, not the sweep. A hold asked for while the
// session is active with a live channel is not taken THEN — it is taken by the
// first sweep in which that session goes idle.
TEST(OperationManager, HoldRequestedDuringLiveSmSessionIsAppliedAtIdle)
{
    std::atomic<int> opens{0};
    FakeHolderClock clock;
    OperationManager mgr;
    installCountingFactory(mgr, opens);
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());
    mgr.setHolderSmProbeForTest([](const LibreSCRS::SmartCard::CardSession&) { return true; });

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
    EXPECT_EQ(held.load(), 0) << "the requested hold is not taken under a live channel on an active session";
    EXPECT_TRUE(mgr.isReaderHeldForTest(ObjectId{1})) << "the request itself stands; only the handle waits";

    clock.advance(CardSessionHolder::kIdleClose);
    std::this_thread::sleep_for(kAfterOneSweep);

    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    EXPECT_EQ(held.load(), 1) << "the first sweep with that session idle takes the hold";
}

namespace {

// Counts the sessions the holder is holding RIGHT NOW, and the fewest it ever
// held while both a logical session and a power hold were live.
//
// The factory is injected, so a test can own what it hands out: each session
// goes back wrapped in an aliasing shared_ptr whose control block runs a
// release hook. The holder's own reset() is therefore the event that decrements
// the count, which makes the count the number of PC/SC handles the reader
// carries -- the quantity the sweep's order exists to protect.
class HandleCensus
{
public:
    SessionFactory factory()
    {
        return
            [this](const std::string& r)
                -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
                auto owner = std::make_shared<Owned>(LibreSCRS::SmartCard::detail::makeDetachedCardSession(r), this);
                {
                    const std::lock_guard lock(m_mutex);
                    ++m_live;
                    ++m_opens;
                }
                return std::shared_ptr<LibreSCRS::SmartCard::CardSession>{owner, owner->session.get()};
            };
    }

    // Start watching from this many live handles. Called once both the logical
    // session and the hold are up, so the floor below is about the sweep and
    // not about the way there.
    void arm()
    {
        const std::lock_guard lock(m_mutex);
        m_armed = true;
        m_floor = m_live;
    }
    [[nodiscard]] int floorWhileArmed() const
    {
        const std::lock_guard lock(m_mutex);
        return m_floor;
    }
    [[nodiscard]] int opens() const
    {
        const std::lock_guard lock(m_mutex);
        return m_opens;
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
        --m_live;
        if (m_armed && m_live < m_floor) {
            m_floor = m_live;
        }
    }

    mutable std::mutex m_mutex;
    int m_live = 0;
    int m_opens = 0;
    int m_floor = 0;
    bool m_armed = false;
};

} // namespace

// R4: the sweep renews the hold BEFORE it idle-closes the logical session, so
// the reader is never left with no handle at all. Neither hasHoldForTest() nor
// an open count can see that: with the order reversed the hold is still taken
// (by then there is no session for the predicate to skip on) and the factory is
// still called once. What distinguishes the two is the FLOOR -- how few handles
// the reader carried at the worst moment of the sweep. Under R4 the logical
// session is still standing when the new hold opens, so the floor is 1; close
// first and it is 0.
TEST(OperationManager, SweepRenewsTheHoldBeforeItClosesTheIdleSession)
{
    HandleCensus census;
    FakeHolderClock clock;
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kSweepPeriod);
    mgr.setHolderClockForTest(clock.fn());
    mgr.setHolderSmProbeForTest([](const LibreSCRS::SmartCard::CardSession&) { return true; });

    probeOnWorker(mgr, [](CardSessionHolder&) {}); // materialise the worker
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    ASSERT_EQ(held.load(), 1);

    // A logical session too, and NOT retained: an AcquiredCard kept alive here
    // would hold the session open through the sweep and hide the very drop this
    // case is about.
    probeOnWorker(mgr, [](CardSessionHolder& h) { (void)h.acquire(); });
    ASSERT_EQ(census.opens(), 2) << "one logical session and one hold";

    census.arm();
    clock.advance(CardSessionHolder::kIdleClose);
    std::this_thread::sleep_for(kAfterOneSweep);

    std::atomic<int> reopened{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held.store(h.hasHoldForTest() ? 1 : 0);
        reopened.store(h.acquire().has_value() ? 1 : 0);
    });

    // The sweep ran and did its two jobs: it renewed the hold (a third open)
    // and it closed the idle session (a fourth open, for the probe above).
    // Without this the floor assertion could pass on a sweep that never fired.
    ASSERT_EQ(census.opens(), 4) << "the sweep renewed the hold and the session was closed and re-opened";
    ASSERT_EQ(held.load(), 1);
    ASSERT_EQ(reopened.load(), 1);

    EXPECT_GE(census.floorWhileArmed(), 1) << "the reader carried at least one handle at every point of the sweep";
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

// One sweep, one instant. The hold skip asks "< kIdleClose" and the idle close
// asks ">= kIdleClose": complementary tests, so against a SINGLE reading of the
// clock exactly one of them fires. Read the clock twice and the boundary can
// fall in between -- the skip sees a session still in use and declines the
// hold, then the close sees the same session idle and drops it, and the reader
// is left with no handle at all until the next sweep.
//
// Every entry of the script below is spent where the comments say, and the
// count is asserted: the script is one entry longer than an earlier version of
// this case, which had the sweep land on entries that straddled nothing and
// passed with the clock read twice.
//
//   read 1  0 ms       acquireHold() on the hold-changed branch. It reads the
//                      clock BEFORE it can know whether there is a session to
//                      skip on, so this entry is spent here, not by acquire().
//   read 2  0 ms       acquire() -> the session's last-used stamp is 0 ms.
//   read 3  44'999 ms  the sweep. One read: the session is 44'999 ms old, so it
//                      is still in use -- no hold, and no close.
//   read 4  45'000 ms  spent ONLY if the sweep reads the clock a second time,
//                      and then it says the same session is idle -> closed,
//                      with the hold already declined. Zero handles.
TEST(OperationManager, SweepDecidesTheHoldAndTheIdleCloseOnOneInstant)
{
    // A wider period than the other sweep cases use: this one must observe the
    // state after EXACTLY one sweep, so the quiet stretch between the first and
    // the second has to be wide enough to probe in without racing.
    constexpr auto kWidePeriod = 500ms;
    constexpr auto kAfterOneWideSweep = 750ms;

    HandleCensus census;
    ScriptedClock clock{{0ms, 0ms, 44'999ms, 45'000ms}};
    OperationManager mgr;
    mgr.setSessionFactoryForTest(census.factory());
    mgr.setIdleSweepForTest(kWidePeriod);
    mgr.setHolderClockForTest(clock.fn());
    mgr.setHolderSmProbeForTest([](const LibreSCRS::SmartCard::CardSession&) { return true; });

    // The hold first, while there is no session yet: nothing for the skip to
    // decline, so it is taken. This is read 1.
    probeOnWorker(mgr, [](CardSessionHolder&) {});
    mgr.setReaderHold(ObjectId{1}, true);
    std::atomic<int> held{-1};
    probeOnWorker(mgr, [&](CardSessionHolder& h) { held.store(h.hasHoldForTest() ? 1 : 0); });
    ASSERT_EQ(held.load(), 1);
    ASSERT_EQ(clock.reads(), 1U) << "the hold spent the first entry";

    // Then the logical session, not retained: an AcquiredCard kept alive here
    // would hold it open through the sweep. This is read 2, and it stamps the
    // session's last-used time at 0 ms.
    probeOnWorker(mgr, [](CardSessionHolder& h) { (void)h.acquire(); });
    ASSERT_EQ(census.opens(), 2) << "one hold and one logical session";
    ASSERT_EQ(clock.reads(), 2U);

    census.arm();
    std::this_thread::sleep_for(kAfterOneWideSweep);

    std::atomic<std::size_t> readsAfterSweep{0};
    std::atomic<int> opensBefore{0};
    std::atomic<int> opensAfter{0};
    probeOnWorker(mgr, [&](CardSessionHolder& h) {
        held.store(h.hasHoldForTest() ? 1 : 0);
        readsAfterSweep.store(clock.reads());
        opensBefore.store(census.opens());
        // Re-opens if and only if the sweep closed the session.
        (void)h.acquire();
        opensAfter.store(census.opens());
    });

    EXPECT_EQ(readsAfterSweep.load(), 3U) << "one sweep, and it read the clock once";
    EXPECT_EQ(held.load(), 0) << "at 44'999 ms the session is still in use, so the hold is declined";
    EXPECT_EQ(opensAfter.load(), opensBefore.load()) << "and the same instant says it is not idle, so it is not closed";
    EXPECT_GE(census.floorWhileArmed(), 1) << "so the reader was never left without a handle";
}
