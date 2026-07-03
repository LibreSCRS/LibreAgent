// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

namespace {

// The typed Operation1 + sub-interface adaptors (Identity/Photo/Certificates/
// Sign) and their per-op factory recipes moved to the Linux backend
// (dbus/OperationAdaptorFactory) — the neutral scheduler no longer constructs
// any backend adaptor. The per-reader backlog cap now surfaces the neutral
// QueueFull (OperationManager.h); the backend maps it to the RateLimited wire
// error. enqueueOnReaderWorker (below) still references kMaxQueuedOpsPerReader
// and returns false on a full queue.

// Production SessionFactory body: open the LM CardSession for @p reader once and
// wrap it in a shared_ptr. The shared owner is what the holder reuses across the
// reader's ops so a PACE-established secure channel survives. Hoisted out of the
// workerFor lambda so the open-then-make_shared logic has a name.
std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError>
openReaderSession(const std::string& reader)
{
    auto opened = LibreSCRS::SmartCard::CardSession::open(reader);
    if (!opened) {
        return std::unexpected{opened.error()};
    }
    return std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
}

} // namespace

OperationManager::OperationManager() = default;

OperationManager::OperationManager(CapabilityResolver* resolver)
    : m_production(true), m_resolver(resolver),
      m_cleanupWorker([this](std::stop_token st) { cleanupLoop(std::move(st)); })
{}

OperationManager::~OperationManager()
{
    // Move every live worker out under the lock, then tear each down via
    // abandonOrJoin OUTSIDE the lock (abandonOrJoin re-takes m_workersMutex
    // when it parks a wedged worker on the zombie list). Non-wedged workers
    // are joined; workers wedged in a non-cooperating doWork() are detached
    // to the never-joined zombie list so the dtor — and the bus thread —
    // never blocks on an uncancellable card call.
    std::vector<std::shared_ptr<ReaderWorker>> live;
    {
        std::lock_guard lock(m_workersMutex);
        for (auto& [_, w] : m_workers) {
            if (w) {
                live.push_back(std::move(w));
            }
        }
        m_workers.clear();
    }
    for (auto& w : live) {
        abandonOrJoin(std::move(w));
    }
    // Any zombie storage (detached threads still referencing their
    // ReaderWorker's queue/mutex/cv + the in-flight op on their stack) must
    // outlive THIS object: destroying m_zombies here would free storage out
    // from under a still-running detached thread (UAF). Hand the storage to
    // a never-destroyed process-lifetime sink so it lives until exit
    // independent of the manager — this is the "tolerate the leaked
    // thread+storage until exit" contract (the udisksd LUKS-wedge pattern).
    // SECURITY (accepted risk, decision 2026-07-03): a wedged holder may keep
    // live SM/PACE session keys resident until daemon exit — they are
    // intentionally NOT force-scrubbed. The blocked SCardTransmit is
    // uncancellable on Linux and may still read the channel buffers, so
    // scrubbing memory a blocked consumer can touch is a use-after-scrub
    // hazard with no safe synchronization point. Exposure is bounded:
    // same-user model, PR_SET_DUMPABLE=0 (no dump/attach), no PIN retained,
    // card removal revokes the lease. Revisit only if a key-lifecycle model
    // with quiesce semantics makes the scrub provably safe.
    if (!m_zombies.empty()) {
        // Function-local static with intentionally-never-run destructor: a
        // leaked container guaranteed to outlive every detached thread.
        static auto* const leakedZombies = new std::vector<std::shared_ptr<ReaderWorker>>();
        std::lock_guard lock(m_workersMutex);
        for (auto& z : m_zombies) {
            leakedZombies->push_back(std::move(z));
        }
        m_zombies.clear();
    }
    // The cleanup-grace jthread member joins normally (it polls a
    // stop_token and never makes uncancellable calls).
}

OperationId OperationManager::nextOperationId()
{
    return OperationId{m_counter.fetch_add(1) + 1}; // +1: 0 is reserved for "none"
}

std::shared_ptr<OperationManager::ReaderWorker> OperationManager::workerFor(ObjectId reader,
                                                                            const std::string& readerName)
{
    std::lock_guard lock(m_workersMutex);
    auto it = m_workers.find(reader);
    if (it == m_workers.end()) {
        auto worker = std::make_shared<ReaderWorker>();
        // Build the per-reader shared-session holder. The SessionFactory opens
        // the LM CardSession once for this reader and wraps it in a shared_ptr
        // (or a test-supplied override yields a detached session); the
        // CandidateResolver forwards to the agent's plugin resolver (or yields
        // an empty list when no resolver was provided — the test path). The
        // holder lives on the worker and is touched ONLY on the worker thread
        // (via each op's Deps.holder pointer).
        CapabilityResolver* resolver = m_resolver;
        SessionFactory factory = m_testSessionFactory ? m_testSessionFactory : SessionFactory{&openReaderSession};
        worker->holder = std::make_unique<CardSessionHolder>(
            readerName, std::move(factory),
            [resolver](std::span<const std::uint8_t> atr, LibreSCRS::SmartCard::CardSession& s) -> CandidateList {
                if (!resolver) {
                    return {};
                }
                return resolver->resolveCandidates(atr, s);
            },
            std::make_shared<LibreSCRS::SmartCard::CardMap>());
        auto* raw = worker.get();
        raw->worker = std::jthread([this, raw](std::stop_token st) { workerLoop(*raw, std::move(st)); });
        it = m_workers.emplace(reader, std::move(worker)).first;
    }
    // Return a shared_ptr COPY: the caller touches the worker after we release
    // m_workersMutex, so a concurrent removeReader must not free it underneath.
    return it->second;
}

void OperationManager::workerLoop(ReaderWorker& worker, std::stop_token st)
{
    while (!st.stop_requested()) {
        std::unique_lock lock(worker.mutex);
        // Wake on a queued op, a pending session-invalidate, stop, or the idle
        // sweep deadline. The invalidate is honoured BETWEEN ops (here, with no
        // op in flight) so a live AcquiredCard is never pulled out from under a
        // running doWork(). The bounded wait caps a quiescent reader's sleep at
        // kIdleClose so an idle held session is proactively closed even with no
        // queue traffic and no events; a real op / invalidate / stop still wins
        // and is handled promptly. wait_for returns false only on timeout.
        const bool ready = worker.cv.wait_for(lock, st, CardSessionHolder::kIdleClose, [&] {
            return !worker.queue.empty() || worker.pendingInvalidate || st.stop_requested();
        });
        if (st.stop_requested()) {
            break;
        }
        if (!ready) {
            // Timed out with an empty queue and no pending invalidate: close the
            // shared CardSession if it has been idle long enough. closeIfIdle is
            // touched ONLY on this (the worker) thread, like the holder's other
            // methods. The lock guards the queue/flags, not the holder.
            lock.unlock();
            if (worker.holder) {
                worker.holder->closeIfIdle(); // noexcept
            }
            continue;
        }
        // Process a pending session-invalidate before touching the queue: close
        // the shared CardSession on this (the only) thread allowed to touch the
        // holder, then re-loop so the next op re-opens + re-resolves candidates.
        if (worker.pendingInvalidate) {
            worker.pendingInvalidate = false;
            lock.unlock();
            if (worker.holder) {
                worker.holder->invalidate(); // noexcept
            }
            continue;
        }
        auto op = std::move(worker.queue.front());
        worker.queue.pop_front();
        worker.inFlight = op.get();
        lock.unlock();

        op->runOnWorker();

        {
            std::lock_guard inflightLock(worker.mutex);
            worker.inFlight = nullptr;
        }

        if (worker.abandoned.load(std::memory_order_acquire)) {
            // This worker was detached + parked on the zombie list while it
            // was wedged in this op's doWork(). The op has already been
            // driven to a terminal state by the per-op watchdog. The owning
            // OperationManager may have been destroyed in the meantime, so
            // do NOT touch m_finished / m_production (cleanup-grace re-export is
            // moot for an abandoned reader).
            //
            // quiesce() the op FIRST (as the normal path does at the loop
            // bottom, which the abandon branch used to skip): it stops + joins
            // the per-op watchdog + throttler on THIS (the zombie worker) thread.
            // Without it a still-armed watchdog could fire finishWatchdogTimeout()
            // -> finish() -> m_channel->emitFinished() after the backend has been
            // torn down; joining it here means it can never touch the channel
            // post-teardown (the emit is additionally shutdown-gated in finish()).
            // quiesce() joins a DIFFERENT thread (the watchdog), never self-joins,
            // and touches only the op's own members, so it is safe even though the
            // manager may be gone. Then drop the op and exit the loop without
            // running the drain over (an already-empty) queue.
            op->quiesce();
            op.reset();
            return;
        }

        // Reclaim the op's per-op auxiliary threads now that it is terminal,
        // BEFORE it enters the 5 s cleanup-grace queue. Otherwise a burst of
        // fast operations parks hundreds of idle jthreads in the grace window
        // (each finished op holding its throttler + watchdog thread until
        // destruction), exhausting threads and wedging the single bus event
        // loop. The op object stays exported for the grace; only its now-idle
        // threads are reclaimed here, on the worker thread.
        op->quiesce();

        if (m_production) {
            // Production: hand to cleanup-grace queue. The op + its adaptor
            // stay exported on the bus for 5 s so late client reads still
            // see the terminal phase/progress before unexport.
            std::lock_guard finLock(m_finishedMutex);
            m_finished.push_back({std::move(op), std::chrono::steady_clock::now()});
        }
        // Test mode (no bus, no cleanup thread): the op's destructor fires
        // here as the unique_ptr leaves scope; the test's adaptor capture
        // has already recorded the finish.
    }
    // Drain: queued ops on shutdown get finishCardRemoved() so they
    // terminate with errorCode=CardRemoved instead of vanilla Cancelled
    // (distinguishes reader-removal from client-cancel for diagnostics).
    // This drain is reached ONLY on the cooperative-exit (join) path — the
    // abandoned (detached) worker short-circuits and returns above, so `this`
    // (the manager) is guaranteed alive here (abandonOrJoin / ~OperationManager
    // blocks on the join). Scrub each queued op from the tracking tables BEFORE
    // it is destroyed so no stale OperationBase* survives in m_byId /
    // m_senderToOps for a concurrent cancel / dispatchClientDisconnect
    // (the backend event-loop thread) to deref: the destructive teardown runs on the
    // PC/SC monitor thread, with nothing serialising it against the bus thread,
    // so the scrub MUST precede the free, not merely happen eventually.
    //
    // Move the queue out under worker.mutex first: after the move this thread
    // (the worker itself, on its own stop-exit path — no concurrent pop) solely
    // owns the doomed ops in a local deque. forgetOp* takes
    // m_pathMutex/m_sendersMutex and must never run under worker.mutex, so the
    // mutex is released before scrubbing. Scrub each op by id while it is STILL
    // ALIVE in the local deque; only then finish + destroy the ops. After the
    // scrub a concurrent cancel finds nothing → safe no-op.
    std::deque<std::unique_ptr<OperationBase>> doomed;
    {
        std::lock_guard lock(worker.mutex);
        doomed = std::move(worker.queue);
        worker.queue.clear(); // leave the moved-from deque well-defined + empty
    }
    for (const auto& op : doomed) {
        forgetOpById(op->id()); // scrub while the op is still alive, off the worker mutex
    }
    for (auto& op : doomed) {
        op->finishCardRemoved(); // drive each to its CardRemoved terminal
    }
    doomed.clear(); // destroys the ops AFTER the tables are scrubbed
}

void OperationManager::setSessionFactoryForTest(SessionFactory factory)
{
    m_testSessionFactory = std::move(factory);
}

void OperationManager::invalidateReaderSession(ObjectId reader)
{
    // Lock order: m_workersMutex FIRST, then briefly w.mutex — never the
    // reverse anywhere. Notify AFTER releasing w.mutex but BEFORE releasing
    // m_workersMutex: the worker storage is only ever moved out / destroyed by
    // removeReader, which also takes m_workersMutex, so holding it here keeps
    // the worker reference alive across notify. (Releasing m_workersMutex before
    // the notify would race removeReader and risk a use-after-free, so the
    // optional "notify outside m_workersMutex" micro-opt is intentionally not
    // applied.)
    std::lock_guard wl(m_workersMutex);
    auto it = m_workers.find(reader);
    if (it == m_workers.end() || !it->second) {
        return; // no worker yet => nothing held to invalidate
    }
    auto& w = *it->second;
    {
        std::lock_guard l(w.mutex);
        w.pendingInvalidate = true;
    }
    w.cv.notify_all();
}

void OperationManager::enqueueForTest(ObjectId reader, std::unique_ptr<OperationBase> op)
{
    // The test supplies a fully-built op (which already carries its own holder,
    // if any), so no holder needs to be stamped here; an empty reader name is
    // fine for the lazily-created worker's holder, which goes unused.
    auto worker = workerFor(reader, std::string{});
    std::lock_guard lock(worker->mutex);
    worker->queue.push_back(std::move(op));
    worker->cv.notify_one();
}

void OperationManager::enqueueTrackedForTest(ObjectId reader, std::unique_ptr<OperationBase> op, OperationId id,
                                             const CallerToken& sender)
{
    auto worker = workerFor(reader, std::string{});
    op->setId(id);
    if (!sender.empty()) {
        recordSender(id, sender);
    }
    {
        std::lock_guard pathLock(m_pathMutex);
        m_byId.emplace(id, op.get());
    }
    std::lock_guard lock(worker->mutex);
    worker->queue.push_back(std::move(op));
    worker->cv.notify_one();
}

namespace {

class SyncProbeChannel final : public OperationChannel
{
public:
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus, ErrorCode, std::string_view, std::string_view) noexcept override {}
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }
};

// Runs @p fn on the reader's worker thread with the reader's holder; the bridge
// for the deferred-async PKCS#11 hop (enqueueOnReaderWorker). The op OWNS the
// work closure (moved in), it does NOT borrow the caller's: enqueueOnReaderWorker
// returns the bus thread IMMEDIATELY while this op is still queued or mid-doWork
// on the worker, so the closure (and its by-value / shared_ptr captures, incl.
// the deferred D-Bus reply) must outlive that return. Owning it keeps it alive
// for as long as the op lives. If the op is torn down without running (reader
// removed, or wedged-worker abandon), the closure is destroyed and the captured
// reply's fail-closed destructor sends the error. Never throws out of doWork.
class SyncProbeOp final : public OperationBase
{
public:
    SyncProbeOp(CardSessionHolder* holder, std::function<void(CardSessionHolder&)> fn)
        : OperationBase(std::make_unique<SyncProbeChannel>(), std::make_shared<OperationState>()), m_holder(holder),
          m_fn(std::move(fn))
    {}

protected:
    void doWork() override
    {
        if (m_holder && m_fn) {
            m_fn(*m_holder);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "ok", "ok");
    }

private:
    CardSessionHolder* m_holder;
    std::function<void(CardSessionHolder&)> m_fn;
};

} // namespace

// Test-only entrypoint: runs a probe on the worker thread with the worker's
// holder, letting a bus-less test drive a worker-thread holder->acquire()
// without a real PC/SC reader. Reuses the production SyncProbeOp (identical
// behavior — owns the moved-in closure, runs it on the worker, then finishes).
void OperationManager::enqueueHolderProbeForTest(ObjectId reader, std::function<void(CardSessionHolder&)> probe)
{
    auto worker = workerFor(reader, std::string{});
    auto op = std::make_unique<SyncProbeOp>(worker->holder.get(), std::move(probe));
    std::lock_guard lock(worker->mutex);
    worker->queue.push_back(std::move(op));
    worker->cv.notify_one();
}

bool OperationManager::enqueueOnReaderWorker(ObjectId reader, const std::string& readerName,
                                             std::function<void(CardSessionHolder&)> fn)
{
    if (!m_production) {
        throw std::runtime_error{"enqueueOnReaderWorker requires the production ctor"};
    }
    // Queue @p fn on the reader's worker and return the (bus dispatch) thread
    // IMMEDIATELY — no wait. @p fn
    // captures the deferred D-Bus reply and fulfils it ON THE WORKER THREAD when
    // the card op completes; if the op is torn down without running (reader
    // removed -> finishCardRemoved, or wedged-worker abandon), the closure (and
    // thus the captured reply) is destroyed and the reply's fail-closed
    // destructor sends the error. This frees the single bus event loop for the
    // whole in-flight op duration so concurrent clients (and SIGTERM) are never
    // stalled — the topology the enqueue* read paths already use.
    //
    // Pass the REAL reader name: workerFor only consults it when CREATING
    // the worker, so a first-touch async op does not build the cached holder with
    // an empty name (which would fail every CardSession::open on it).
    auto worker = workerFor(reader, readerName);
    // Backpressure: reject (the caller maps false to a retryable rate-limited
    // error) before building the op so a flooding client cannot spawn unbounded
    // per-reader queue depth. Checked under the worker mutex that guards the queue
    // — the same cap + discipline as the enqueue* read paths.
    auto op = std::make_unique<SyncProbeOp>(worker->holder.get(), std::move(fn));
    {
        std::lock_guard lock(worker->mutex);
        if (worker->queue.size() >= kMaxQueuedOpsPerReader) {
            return false;
        }
        worker->queue.push_back(std::move(op));
        worker->cv.notify_one();
    }
    return true;
}

void OperationManager::cancel(OperationId id)
{
    std::lock_guard lock(m_pathMutex);
    auto it = m_byId.find(id);
    if (it == m_byId.end()) {
        return;
    }
    if (it->second) {
        it->second->requestCancel();
    }
}

void OperationManager::removeReader(ObjectId reader)
{
    std::shared_ptr<ReaderWorker> worker;
    {
        std::lock_guard lock(m_workersMutex);
        auto it = m_workers.find(reader);
        if (it == m_workers.end()) {
            return;
        }
        worker = std::move(it->second);
        m_workers.erase(it);
    }
    // abandonOrJoin stops + drains the worker and either joins it (when it
    // can exit promptly) or detaches it to the never-joined zombie list
    // (when it is wedged in a non-cooperating doWork()). Either way this
    // call — and therefore removeReader / the bus thread — never blocks on
    // an uncancellable card call. A subsequent enqueue for this reader
    // lazily spins a fresh worker via workerFor.
    abandonOrJoin(std::move(worker));
}

void OperationManager::abandonOrJoin(std::shared_ptr<ReaderWorker> worker) noexcept
{
    if (!worker) {
        return;
    }
    worker->worker.request_stop();
    OperationBase* inFlight = nullptr;
    std::deque<std::unique_ptr<OperationBase>> doomed;
    {
        std::lock_guard lk(worker->mutex);
        // Drain the queued ops synchronously HERE (not via the worker's own
        // exit-path drain) so CardRemoved semantics are guaranteed
        // regardless of whether we go on to join or detach the worker — a
        // detached worker's loop short-circuits on `abandoned` and never
        // reaches its own drain. finishCardRemoved is idempotent (once_flag),
        // so the worker's residual drain over the now-empty queue is a no-op.
        //
        // MOVE the queued ops out under worker->mutex so ONLY this thread owns
        // them afterwards: the worker has already been removed from m_workers
        // (no new enqueues), and it is either wedged in doWork() (not touching
        // the queue) or parked in cv.wait — neither pops the queue, and the
        // detached-worker exit path (workerLoop) only ever drains a queue it
        // owns, which after this move is empty. So no other thread can free or
        // pop these ops during the brief gap where worker->mutex is released for
        // the scrub. This removes the destroy-then-scrub UAF window entirely
        // (forgetOp* must never run under worker->mutex — it takes
        // m_pathMutex/m_sendersMutex).
        doomed = std::move(worker->queue);
        worker->queue.clear(); // leave the moved-from deque well-defined + empty
        // Trip the cancel on the in-flight op (if any) so a cooperating
        // doWork() that polls isCancelled() / token().isCancelled() exits
        // promptly.
        inFlight = worker->inFlight;
        if (inFlight) {
            inFlight->requestCancel();
        }
        worker->cv.notify_all();
    }
    // Scrub the doomed ops from the tracking tables BEFORE freeing them, off the
    // worker mutex, while they are STILL ALIVE in the local deque. A concurrent
    // cancel / dispatchClientDisconnect (the backend event-loop thread) then finds
    // nothing in m_byId / m_senderToOps → safe no-op, with no window where the
    // table points at a freed op.
    for (const auto& op : doomed) {
        forgetOpById(op->id());
    }
    for (auto& op : doomed) {
        op->finishCardRemoved(); // drive each to its CardRemoved terminal
    }
    doomed.clear(); // destroys the ops AFTER the tables are scrubbed

    // Bounded grace: give a cooperating in-flight op a short window to wind
    // down after the cancel so we can JOIN it cleanly (no thread leak). A
    // non-cooperating op parked in an uncancellable call (SCardTransmit on
    // Linux) never returns within the
    // window — we must NOT join it, or removeReader / the bus thread wedges.
    // The grace is intentionally short; it bounds removeReader latency.
    //
    // The abandon decision keys on whether the WORKER is still executing
    // doWork(), observed via worker->inFlight: workerLoop clears inFlight
    // under worker->mutex only AFTER runOnWorker() (i.e. doWork()) returns.
    // It must NOT key on inFlight->isFinished(): the per-op watchdog runs on
    // an independent thread and flips isFinished() true while the worker is
    // still stuck inside an uncancellable doWork(). Keying on isFinished()
    // would skip both the grace and the abandon and fall through to a join
    // that re-wedges on the still-stuck worker.
    using namespace std::chrono_literals;
    constexpr auto kGrace = 250ms;
    if (inFlight) {
        const auto deadline = std::chrono::steady_clock::now() + kGrace;
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard lk(worker->mutex);
                if (worker->inFlight == nullptr) {
                    // doWork() returned; the worker cleared inFlight and is
                    // now winding back to cv.wait, where request_stop wakes it.
                    break;
                }
            }
            // Sleep with the lock released so the worker can acquire it to
            // clear inFlight; also keeps the poll off a hot spin.
            std::this_thread::sleep_for(5ms);
        }
    }

    bool stillInDoWork = false;
    if (inFlight) {
        std::lock_guard lk(worker->mutex);
        // Re-read under the worker's lock: if the worker still hasn't cleared
        // inFlight after the grace, doWork() is still executing (wedged in a
        // non-cooperating, likely uncancellable call). isFinished() is
        // irrelevant here — the watchdog may have set it true while the
        // worker remains stuck.
        stillInDoWork = (worker->inFlight != nullptr);
    }

    if (stillInDoWork) {
        // Worker still in doWork() after the grace: treat as wedged. Mark
        // abandoned BEFORE detaching so the worker observes it on the path
        // after doWork() finally returns and exits WITHOUT touching the
        // (possibly-destroyed) manager. Detach so the jthread destructor
        // neither joins (would block) nor calls std::terminate; the still-
        // running detached thread keeps referencing this ReaderWorker's
        // queue/mutex/cv and owns the in-flight op on its stack, so the
        // storage must outlive the thread. Park it on the never-joined
        // zombie list. A typed Operation1 op (Identity/Cert/Sign) is still
        // driven to a terminal WatchdogTimeout on the wire by its per-op
        // watchdog; a deferred-async PKCS#11 probe op (which arms no watchdog
        // and has no wire surface) instead has its client's pending call
        // bounded by the D-Bus method-call timeout.
        // Scrub the in-flight op from the tracking tables NOW, while `this` (the
        // manager) is guaranteed alive on this (the bus/dtor) thread. The
        // detached worker later drops the op via op.reset() (the `abandoned`
        // branch in workerLoop) WITHOUT touching the possibly-destroyed manager,
        // so it cannot scrub the tables itself. Doing it here means a later
        // cancel / dispatchClientDisconnect never dereferences the op after the
        // detached thread frees it. forgetOp takes
        // m_pathMutex/m_sendersMutex; run it before taking m_workersMutex so the
        // table mutexes are never nested under m_workersMutex.
        forgetOp(inFlight);
        // Invoke the op's abandon hook before detaching it to the zombie list
        // (where ~op will not run until the wedged worker's uncancellable call
        // finally returns). It is a no-op for ops with no external waiter — the
        // deferred-async PKCS#11 probe ops carry none (their reply is released by
        // the closure's fail-closed destructor when the op is finally destroyed);
        // the hook is kept as a defensive extension point, exercised by the
        // abandon unit test, and must be idempotent + safe to race the worker.
        inFlight->onAbandoned();
        worker->abandoned.store(true, std::memory_order_release);
        worker->worker.detach();
        std::lock_guard lock(m_workersMutex);
        m_zombies.push_back(std::move(worker));
        return;
    }
    // Worker cleared inFlight within the grace (doWork() returned) or there
    // was no in-flight op: the worker is winding down / parked in cv.wait and
    // exits promptly on the request_stop above. Its jthread joins as the
    // unique_ptr drops at scope exit — bounded, non-wedging.
}

void OperationManager::cleanupLoop(std::stop_token st)
{
    using namespace std::chrono_literals;
    constexpr auto grace = 5s;
    while (!st.stop_requested()) {
        std::this_thread::sleep_for(1s);
        if (st.stop_requested()) {
            return;
        }
        sweepFinished(grace);
    }
}

void OperationManager::sweepFinished(std::chrono::steady_clock::duration grace)
{
    const auto now = std::chrono::steady_clock::now();
    // Collect the ops that have outlived the grace + their ids under m_finishedMutex,
    // then scrub their tracking-table entries and DESTROY them only AFTER every agent
    // lock is released. The op's destructor tears down its inbound channel, which the
    // backend implements as an outbound transport object-unregister that takes the
    // transport's connection mutex. The dispatch thread holds that same connection
    // mutex across message processing while running a method-call slot (e.g.
    // ReadCertificates -> publish), and that slot blocks on m_pathMutex to publish the
    // new op. Destroying the op here while still holding m_finishedMutex/m_pathMutex
    // would invert the lock order (agent-mutex -> transport-mutex here vs
    // transport-mutex -> agent-mutex on the dispatch thread) and deadlock the whole
    // agent under sustained load. Moving BOTH the scrub and the teardown out from
    // under the locks removes the inversion.
    std::vector<std::unique_ptr<OperationBase>> expired;
    std::vector<OperationId> agedOutIds;
    {
        std::lock_guard lock(m_finishedMutex);
        while (!m_finished.empty() && (now - m_finished.front().finishedAt) >= grace) {
            // Snapshot the id while the op is still alive in the record, so the
            // off-lock scrub below can key on it after the op has been moved out.
            agedOutIds.push_back(m_finished.front().op->id());
            // Move the op out of the record, then drop the record. The op is now
            // solely owned by `expired` and is destroyed below, off-lock.
            expired.push_back(std::move(m_finished.front().op));
            m_finished.pop_front();
        }
    }
    // Locks released. Scrub each aged-out op from ALL THREE tracking tables (m_byId
    // + m_senderToOps + m_opToSender), off every agent lock, BEFORE the ops destruct.
    // The old inline erase touched ONLY m_byId, so the sender maps grew unbounded for
    // a session-lifetime client whose ops all completed normally via this route.
    // forgetOpById takes m_pathMutex then m_sendersMutex (sequentially, never nested,
    // so no lock-ordering cycle with cleanupLoop / dispatchClientDisconnect) and is a
    // harmless no-op for an already-scrubbed id or an unrecorded (invalid-id) probe op.
    for (const auto& id : agedOutIds) {
        forgetOpById(id);
    }
    // Now the op (and its adaptor) destructs. The adaptor's Object::unregister takes
    // only the bus mutex, never an agent mutex, so it can no longer be the inner half
    // of a bus<->agent lock-order inversion.
    expired.clear();
}

void OperationManager::recordSender(OperationId id, const CallerToken& sender)
{
    std::lock_guard lock(m_sendersMutex);
    m_senderToOps[sender].insert(id);
    m_opToSender[id] = sender;
}

void OperationManager::recordSenderForTest(OperationId id, CallerToken sender, OperationBase* op)
{
    {
        std::lock_guard pathLock(m_pathMutex);
        m_byId[id] = op;
    }
    recordSender(id, sender);
}

void OperationManager::forgetOp(OperationBase* op) noexcept
{
    if (!op) {
        return;
    }
    forgetOpById(op->id());
}

void OperationManager::forgetOpById(OperationId id) noexcept
{
    if (!id.valid()) {
        // Never recorded in the tables (bus-less test enqueue path): nothing to
        // scrub. Avoids erasing the "none" sentinel if several unrecorded ops
        // shared it.
        return;
    }
    // Scrub m_byId FIRST, releasing m_pathMutex before taking m_sendersMutex:
    // the two are taken sequentially (never nested) so no lock-ordering cycle is
    // introduced with cleanupLoop (m_finishedMutex -> m_pathMutex) or
    // dispatchClientDisconnect (m_sendersMutex, then cancel's m_pathMutex, also
    // sequential). erase of an absent key is a harmless no-op.
    {
        std::lock_guard pathLock(m_pathMutex);
        m_byId.erase(id);
    }
    {
        std::lock_guard sendersLock(m_sendersMutex);
        auto sit = m_opToSender.find(id);
        if (sit != m_opToSender.end()) {
            auto setIt = m_senderToOps.find(sit->second);
            if (setIt != m_senderToOps.end()) {
                setIt->second.erase(id);
                if (setIt->second.empty()) {
                    m_senderToOps.erase(setIt);
                }
            }
            m_opToSender.erase(sit);
        }
    }
}

void OperationManager::dispatchClientDisconnect(CallerToken client)
{
    std::vector<OperationId> doomed;
    {
        std::lock_guard lock(m_sendersMutex);
        auto it = m_senderToOps.find(client);
        if (it == m_senderToOps.end()) {
            return;
        }
        doomed.assign(it->second.begin(), it->second.end());
        m_senderToOps.erase(it);
        for (const auto& id : doomed) {
            m_opToSender.erase(id);
        }
    }
    for (const auto& id : doomed) {
        cancel(id);
    }
}

} // namespace LibreSCRS::Agent::Operations
