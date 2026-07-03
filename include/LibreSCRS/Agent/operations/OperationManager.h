// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // OperationId, CallerToken
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept> // QueueFull, std::logic_error
#include <string>
#include <thread>
#include <vector>

namespace LibreSCRS::Agent {
class CapabilityResolver;
}

namespace LibreSCRS::Agent::Operations {

// Per-reader backlog cap: bounds queued ops per reader so a flooding client
// cannot spawn unbounded per-op threads (each operation owns aux threads).
// Shared by the generic publish funnel (throws QueueFull) and
// enqueueOnReaderWorker (returns false). Header-visible because publish is a
// template defined inline below.
inline constexpr std::size_t kMaxQueuedOpsPerReader = 32;

// Neutral backlog-cap exception (was a backend wire error). The
// backend maps it to org.librescrs.Agent.Error.RateLimited.
struct QueueFull : std::runtime_error
{
    QueueFull() : std::runtime_error("reader operation backlog full; retry shortly") {}
};

// Per-reader worker + queue + per-Operation export/lifecycle. Constructed
// once by the backend service; lives as long as the agent. Bus-less for unit
// tests via the no-arg ctor; the production ctor runs the cleanup-grace
// worker and enables the generic publish / async enqueue entry points.
// The scheduler is backend-neutral — it holds no backend/transport type:
// adaptor construction + wire mapping live in the Linux backend.
//
// Each per-reader worker owns one CardSessionHolder: the session is opened
// once for the reader and reused across this reader's operations (so a
// PACE-established secure channel survives), with the candidate plugin list
// resolved once per held session. The holder is touched ONLY on the worker
// thread; enqueue* stamps the holder pointer into the op's Deps under the
// worker mutex, the worker dereferences it inside doWork().
class OperationManager
{
public:
    OperationManager(); // unit-test (bus-less) ctor
    // Production ctor: starts the cleanup-grace worker and enables the generic
    // publish / enqueueOnReaderWorker entry points. @p resolver is the agent's
    // candidate-plugin resolver — each per-reader holder resolves its candidate
    // list through it on the held session. A null resolver yields holders that
    // resolve to an empty candidate list (the resolver-free path).
    explicit OperationManager(CapabilityResolver* resolver);
    ~OperationManager();

    OperationManager(const OperationManager&) = delete;
    OperationManager& operator=(const OperationManager&) = delete;

    // Generic inbound entry (production; requires the bus ctor). Mints the
    // OperationId, ensures the per-reader worker, applies the per-reader backlog
    // cap (throwing QueueFull uniformly, so Sign is capped like the read paths),
    // then lets @p makeOp build the op given the worker's holder (to stamp into
    // Deps BEFORE the op ctor moves them) and the minted id, and finally tracks
    // (recordSender + setId + m_byId) + enqueues + notifies. A template (not
    // std::function) because the op-build closure captures a move-only Deps.
    //
    // @p caller is registered with the disconnect table BEFORE the op enters the
    // worker queue: this closes the disconnect-race window where a client could
    // drop off the bus between the worker picking the op up and the agent
    // recording the sender. Pass an empty CallerToken when no client-cancel
    // auto-track is desired (callers that synthesise the op outside a request
    // context).
    //
    // The caller MUST pass a @p readerName already read into a local — never
    // `deps.readerName` in the same call as a `[deps = std::move(deps)]` closure:
    // the argument evaluations are unsequenced, so the move could empty the name
    // before it is read (an empty name makes the holder open "").
    template <class MakeOp> // std::unique_ptr<OperationBase>(CardSessionHolder* holder, OperationId id)
    [[nodiscard]] OperationId publish(ObjectId reader, const std::string& readerName, CallerToken caller,
                                      MakeOp&& makeOp)
    {
        if (!m_production) {
            throw std::logic_error{"OperationManager::publish requires the production ctor"};
        }
        const auto id = nextOperationId();
        // Resolve (lazily create) the per-reader worker FIRST so makeOp can stamp
        // its holder into the op's Deps. The holder is owned by the worker and
        // dereferenced only on the worker thread.
        auto worker = workerFor(reader, readerName);
        {
            // Backpressure: reject (retryable) before building the op so a
            // flooding client cannot spawn unbounded per-op threads.
            std::lock_guard backlogLock(worker->mutex);
            if (worker->queue.size() >= kMaxQueuedOpsPerReader) {
                throw QueueFull{};
            }
        }
        std::unique_ptr<OperationBase> op = std::forward<MakeOp>(makeOp)(worker->holder.get(), id);
        // Register the sender FIRST so a NameOwnerChanged that arrives between
        // enqueue and the worker picking the op up still finds the id.
        if (!caller.empty()) {
            recordSender(id, caller);
        }
        op->setId(id);
        {
            std::lock_guard pathLock(m_pathMutex);
            m_byId.emplace(id, op.get());
        }
        {
            std::lock_guard lock(worker->mutex);
            worker->queue.push_back(std::move(op));
            worker->cv.notify_one();
        }
        return id;
    }

    // Queue @p fn on @p reader's worker
    // thread (with the worker's CardSessionHolder) and return the calling (bus
    // dispatch) thread IMMEDIATELY — no blocking wait. This is the bridge the
    // ASYNC Pkcs11_1.{CertDer,PublicKey,Login,SignRaw,Decrypt} methods use: card
    // I/O runs on the per-reader worker (serialised against the reader's other
    // ops, single held session), and @p fn fulfils the deferred backend reply on
    // completion — so the bus event loop is never parked on an in-flight op.
    //
    // @p fn is taken BY VALUE and owned by the queued op; it MUST capture only by
    // value / shared_ptr (the dispatch frame is gone before the worker runs it).
    // @p fn carries the deferred reply and is responsible for fulfilling it; if
    // the op is torn down before running (reader removal / wedged-worker abandon),
    // @p fn is destroyed unrun and the reply's fail-closed destructor replies.
    //
    // @p readerName MUST be the real PC/SC reader name — workerFor consults it
    // only when first creating the worker.
    //
    // Returns false when the reader's queue is at its backpressure cap (the caller
    // maps that to a retryable rate-limited error and fulfils the reply itself);
    // true once the op is queued. Throws std::runtime_error if not the production ctor.
    [[nodiscard]] bool enqueueOnReaderWorker(ObjectId reader, const std::string& readerName,
                                             std::function<void(CardSessionHolder&)> fn);

    // Unit-test entry-point: skip adaptor construction; queue an already-
    // built Operation. Production code never calls this.
    void enqueueForTest(ObjectId reader, std::unique_ptr<OperationBase> op);

    // Unit-test entry-point that mirrors the PRODUCTION enqueue bookkeeping
    // (stamp the op's id, record the sender, insert into m_byId) so a bus-less
    // test can exercise the destructive-teardown table scrub without a real bus.
    // Queues the op on the reader's worker. Production never calls this —
    // production goes through the typed enqueue* methods.
    void enqueueTrackedForTest(ObjectId reader, std::unique_ptr<OperationBase> op, OperationId id,
                               const CallerToken& sender);

    // Test seam: override the per-reader holder's SessionFactory so a test can
    // supply a detached CardSession instead of opening a real PC/SC reader.
    // MUST be called before the first enqueue for any reader (the factory is
    // captured when each worker's holder is lazily built). Production never
    // calls this — the holder uses the in-process CardSession::open wrapper.
    void setSessionFactoryForTest(SessionFactory factory);

    // Test seam: enqueue a probe that runs ON THE WORKER THREAD with a
    // reference to the reader's CardSessionHolder. Lets a bus-less test drive a
    // worker-thread holder->acquire() (the bus-less enqueueForTest path does NOT
    // stamp the holder into an op's Deps). Production never calls this.
    void enqueueHolderProbeForTest(ObjectId reader, std::function<void(CardSessionHolder&)> probe);

    // Closes the per-reader shared CardSession so the NEXT operation on the
    // reader re-opens and re-resolves candidates against whatever card is then
    // present. Called on card removal. The holder may only be touched on the
    // worker thread, so this merely flags the worker (under its mutex) and wakes
    // it; the worker invalidates the holder between ops. No-op when no worker
    // exists for the reader (nothing is held).
    void invalidateReaderSession(ObjectId reader);

    // Trip the cancel on the live Operation @p id. No-op if absent.
    void cancel(OperationId id);

    // Stop + drain the reader's worker. Queued ops finish Cancelled with
    // ErrorCode::CardRemoved. Called by the backend reader object's destructor.
    void removeReader(ObjectId reader);

    // Test seam: same as recordSender (registers sender against id)
    // but also wires the id → op pointer (production goes through the
    // id → op map populated by enqueue).
    void recordSenderForTest(OperationId id, CallerToken sender, OperationBase* op);

    // Cancels every Operation whose recorded sender matches @p client.
    // Production callers: the AgentTransport client-disconnect watch forwards
    // here through the handler the backend service registers via onClientDisconnect.
    // Tests synthesise client-disconnect events by invoking this directly.
    void dispatchClientDisconnect(CallerToken client);

#ifdef LIBRESCRS_AGENT_TESTING
    // Test observers for the op-tracking tables: a destructive teardown must
    // leave no entry for a torn-down op so a later cancel /
    // dispatchClientDisconnect cannot dereference a freed OperationBase*.
    [[nodiscard]] bool isIdTrackedForTest(OperationId id)
    {
        std::lock_guard lock(m_pathMutex);
        return m_byId.find(id) != m_byId.end();
    }
    [[nodiscard]] bool isSenderTrackedForTest(const CallerToken& sender)
    {
        std::lock_guard lock(m_sendersMutex);
        return m_senderToOps.find(sender) != m_senderToOps.end();
    }
    [[nodiscard]] bool isOpSenderTrackedForTest(OperationId id)
    {
        std::lock_guard lock(m_sendersMutex);
        return m_opToSender.find(id) != m_opToSender.end();
    }
    // Probe the ownership invariant deterministically: obtain (lazily
    // creating) the per-reader worker handle the same way workerFor hands it to
    // production callers, then call removeReader to drop it from m_workers (+
    // abandonOrJoin releases its ref). Returns true iff the handle obtained
    // beforehand is STILL valid storage afterwards (its members are touchable —
    // no use-after-free of worker.mutex / worker.holder in the workerFor->push
    // gap). The pre-fix unique_ptr ownership could not even hand a test a second
    // owner; shared ownership is what makes this hold. Inline (member bodies see
    // the complete class, so ReaderWorker is visible here).
    [[nodiscard]] bool workerSurvivesRemovalForTest(ObjectId reader)
    {
        auto handle = workerFor(reader, std::string{});
        if (!handle) {
            return false;
        }
        removeReader(reader);
        // Touch members through the surviving handle: a freed worker would crash
        // / trip the sanitizer. Acquire+release the mutex and read the holder.
        {
            std::lock_guard lk(handle->mutex);
            static_cast<void>(handle->queue.size());
        }
        static_cast<void>(handle->holder.get());
        return handle.use_count() >= 1;
    }
    // Run ONE synchronous cleanup-grace sweep aging out EVERY finished op (grace 0),
    // exercising the exact scrub the 5 s cleanup worker runs — so a test can assert
    // the normal-completion route scrubs all three tracking tables (not just m_byId)
    // deterministically, without the 5 s wall-clock grace. Production never calls this.
    void runCleanupSweepForTest()
    {
        sweepFinished(std::chrono::steady_clock::duration::zero());
    }
#endif

private:
    struct ReaderWorker
    {
        std::deque<std::unique_ptr<OperationBase>> queue;
        // Raw pointer to the op the worker is currently executing (held by
        // the worker thread itself; the unique_ptr lives in the worker's
        // stack frame inside workerLoop). Used by removeReader to fire
        // requestCancel on the in-flight op so cooperating doWork()
        // implementations exit promptly. Guarded by `mutex`.
        OperationBase* inFlight{nullptr};
        // Set true by abandonOrJoin just before the jthread is detached and
        // parked on the zombie list. The detached worker observes this on
        // the path after doWork() finally returns and exits WITHOUT
        // touching the (possibly-destroyed) OperationManager — no m_finished /
        // m_production access, no cleanup-grace re-export. Atomic because the
        // setter (bus/dtor thread) and the reader (the detached worker) are
        // distinct threads with no shared lock on that path.
        std::atomic<bool> abandoned{false};
        // Per-reader shared CardSession holder. Opens the session once and
        // reuses it across this reader's ops (PACE reuse). Touched ONLY on the
        // worker thread (inside doWork, via the op's Deps.holder pointer); the
        // worker never accesses it under `mutex`. Declared BEFORE `worker` so it
        // is destroyed AFTER the jthread member: ~jthread joins (or the worker
        // was already detached via abandonOrJoin), so the worker thread has
        // stopped touching the holder before it is freed. A wedged/detached
        // worker keeps the whole ReaderWorker (holder included) alive on the
        // never-destroyed zombie list, so a still-running detached thread never
        // sees a freed holder.
        std::unique_ptr<CardSessionHolder> holder;
        // Set true by invalidateReaderSession (monitor/bus thread) under
        // `mutex`; observed + cleared by the worker thread BETWEEN ops (in the
        // cv predicate and at the loop head). A plain bool guarded by `mutex` —
        // NOT a separate atomic — so it participates in the cv wait predicate
        // under the lock. When set, the worker closes the shared CardSession via
        // holder->invalidate() on its own thread (the only thread allowed to
        // touch the holder), never mid-op, so a live AcquiredCard is never
        // pulled out from under an in-flight doWork().
        bool pendingInvalidate{false};
        std::mutex mutex;
        std::condition_variable_any cv;
        std::jthread worker;
    };

    // Lazily create (or return) the per-reader worker for @p readerPath. On
    // first creation the worker's CardSessionHolder is built for @p readerName
    // (the human reader name the production SessionFactory opens). An empty
    // @p readerName (test path) still creates the holder; its factory simply
    // opens "" and the resolver yields an empty candidate list.
    //
    // Returns a shared_ptr COPY so the caller's worker storage survives even if a
    // concurrent removeReader (monitor thread) drops the worker from m_workers
    // and abandonOrJoin frees its own ref in the window between this call
    // releasing m_workersMutex and the caller finishing its push onto the
    // worker's queue. Without the shared ownership the caller would dereference
    // worker.mutex / worker.holder after the storage was freed (UAF) and its
    // completion latch would never be signalled (bus-thread hang).
    [[nodiscard]] std::shared_ptr<ReaderWorker> workerFor(ObjectId reader, const std::string& readerName);
    void workerLoop(ReaderWorker& worker, std::stop_token st);
    [[nodiscard]] OperationId nextOperationId();

    // Tear a worker down without ever blocking the caller. If the worker
    // has an in-flight op that has NOT finished (isFinished() == false),
    // its doWork() may be parked in an uncancellable call (SCardTransmit
    // on Linux/pcsclite) — joining would
    // wedge the bus thread. Such a worker is DETACHED and moved to the
    // never-joined zombie list, where its storage (queue/mutex/cv that the
    // detached thread still references, plus the in-flight op owned by the
    // thread's stack) lives until process exit; a fresh worker is spun on
    // demand for the reader. The per-op watchdog still drives the
    // abandoned op to a terminal WatchdogTimeout on the wire. A worker
    // with no unfinished in-flight op exits promptly on request_stop and
    // is joined normally as its unique_ptr drops at scope exit.
    void abandonOrJoin(std::shared_ptr<ReaderWorker> worker) noexcept;

    // Insert (id, sender) into the sender → ops dispatch table.
    // Internal: production enqueue calls this BEFORE adding the op to
    // the byId map, and tests reach it via recordSenderForTest.
    void recordSender(OperationId id, const CallerToken& sender);

    // Scrub @p op from ALL THREE op-tracking tables (m_byId, m_opToSender,
    // m_senderToOps) keyed by the op's own id(), so a later cancel /
    // dispatchClientDisconnect can never dereference it after it is destroyed.
    // Called on the destructive teardown paths that drop an op WITHOUT routing
    // it through the cleanup-grace queue (an abandoned in-flight op, queued ops
    // cleared in abandonOrJoin, queued ops cleared on workerLoop exit), BEFORE
    // the op is destroyed. A no-op for an op never recorded in the tables (the
    // bus-less test enqueue path): erasing an absent key / scanning an absent
    // sender is harmless. MUST NOT be called while holding any worker.mutex —
    // it takes m_pathMutex then m_sendersMutex (sequentially, never nested), and
    // no other code path nests those two, so no lock-ordering cycle is created.
    void forgetOp(OperationBase* op) noexcept;
    // Same scrub keyed directly by an id read off a still-alive op — for the
    // queued-op teardown drains (abandonOrJoin + the workerLoop stop-exit). Both
    // move the queued ops out into a locally-owned deque under worker.mutex,
    // release the mutex, then call this to scrub the tables while the ops are
    // STILL ALIVE, and only THEN finish + destroy them. Scrubbing before the free
    // closes the cross-thread UAF window against a concurrent cancel /
    // dispatchClientDisconnect on the bus thread.
    void forgetOpById(OperationId id) noexcept;

    // True when constructed via the production ctor: the cleanup-grace worker is
    // running and the generic publish / enqueueOnReaderWorker entry points are
    // enabled. False under the bus-less unit-test ctor. Replaces the old
    // bus-connection presence gate — that pointer was only ever read as a
    // production-mode flag once backend adaptor construction moved to the Linux
    // backend, so the core no longer references any backend/transport type.
    bool m_production{false};
    // Candidate-plugin resolver shared by every per-reader holder (resolves the
    // candidate list once per held session). Null on the bus-less / resolver-free
    // test path, in which case holders resolve to an empty candidate list. The
    // resolver outlives the manager (owned by main / the backend service).
    CapabilityResolver* m_resolver{nullptr};
    // Test-only SessionFactory override (empty in production). When set, the
    // per-reader holder uses it instead of the in-process CardSession::open
    // wrapper. Set once before any enqueue, then only read on the enqueue path.
    SessionFactory m_testSessionFactory;
    std::mutex m_workersMutex;
    // std::map over unordered_map for consistency with the rest of the
    // manager's id-keyed tables; reader churn is low so ordering overhead is
    // negligible. Keyed by the reader's opaque ObjectId (the backend owns the
    // ObjectId<->wire-path mapping; the neutral scheduler never sees a path).
    // shared_ptr (not unique_ptr) so workerFor can hand callers a ref that
    // outlives a concurrent removeReader: the caller touches worker.mutex /
    // worker.holder after releasing m_workersMutex, and removeReader can free its
    // own ref in that window. Shared ownership keeps the storage alive until the
    // caller's push completes (see workerFor / enqueueOnReaderWorker).
    std::map<ObjectId, std::shared_ptr<ReaderWorker>> m_workers;

    // Abandoned (detached) workers wedged in a non-cooperating doWork().
    // Their jthreads are detached, so this list is INTENTIONALLY never
    // joined or cleared — keeping the ReaderWorker storage alive lets the
    // still-running detached thread (which references the queue/mutex/cv
    // and owns the in-flight op on its stack) finish unwinding whenever
    // its uncancellable call eventually returns, without UAF. The process
    // tolerates the leaked thread+storage until exit (the udisksd
    // LUKS-wedge pattern). Guarded by m_workersMutex.
    std::vector<std::shared_ptr<ReaderWorker>> m_zombies;
    std::mutex m_pathMutex;
    std::map<OperationId, OperationBase*> m_byId;
    std::atomic<std::uint64_t> m_counter{0};

    // Cleanup-grace thread: owns the list of finished operations + their
    // finish-timestamps; unexports after 5 s.
    struct FinishedRecord
    {
        std::unique_ptr<OperationBase> op;
        std::chrono::steady_clock::time_point finishedAt;
    };
    std::mutex m_finishedMutex;
    std::deque<FinishedRecord> m_finished;
    std::jthread m_cleanupWorker;
    void cleanupLoop(std::stop_token st);
    // One age-out pass over m_finished: destroy every op older than @p grace and
    // scrub it from ALL THREE tracking tables (m_byId + m_senderToOps +
    // m_opToSender), off every agent lock. Shared by the cleanup-grace worker
    // (grace = 5s) and the test seam (grace = 0, deterministic).
    void sweepFinished(std::chrono::steady_clock::duration grace);

    // Sender → ops dispatch table for the client-disconnect auto-cancel. The
    // client-disconnect watch that feeds this now lives in the AgentTransport
    // backend; dispatchClientDisconnect is its forwarding target.
    std::mutex m_sendersMutex;
    std::map<CallerToken, std::set<OperationId>> m_senderToOps;
    std::map<OperationId, CallerToken> m_opToSender;
};

} // namespace LibreSCRS::Agent::Operations
