// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/Identity.h>                 // OperationId
#include <LibreSCRS/Agent/backend/OperationChannel.h> // OperationChannel, ResultPayload
#include <LibreSCRS/Agent/OperationPhase.h>           // OperationPhase, OperationStatus
#include <LibreSCRS/Agent/OperationState.h>           // OperationState
#include <LibreSCRS/Agent/operations/PropertyEmissionThrottler.h>
#include <LibreSCRS/Agent/operations/Seams.h> // OperationPhaseSink
#include <LibreSCRS/CancelToken.h>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace LibreSCRS::Agent::Operations {

class OperationBase : public OperationPhaseSink
{
public:
    // Construct with the shared OperationState BEFORE the channel is
    // built; the backend factory passes the same shared_ptr to both the
    // channel and this ctor. No post-construction rebind.
    OperationBase(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state);

    // Variant that takes a prompter-cancel callback. requestCancel
    // invokes the callback when the op is currently in
    // OperationPhase::AwaitingConsent so the prompter dismisses its modal.
    // Production wiring sets the callback to the backend prompter client's cancel();
    // tests pass an empty callback (default ctor) or a recording fake.
    OperationBase(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state,
                  std::function<void()> prompterCancelCallback);

    virtual ~OperationBase();

    OperationBase(const OperationBase&) = delete;
    OperationBase& operator=(const OperationBase&) = delete;

    // Public entry-point invoked by the per-reader worker thread.
    void runOnWorker();

    // Value-own an arbitrary shared collaborator for this op's whole lifetime.
    // A read/sign worker abandoned while blocked in the consent prompt is
    // detached to the process-lifetime zombie list and outlives the composition
    // that owned its collaborators; co-owning the prompter + the prompt gate
    // here keeps exactly the two members the post-unblock unwind touches
    // unconditionally alive until this op (and its blocked call) finally drains,
    // rather than dereferencing freed memory. The backend additionally co-owns the
    // op's bus connection through this seam, so the channel's adaptor emit +
    // unregister at zombie drain touch a live connection (the vector is destroyed
    // AFTER m_channel — see its declaration). Held as shared_ptr<void> so the op
    // stays agnostic to the collaborator types. Call before the op is enqueued.
    void keepAlive(std::shared_ptr<void> owner);

    // Bind the agent-wide shutdown-cancel token: when the backend begins
    // teardown it cancels that token, which trips THIS op's cancel source so the
    // flow returns Cancelled at its post-prompt gate BEFORE touching any
    // torn-down collaborator (credentials / lease / broker / terminal seam). It
    // deliberately does NOT dismiss the prompter modal a second time — the
    // backend's cross-connection CancelCurrent owns that, and a second dismiss
    // would put two threads on the one prompter connection a wedged worker is
    // pumping inline. shutdownRequested() then lets doWork() skip the wire
    // completion. Call before the op is enqueued; a default (never-cancellable)
    // token is a no-op.
    void bindShutdownToken(LibreSCRS::CancelToken shutdownToken) noexcept;

    // Reclaim this op's per-op auxiliary threads (property-emission
    // throttler + watchdog) once it is terminal, WITHOUT destroying the op
    // (it stays exported for the cleanup grace). Called by the per-reader
    // worker thread immediately after runOnWorker() returns, so it never
    // joins the thread it runs on. Idempotent.
    void quiesce() noexcept;

    // Bus thread -> worker: trips the cancel flag in the shared state.
    // Idempotent. Used both by Operation1.Cancel() dispatch and by the
    // OperationManager's drain / NameOwnerChanged paths.
    void requestCancel() noexcept;

    // Auto-cancel finish: drain loop on ReaderRemoved / CardRemoved calls
    // this to terminate queued ops with errorCode = CardRemoved instead of
    // a vanilla Cancelled (errorCode = None).
    void finishCardRemoved() noexcept;

    // Watchdog finish: per-op timer expired before the worker observed
    // its cancel + finish on its own. Trips cancel and finishes with
    // ErrorCode::WatchdogTimeout. Idempotent via the same std::once_flag
    // gate as finish(): if doWork has already finished, this is a no-op.
    void finishWatchdogTimeout() noexcept;

    // Called by abandonOrJoin on the IN-FLIGHT op just before its wedged worker
    // is detached to the never-joined zombie list. The default is a no-op. An op
    // that parks a separate thread on its completion may override this to release
    // that waiter NOW, so the thread is not parked until the detached worker's
    // uncancellable doWork (wedged in an SCardTransmit) finally returns — which it
    // may never do. The deferred-async PKCS#11 ops carry no such waiter (their
    // reply is released by the closure's fail-closed destructor when the op is
    // destroyed), so the hook is a no-op for them today; it remains a defensive
    // extension point, exercised by the abandon unit test. MUST be idempotent +
    // safe to race the detached worker. Called on the bus/monitor thread.
    virtual void onAbandoned() noexcept {}

    // Has finish() already fired? Observed by the OperationManager (the
    // watchdog-firing path needs to decide whether to replace a worker
    // that may still be stuck in doWork).
    [[nodiscard]] bool isFinished() const noexcept
    {
        return m_finished.load(std::memory_order_acquire);
    }

    // Accessors used by the OperationManager when wiring property reads
    // through the shared OperationState (also referenced by tests).
    [[nodiscard]] std::uint32_t phase() const noexcept
    {
        return m_state ? m_state->phase.load(std::memory_order_acquire) : 0u;
    }
    [[nodiscard]] double progress() const noexcept
    {
        return m_state ? m_state->progress.load(std::memory_order_acquire) : 0.0;
    }
    [[nodiscard]] bool isIndeterminate() const noexcept
    {
        return m_state && m_state->isIndeterminate.load(std::memory_order_acquire);
    }
    // Terminal property mirrors. Valid (race-free) only AFTER finish() has
    // run; a client reads them within the cleanup grace window to recover a
    // Finished signal it may have missed (see the XML doc block).
    [[nodiscard]] bool completed() const noexcept
    {
        return m_state && m_state->completed.load(std::memory_order_acquire);
    }
    [[nodiscard]] std::uint32_t terminalStatus() const noexcept
    {
        return m_state ? m_state->terminalStatus.load(std::memory_order_acquire) : 0u;
    }
    [[nodiscard]] std::uint32_t terminalErrorCode() const noexcept
    {
        return m_state ? m_state->terminalErrorCode.load(std::memory_order_acquire) : 0u;
    }
    [[nodiscard]] bool isCancelled() const noexcept
    {
        return m_state && m_state->cancelled.load(std::memory_order_acquire);
    }
    [[nodiscard]] const LibreSCRS::CancelToken& cancelTokenForTest() const noexcept
    {
        return m_token;
    }

    // Test-only observer: how many phase transitions PASSED the watchdog arm-phase
    // filter (Authenticating/Reading) — counted before the one-shot CAS, so it
    // counts *accepted arms*, not *fired timers*. A correct one-shot arm-set is
    // entered exactly once per op regardless of how many later phases transition;
    // this makes the "Timestamping does not re-arm" property genuinely testable
    // (it would increment past 1 if Timestamping were ever added to the filter),
    // which the CAS-gated single fire alone cannot prove.
    [[nodiscard]] unsigned watchdogArmAttempts() const noexcept
    {
        return m_watchdogArmAttempts.load(std::memory_order_acquire);
    }

    // The opaque operation id this op is tracked under. Stamped by the
    // OperationManager right after the op is recorded in its tracking tables
    // (m_byId / m_senderToOps), so the manager can scrub those tables by id when
    // an op is destroyed off the normal cleanup path (a destructive worker
    // teardown). Empty (==0) until stamped (the bus-less test enqueue path never
    // stamps it, and never records the op in the tables either).
    void setId(OperationId id) noexcept
    {
        m_id = id;
    }
    [[nodiscard]] OperationId id() const noexcept
    {
        return m_id;
    }

    // OperationPhaseSink override -- public surface so IdentityReadFlow
    // (which holds an OperationPhaseSink&) can drive transitions through
    // AwaitingConsent and Authenticating from outside this class. Calls
    // are forwarded to the same internal setPhase the worker uses.
    void setPhase(std::uint32_t phase) noexcept override;

protected:
    // Subclass implements the actual work. Runs on the worker thread.
    virtual void doWork() = 0;

    // True once the agent-wide shutdown-cancel token bound via
    // bindShutdownToken() has fired. doWork() consults it AFTER the flow returns
    // to SKIP the wire completion (finish / Result emit): the reply channel + the
    // broker are being torn down, so the client observes agent-gone via the
    // dropped connection rather than a completion into freed memory.
    [[nodiscard]] bool shutdownRequested() const noexcept;

    // Worker-side mutator. setPhase is public (via OperationPhaseSink
    // override above) so the orchestration flow can drive it too.
    void setProgress(double progress) noexcept;

    // Marks the operation as an honest spinner (no meaningful percentage).
    // Card-I/O operations call setIndeterminate(true) at op start; the
    // determinate Progress property is reserved for a future op that can
    // report real percentages. Emits PropertiesChanged on change.
    void setIndeterminate(bool indeterminate) noexcept;
    [[nodiscard]] LibreSCRS::CancelToken token() const noexcept
    {
        return m_token;
    }

    // Subclass-driven terminal transition. Idempotent via std::once_flag.
    // setProgress(1.0) and setPhase(Done) are implicit when status == Ok.
    void finish(OperationStatus status, ErrorCode code, std::string msgKey, std::string msgFallback) noexcept;

    // Emit the operation's high-level result (Identity1/Certificates1/Photo1/
    // Sign1.Result) through the backend channel, fired BEFORE finish() per the
    // strict Result-before-Finished ordering contract. The channel selects and
    // marshals the matching variant arm. Returns false when a required
    // large-result seal failed (Photo1/Sign1 memfd): the Sign/GetPhoto ops turn
    // that into finish(Error, CommunicationError, "op.memfd_failed") so a seal
    // failure never leaks as Finished(Ok) with no result signal. Returns true
    // otherwise — including a null channel (test/no-bus), which is a no-op
    // success. Identity/Certificates deliver inline and discard the always-true
    // status.
    [[nodiscard]] bool emitResult(const ResultPayload& result) noexcept
    {
        return m_channel ? m_channel->emitResult(result) : true;
    }

private:
    // Arms the watchdog timer on the first transition into Authenticating
    // or Reading. Subsequent transitions inside that phase set are
    // no-ops (the timer is one-shot per op). Wakes via the per-op
    // condition_variable + stop_token; the cv is notified by finish() so
    // the timer thread observes the op completing early and exits without
    // firing the timeout finish.
    void armWatchdogIfNeeded(std::uint32_t newPhase);

    // Shutdown-cancel of THIS op's token only: trip the cancel source + the
    // shared cancelled flag, invoked from the bound shutdown token's callback.
    // Unlike requestCancel() it does NOT invoke the prompter-cancel callback (see
    // bindShutdownToken()).
    void requestShutdownCancel() noexcept;

    // Prompter-cancel callback (the backend prompter client's cancel forwarder in
    // production; may be empty in tests that do not exercise the path).
    std::function<void()> m_prompterCancelCallback;

    std::shared_ptr<OperationState> m_state;
    // Shared collaborators this op value-owns for its whole lifetime (see
    // keepAlive()). Declared BEFORE m_channel so it is destroyed AFTER it: a
    // co-owned bus connection (the backend keepAlives the typed op's connection
    // share here) must still be alive when m_channel's adaptor unregisters against
    // it at op destruction — a zombie op abandoned past teardown may be the last
    // owner, so releasing the connection before the channel unregister would be a
    // use-after-free.
    std::vector<std::shared_ptr<void>> m_keepAlives;
    std::unique_ptr<OperationChannel> m_channel;
    // The op's opaque operation id (empty == 0 until OperationManager stamps it
    // via setId on the production enqueue path).
    OperationId m_id;
    // Propagates the shared cancel flag into the LM CancelToken the seam
    // layer consumes. Wired in the ctor body so bus-side Cancel and
    // worker-side token observation share a single cancellation signal.
    LibreSCRS::CancelSource m_cancelSource;
    LibreSCRS::CancelToken m_token;
    // Coalesces progress-only PropertiesChanged emissions (at most one
    // per 100 ms). Phase transitions still emit immediately through
    // setPhase()'s direct path.
    std::unique_ptr<PropertyEmissionThrottler> m_progressThrottler;
    std::once_flag m_finishOnce;
    // Mirror of the std::once_flag for external observation. Stored AFTER
    // emitFinished completes (i.e. inside the call_once body) so a
    // concurrent isFinished() reader never reports "true" before the
    // channel has actually emitted Finished.
    std::atomic<bool> m_finished{false};

    // Watchdog: armed on first Authenticating/Reading entry; one-shot.
    // m_watchdogArmed gates the arm path. m_watchdogCv (condition_variable_any
    // so it supports stop_token wait) wakes the timer thread early when
    // finish() runs to completion.
    std::atomic<bool> m_watchdogArmed{false};
    // Test-only: counts phase transitions that passed the arm-phase filter, before
    // the one-shot CAS (see watchdogArmAttempts()). Not on any wire/ABI surface.
    std::atomic<unsigned> m_watchdogArmAttempts{0};
    std::mutex m_watchdogMutex;
    std::condition_variable_any m_watchdogCv;
    std::jthread m_watchdog;

    // Agent-wide shutdown-cancel token (default = never-cancellable). Observed by
    // shutdownRequested(); its callback trips this op's cancel source. Declared
    // LAST so the registration is torn down (waiting out any in-flight callback)
    // before the cancel source + state the callback touches.
    LibreSCRS::CancelToken m_shutdownToken;
    LibreSCRS::CancelToken::Registration m_shutdownReg;
};

} // namespace LibreSCRS::Agent::Operations
