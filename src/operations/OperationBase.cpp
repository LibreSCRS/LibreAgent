// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <chrono>
#include <mutex>
#include <stop_token>
#include <utility>

namespace LibreSCRS::Agent::Operations {

OperationBase::OperationBase(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state), std::function<void()>{})
{}

OperationBase::OperationBase(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state,
                             std::function<void()> prompterCancelCallback)
    : m_prompterCancelCallback(std::move(prompterCancelCallback)), m_state(std::move(state)),
      m_channel(std::move(channel)), m_token(m_cancelSource.token())
{
    if (m_channel) {
        m_progressThrottler = std::make_unique<PropertyEmissionThrottler>(
            [channel = m_channel.get()] { channel->emitPropertiesChanged(); }, std::chrono::milliseconds{100});
    }
}

OperationBase::~OperationBase()
{
    // Stop the watchdog thread early (if it was armed). The jthread member
    // joins on destruction either way, but a notify_all wakes it without
    // having to wait for the configured timeout.
    if (m_watchdog.joinable()) {
        m_watchdog.request_stop();
        std::lock_guard lk(m_watchdogMutex);
        m_watchdogCv.notify_all();
    }
}

void OperationBase::quiesce() noexcept
{
    // Join the watchdog FIRST (so any in-flight finishWatchdogTimeout() ->
    // finish() completes while the throttler is still alive), THEN stop the
    // throttler. Safe only on the worker thread (never the watchdog/throttler
    // thread itself). The destructor repeats both as no-ops.
    if (m_watchdog.joinable()) {
        m_watchdog.request_stop();
        {
            std::lock_guard lk(m_watchdogMutex);
            m_watchdogCv.notify_all();
        }
        m_watchdog.join();
    }
    if (m_progressThrottler) {
        m_progressThrottler->stop();
    }
}

void OperationBase::keepAlive(std::shared_ptr<void> owner)
{
    if (owner) {
        m_keepAlives.push_back(std::move(owner));
    }
}

void OperationBase::bindShutdownToken(LibreSCRS::CancelToken shutdownToken) noexcept
{
    m_shutdownToken = std::move(shutdownToken);
    if (!m_shutdownToken.isCancellable()) {
        return; // never-cancellable default: nothing to observe.
    }
    try {
        m_shutdownReg = m_shutdownToken.registerCallback([this] { requestShutdownCancel(); });
    } catch (...) {
        // registerCallback may throw bad_alloc; a missing registration falls back
        // to the keep-alive + the flow's own token gates, still UAF-safe.
    }
}

bool OperationBase::shutdownRequested() const noexcept
{
    return m_shutdownToken.isCancellable() && m_shutdownToken.isCancelled();
}

void OperationBase::requestShutdownCancel() noexcept
{
    // Token-only cancel: no prompter dismiss (see bindShutdownToken()).
    if (m_state) {
        m_state->cancelled.store(true, std::memory_order_release);
    }
    try {
        m_cancelSource.requestCancel();
    } catch (...) {
        // CancelSource::requestCancel is noexcept on the LM side; defensive.
    }
}

void OperationBase::runOnWorker()
{
    try {
        doWork();
    } catch (const std::exception& e) {
        log::warnf("OperationBase: doWork threw, finishing with Error: {}", e.what());
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", e.what());
    } catch (...) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "unknown exception");
    }
}

void OperationBase::requestCancel() noexcept
{
    // Snapshot the phase BEFORE flipping the cancel atomic so the
    // prompter-cancel decision reflects the state the user was in when
    // they hit Cancel.
    const auto previousPhase = m_state ? m_state->phase.load(std::memory_order_acquire) : 0u;
    if (m_state) {
        m_state->cancelled.store(true, std::memory_order_release);
    }
    try {
        m_cancelSource.requestCancel();
    } catch (...) {
        // CancelSource::requestCancel is noexcept on the LM side; defensive catch.
    }
    // When cancelling an op currently waiting on the prompter, dismiss
    // the modal too -- otherwise the user is left staring at a dialog
    // whose owning Operation no longer exists.
    if (previousPhase == static_cast<std::uint32_t>(OperationPhase::AwaitingConsent) && m_prompterCancelCallback) {
        try {
            m_prompterCancelCallback();
        } catch (...) {
            // Callback is noexcept by contract but stays caught here so a
            // misbehaving callback cannot escape past requestCancel.
        }
    }
}

void OperationBase::finishCardRemoved() noexcept
{
    // Drain-path entry: trip cancel, then drive the worker so doWork()
    // observes the cancel and calls finish() — but override the errorCode
    // to CardRemoved by short-circuiting through finish() ourselves when
    // the subclass hasn't already terminated.
    requestCancel();
    finish(OperationStatus::Error, ErrorCode::CardRemoved, "op.card_removed", "Card removed");
}

void OperationBase::setPhase(std::uint32_t phase) noexcept
{
    if (!m_state) {
        return;
    }
    const auto previous = m_state->phase.exchange(phase, std::memory_order_acq_rel);
    if (previous != phase && m_channel) {
        // Phase transitions ALWAYS emit immediately; the throttler is
        // only consulted for progress-only updates.
        if (m_progressThrottler) {
            m_progressThrottler->flush();
        } else {
            m_channel->emitPropertiesChanged();
        }
    }
    // Watchdog production: the timer covers MACHINE time only. Entry into
    // AwaitingConsent (2) stops it -- the holder is not something to time, and
    // the prompt carries its own visible deadline -- and the next entry into
    // Authenticating (3) / Reading (4) arms a FRESH full budget. Other phases
    // (Connecting, Signing, Timestamping, Done) neither arm nor disarm: they run
    // out whatever budget the last machine-phase entry started.
    //
    // Enlarging the budget to cover the human instead was rejected: it would
    // make the card's allowance depend on typing speed, so a slow MRZ entry
    // would leave a healthy card almost no time while a fast one would grant a
    // wedged card minutes of tolerance.
    if (previous != phase) {
        try {
            if (phase == static_cast<std::uint32_t>(OperationPhase::AwaitingConsent)) {
                disarmWatchdog();
            } else {
                armWatchdogIfNeeded(phase);
            }
        } catch (...) {
            // setPhase is noexcept; arm failures (thread creation) are
            // logged but cannot escape — a missing watchdog falls back to
            // the worker's own cooperation contract.
        }
    }
}

void OperationBase::groupReady(const GroupSnapshot& group) noexcept
{
    // One hop to the channel, exactly like setPhase's emitPropertiesChanged
    // forward above. A null channel (test/no-bus) is a silent no-op, same
    // posture as emitResult's own null-channel branch.
    if (m_channel) {
        m_channel->emitGroup(group);
    }
}

void OperationBase::armWatchdogIfNeeded(std::uint32_t newPhase)
{
    constexpr auto kAuthenticating = static_cast<std::uint32_t>(OperationPhase::Authenticating);
    constexpr auto kReading = static_cast<std::uint32_t>(OperationPhase::Reading);
    if (newPhase != kAuthenticating && newPhase != kReading) {
        return;
    }
    // Count every transition that PASSED the arm-phase filter, BEFORE the CAS
    // below. The arm-set is entered once per machine-phase entry; this counter
    // (test-only, see watchdogArmAttempts()) would exceed that if a non-arming
    // phase such as Timestamping were ever added to the filter above.
    m_watchdogArmAttempts.fetch_add(1, std::memory_order_acq_rel);
    // Only one timer runs at a time: the CAS refuses a second arm while one is
    // live. It is no longer once per OPERATION -- disarmWatchdog() clears the
    // flag on entry to AwaitingConsent, so an op that prompts more than once
    // arms once per machine-phase entry. disarmWatchdog() JOINS before
    // clearing, which is what keeps timer threads from stacking.
    bool expected = false;
    if (!m_watchdogArmed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }
    const auto timeoutSec = m_state ? m_state->watchdogTimeoutSec.load(std::memory_order_acquire) : 0u;
    if (timeoutSec == 0u) {
        // Watchdog disabled (0 = no timeout). Do not start the thread.
        return;
    }
    m_watchdog = std::jthread([this, timeoutSec](std::stop_token st) {
        std::unique_lock lock(m_watchdogMutex);
        const bool stoppedEarly = m_watchdogCv.wait_for(lock, st, std::chrono::seconds{timeoutSec}, [this, &st] {
            return st.stop_requested() || m_finished.load(std::memory_order_acquire);
        });
        if (stoppedEarly) {
            return; // op finished or destruction; do not fire timeout.
        }
        lock.unlock();
        // Drop the mutex before finishWatchdogTimeout() — the finish path
        // re-locks the mutex to notify the cv.
        finishWatchdogTimeout();
    });
}

void OperationBase::disarmWatchdog() noexcept
{
    if (!m_watchdogArmed.exchange(false, std::memory_order_acq_rel)) {
        return; // not armed; nothing to stop
    }
    if (m_watchdog.joinable()) {
        m_watchdog.request_stop();
        {
            // The timer waits on m_watchdogCv with the stop token; notifying
            // under the mutex wakes it deterministically rather than leaving
            // the join to the full budget.
            std::lock_guard lock(m_watchdogMutex);
        }
        m_watchdogCv.notify_all();
        // Join before returning: once this function has run, no timer of this
        // op can still be in flight, so the next arm starts from a clean slate
        // instead of stacking a second thread onto a live one. Safe against
        // self-join -- only the worker thread reaches here, via
        // setPhase(AwaitingConsent), and the timer thread's own path into
        // setPhase (finish() -> Done) never takes this branch.
        m_watchdog.join();
    }
}

void OperationBase::setProgress(double progress) noexcept
{
    if (progress < 0.0)
        progress = 0.0;
    if (progress > 1.0)
        progress = 1.0;
    if (m_state) {
        m_state->progress.store(progress, std::memory_order_release);
    }
    // Progress-only updates ride the throttler (at most one
    // PropertiesChanged per 100 ms outside phase transitions).
    if (m_progressThrottler) {
        m_progressThrottler->schedule();
    }
}

void OperationBase::setIndeterminate(bool indeterminate) noexcept
{
    if (!m_state) {
        return;
    }
    const bool previous = m_state->isIndeterminate.exchange(indeterminate, std::memory_order_acq_rel);
    if (previous == indeterminate) {
        return;
    }
    // A spinner toggle is a discrete UI-state change, not a high-frequency
    // progress tick: flush it immediately like a phase transition so a
    // client racing to read IsIndeterminate sees the new value at once.
    if (m_progressThrottler) {
        m_progressThrottler->flush();
    } else if (m_channel) {
        m_channel->emitPropertiesChanged();
    }
}

void OperationBase::finish(OperationStatus status, ErrorCode code, std::string msgKey, std::string msgFallback) noexcept
{
    std::call_once(m_finishOnce, [&] {
        // The watchdog's verdict outranks whatever the caller brought. It is
        // latched before cancel is tripped, so by the time a doWork woken by
        // that cancel gets here the latch is already visible, and the timeout
        // is reported as a timeout no matter which thread won the race to this
        // once_flag. Applied inside the lambda so it governs exactly the one
        // call that publishes the terminal state.
        if (m_watchdogFired.load(std::memory_order_acquire)) {
            status = OperationStatus::Error;
            code = ErrorCode::WatchdogTimeout;
            msgKey = "op.watchdog_timeout";
            msgFallback = "Operation exceeded the watchdog timeout";
        }
        try {
            if (status == OperationStatus::Ok && m_state) {
                m_state->progress.store(1.0, std::memory_order_release);
            }
            setPhase(static_cast<std::uint32_t>(OperationPhase::Done));
            // Populate the read-only terminal-property mirrors BEFORE the
            // Finished signal fires. A client that subscribed too late to
            // catch Finished (a fast op can emit before the client, which
            // learns the op path only from the method return, subscribes)
            // reads Completed/Status/ErrorCode within the cleanup grace
            // window to recover the result race-free. Order matters: store
            // the values first, then publish completed=true as the gate.
            if (m_state) {
                m_state->terminalStatus.store(static_cast<std::uint32_t>(status), std::memory_order_release);
                m_state->terminalErrorCode.store(static_cast<std::uint32_t>(code), std::memory_order_release);
                m_state->completed.store(true, std::memory_order_release);
            }
            // Gate the wire emit on the shutdown token: at backend teardown the
            // client is gone (it learns of agent-exit from the dropped connection)
            // and the reply channel's backend adaptor is racing the connection's
            // destruction, so eliding the emit is correct. This also removes the
            // post-teardown channel touch a zombie typed op's still-armed watchdog
            // would otherwise make (finishWatchdogTimeout -> finish -> emitFinished
            // through an adaptor bound to the being-freed connection). The terminal
            // property mirrors above are populated regardless, so a same-process
            // observer stays coherent.
            if (m_channel && !shutdownRequested()) {
                m_channel->emitFinished(status, code, msgKey, msgFallback);
            }
        } catch (...) {
            // finish() is noexcept; swallow any internal failure.
        }
        // Mark finished AFTER emitFinished so a concurrent isFinished()
        // reader never observes "true" before the wire signal has fired.
        m_finished.store(true, std::memory_order_release);
        // Wake the watchdog timer (if armed). Notify under the lock so
        // the timer's wait predicate observes the store-release ordering.
        std::lock_guard lk(m_watchdogMutex);
        m_watchdogCv.notify_all();
    });
}

void OperationBase::finishWatchdogTimeout() noexcept
{
    // Latch the verdict BEFORE tripping cancel. Cancelling is what wakes a
    // cooperating doWork, and that doWork then races this function to finish():
    // whoever arrives first takes the once_flag, so without the latch the
    // timeout could be published as the woken doWork's Cancelled/None. The
    // latch makes the outcome independent of who wins that race — see finish().
    m_watchdogFired.store(true, std::memory_order_release);
    // Trip cancel so any in-progress doWork that polls the token sees the
    // abort signal and stops.
    requestCancel();
    finish(OperationStatus::Error, ErrorCode::WatchdogTimeout, "op.watchdog_timeout",
           "Operation exceeded the watchdog timeout");
}

} // namespace LibreSCRS::Agent::Operations
