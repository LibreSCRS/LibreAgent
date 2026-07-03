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
    // Watchdog production: first entry into Authenticating (3) or
    // Reading (4) arms the per-op timer. The arm is one-shot; later
    // phase transitions inside the same op (e.g. Reading -> Done) leave
    // the timer running until it observes finish() via the cv.
    if (previous != phase) {
        try {
            armWatchdogIfNeeded(phase);
        } catch (...) {
            // setPhase is noexcept; arm failures (thread creation) are
            // logged but cannot escape — a missing watchdog falls back to
            // the worker's own cooperation contract.
        }
    }
}

void OperationBase::armWatchdogIfNeeded(std::uint32_t newPhase)
{
    constexpr auto kAuthenticating = static_cast<std::uint32_t>(OperationPhase::Authenticating);
    constexpr auto kReading = static_cast<std::uint32_t>(OperationPhase::Reading);
    if (newPhase != kAuthenticating && newPhase != kReading) {
        return;
    }
    // Count every transition that PASSED the arm-phase filter, BEFORE the one-shot
    // CAS below. A correct arm-set is entered exactly once per op; this counter
    // (test-only, see watchdogArmAttempts()) would exceed 1 if a non-arming phase
    // such as Timestamping were ever added to the filter above.
    m_watchdogArmAttempts.fetch_add(1, std::memory_order_acq_rel);
    // Only the first arm wins: keep the timer one-shot per op so we do
    // not stack multiple timer threads across phase transitions.
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
    // Trip cancel first so any in-progress doWork that polls the token
    // sees the abort signal before the finish() it would issue runs into
    // the once_flag guard.
    requestCancel();
    finish(OperationStatus::Error, ErrorCode::WatchdogTimeout, "op.watchdog_timeout",
           "Operation exceeded the watchdog timeout");
}

} // namespace LibreSCRS::Agent::Operations
