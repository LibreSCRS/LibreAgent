// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <memory>
#include <mutex>
namespace LibreSCRS::Agent {
class PresenceModel;
class CardKeyTracker;
// Subscribes to LibreMiddleware's MonitorService and dispatches presence
// events to the PresenceModel + CardKeyTracker under a shared state mutex
// (a single mutex protects all agent state mutations; the backend transport's
// object register/unregister is internally synchronized on the connection).
// LibreMiddleware delivers callbacks on its own poll thread; we serialize
// state through the mutex rather than wire a custom dispatch-loop marshaller —
// refactor to a queue + wakeup if contention shows up later.
class MonitorBridge
{
public:
    MonitorBridge(PresenceModel& model, CardKeyTracker& tracker, std::mutex& stateMutex);
    ~MonitorBridge();
    MonitorBridge(const MonitorBridge&) = delete;
    MonitorBridge& operator=(const MonitorBridge&) = delete;
    void start(); // first subscribe auto-starts the LM poll thread

    // Drop the subscription and release the monitor so no further reader/card event
    // can reach the presence model or key tracker. Drains any in-flight dispatch
    // (blocking until the poll thread has finished it and — being the last
    // subscription — stopped), then releases the service. Idempotent and noexcept:
    // the backend calls it as the first teardown step so the rest of the shutdown
    // runs with the inbound presence source provably quiet; the destructor also
    // calls it for a bridge that is torn down without an explicit stop.
    void stop() noexcept;

private:
    void dispatch(const LibreSCRS::SmartCard::MonitorEvent& ev); // under m_stateMutex

    PresenceModel& m_model;
    CardKeyTracker& m_tracker;
    std::mutex& m_stateMutex;
    std::unique_ptr<LibreSCRS::SmartCard::MonitorService> m_monitor;
    LibreSCRS::SmartCard::MonitorService::SubscriptionId m_sub;
};
} // namespace LibreSCRS::Agent
