// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/MonitorBridge.h>
#include <LibreSCRS/Agent/presence/CardKeyTracker.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <vector>
namespace LibreSCRS::Agent {

using LibreSCRS::SmartCard::MonitorEvent;
using LibreSCRS::SmartCard::MonitorService;

MonitorBridge::MonitorBridge(PresenceModel& model, CardKeyTracker& tracker, std::mutex& stateMutex)
    : m_model(model), m_tracker(tracker), m_stateMutex(stateMutex), m_monitor(std::make_unique<MonitorService>())
{}

MonitorBridge::~MonitorBridge()
{
    stop();
}

void MonitorBridge::start()
{
    m_sub = m_monitor->subscribe([this](const MonitorEvent& ev) {
        std::scoped_lock lock(m_stateMutex);
        dispatch(ev);
    });
}

void MonitorBridge::stop() noexcept
{
    // Idempotent: once the monitor is released, subsequent calls (and the
    // destructor) are no-ops. Drain blocks until any in-flight dispatch — which
    // runs under m_stateMutex and touches the presence model / key tracker — has
    // finished, so those collaborators are guaranteed unreferenced from the poll
    // thread once this returns.
    if (m_monitor) {
        m_monitor->unsubscribe(m_sub, MonitorService::DrainPolicy::Drain);
        m_monitor.reset();
    }
}

void MonitorBridge::dispatch(const MonitorEvent& ev)
{
    using Kind = MonitorEvent::Kind;
    switch (ev.kind) {
    case Kind::ReaderAdded:
        m_model.onReaderAdded(ev.readerName);
        break;
    case Kind::ReaderRemoved:
        m_model.onReaderRemoved(ev.readerName);
        m_tracker.onReaderRemoved(ev.readerName);
        break;
    case Kind::CardInserted: {
        const auto& atr = ev.atr.value_or(std::vector<std::uint8_t>{});
        // The model mints the per-insertion card ObjectId first; the tracker then
        // records that same id as the cache key, so on removal the backend maps it
        // back to the object path the credential/read caches were populated under
        // and scrubs the matching entry.
        m_model.onCardInserted(ev.readerName, atr);
        m_tracker.onCardInserted(ev.readerName, m_model.cardIdFor(ev.readerName));
        break;
    }
    case Kind::CardRemoved:
        m_model.onCardRemoved(ev.readerName);
        m_tracker.onCardRemoved(ev.readerName);
        break;
    case Kind::Error:
        // Surface the diagnostic detail — that's the actual cause of the error.
        log::warnf("monitor error on reader {}: {}", ev.readerName,
                   ev.diagnosticDetail.value_or(std::string{"(no detail)"}));
        break;
    }
}

} // namespace LibreSCRS::Agent
