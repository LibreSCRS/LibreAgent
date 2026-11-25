// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/PrefetchIdentityOperation.h"
#include "operations/IdentityPrefetchFlow.h"
#include "operations/SilentOperationChannel.h"
#include <LibreSCRS/Logging.h>
#include <memory>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

const char* outcomeName(FlowOutcome outcome) noexcept
{
    switch (outcome) {
    case FlowOutcome::Ok:
        return "ok";
    case FlowOutcome::Cancelled:
        return "cancelled";
    case FlowOutcome::Error:
        break;
    }
    return "failed";
}

} // namespace

PrefetchIdentityOperation::PrefetchIdentityOperation(Deps deps)
    : OperationBase(std::make_unique<SilentOperationChannel>(), std::make_shared<OperationState>()),
      m_deps(std::move(deps))
{}

void PrefetchIdentityOperation::doWork()
{
    if (m_deps.holder == nullptr) {
        log::infof("identity prefetch done: card={} outcome=failed {}", m_deps.cardKey,
                   static_cast<std::uint32_t>(ErrorCode::CommunicationError));
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    // A user's read got there first (or a prefetch already ran): nothing to do,
    // and no card I/O.
    if (m_deps.readCache.get(m_deps.cardKey)) {
        log::infof("identity prefetch done: card={} outcome=cached", m_deps.cardKey);
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Already cached");
        return;
    }

    // The silent channel emits nothing, but the phase arms the watchdog.
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));
    IdentityPrefetchFlow flow(IdentityPrefetchFlowDeps{
        .holder = *m_deps.holder,
        .reader = m_deps.reader,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .token = token(),
        .onCardType = m_deps.onCardType,
    });
    auto result = flow.run();

    // Put only when nobody cancelled the read and the agent is not tearing down:
    // the cache is a core member this operation does not co-own, and a card
    // removed mid-read has already retired its key.
    const bool ok = result.outcome == FlowOutcome::Ok && result.snapshot;
    if (ok && !shutdownRequested() && !token().isCancelled()) {
        m_deps.readCache.put(m_deps.cardKey, std::move(*result.snapshot));
    }
    if (result.outcome == FlowOutcome::Error) {
        log::infof("identity prefetch done: card={} outcome=failed {}", m_deps.cardKey,
                   static_cast<std::uint32_t>(result.code));
    } else {
        log::infof("identity prefetch done: card={} outcome={}", m_deps.cardKey, outcomeName(result.outcome));
    }
    finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Prefetch finished");
}

} // namespace LibreSCRS::Agent::Operations
