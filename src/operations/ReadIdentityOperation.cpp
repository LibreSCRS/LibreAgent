// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/ReadIdentityOperation.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include "operations/FlowPrelude.h"
#include "operations/GroupRelay.h"
#include "operations/IdentityGroupFeed.h"
#include <LibreSCRS/Logging.h>
#include <optional>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

// The op's own read after a failed background one: the groups the relay already
// delivered are not sent again (the Result is the whole snapshot either way).
class SkipDelivered final : public GroupSink
{
public:
    SkipDelivered(GroupSink& inner, const GroupRelay& relay) noexcept : m_inner(inner), m_relay(relay) {}
    void groupReady(const GroupSnapshot& group) noexcept override
    {
        if (!m_relay.delivered(group.groupKey)) {
            m_inner.groupReady(group);
        }
    }

private:
    GroupSink& m_inner;
    const GroupRelay& m_relay;
};

} // namespace

ReadIdentityOperation::ReadIdentityOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                             std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    // Per wire-cancel contract: dismiss the prompter
                    // modal when a request-side Cancel arrives during
                    // AwaitingConsent. Capture the prompter pointer (the
                    // owning instance outlives the op via AgentService's
                    // declaration order).
                    [prompter = &deps.prompter, serializer = &deps.serializer, cardKey = deps.cardKey]() noexcept {
                        // Dismiss THIS card's live prompt: more than one window
                        // can stand, and the gate is the only thing that knows
                        // which id is outstanding for this card.
                        for (const auto& id : serializer->liveIdsFor(cardKey)) {
                            prompter->cancel(id);
                        }
                    }),
      m_deps(std::move(deps))
{}

ReadIdentityOperation::~ReadIdentityOperation()
{
    // Every path that ends an attached op closes its relay first. One that did not
    // would leave an emit into a freed op possible: say so, and wait it out (a stall
    // that shows in the log beats a use after free).
    if (m_relay && !m_relay->isClosed()) {
        log::errorf("identity read for card={} destroyed with its group relay open", m_deps.cardKey);
        m_relay->closeAndWait();
    }
}

std::shared_ptr<GroupRelay> ReadIdentityOperation::followIdentityGroupFeed(IdentityGroupFeed& feed)
{
    if (m_relay || feed.cardKey() != m_deps.cardKey) {
        return {};
    }
    auto relay = std::make_shared<GroupRelay>(*this);
    if (!feed.attach(relay)) {
        return {};
    }
    m_relay = relay;
    // Written now, under the worker's mutex, where the log cannot reach the
    // channel: the relay is parked, so no group of this source has gone out yet.
    FlowPrelude::logIdentityRequest(m_deps.requester, m_deps.readerName, m_deps.cardKey,
                                    FlowPrelude::IdentitySource::BackgroundRead);
    return relay;
}

std::shared_ptr<GroupRelay> ReadIdentityOperation::groupRelay() const noexcept
{
    return m_relay;
}

void ReadIdentityOperation::doWork()
{
    // An attached op first shuts its relay and waits out an emit in progress: from
    // here this thread is the only one that emits for it.
    if (m_relay) {
        m_relay->closeAndWait();
    }
    // The per-reader session holder is a raw pointer stamped by the
    // OperationManager; guard against a null (mis-wired) holder so doWork
    // finishes with an internal error instead of dereferencing nullptr.
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    // Serve a still-cached snapshot without re-walking the card: the same
    // per-card read cache GetPhoto consults and that the fresh read below
    // populates. A master-detail return to an already-read, still-seated card
    // then costs a RAM lookup instead of a fresh multi-second APDU walk. The
    // cache is dropped on CardRemoved and on an auth failure, so a re-inserted
    // or re-authenticated card still reads fresh. Mirror GetPhotoOperation and
    // the fresh-read path: skip the wire completion if the backend is tearing
    // down (the client observes agent-gone via the dropped connection).
    if (auto cached = m_deps.readCache.get(m_deps.cardKey)) {
        if (shutdownRequested()) {
            return;
        }
        // An attached op already wrote the line for this source when it attached.
        if (!m_relay) {
            FlowPrelude::logIdentityRequest(m_deps.requester, m_deps.readerName, m_deps.cardKey,
                                            FlowPrelude::IdentitySource::Cache);
        }
        if (!emitResult(ResultPayload{*cached})) {
            finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.result_failed",
                   "Failed to deliver the operation result");
            return;
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Read completed");
        return;
    }

    std::optional<SkipDelivered> skipDelivered;
    if (m_relay) {
        skipDelivered.emplace(*this, *m_relay);
    }
    GroupSink& groupSink = skipDelivered ? static_cast<GroupSink&>(*skipDelivered) : static_cast<GroupSink&>(*this);

    IdentityReadFlow flow(IdentityReadFlowDeps{
        .holder = *m_deps.holder,
        .reader = m_deps.reader,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .groupSink = groupSink,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = m_deps.requester,
        .artifact = m_deps.artifact,
        .token = token(),
        .onCardType = m_deps.onCardType,
        .depositor = m_deps.depositor,
    });
    auto result = flow.run();

    // Backend teardown in progress: the reply channel + broker are being torn
    // down, so skip the wire completion (the client observes agent-gone via the
    // dropped connection). The flow already bailed at its post-read gate on the
    // shutdown-cancel token, before touching any torn-down member.
    if (shutdownRequested()) {
        return;
    }

    if (result.outcome == IdentityReadFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome != IdentityReadFlow::Outcome::Ok || !result.snapshot) {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }

    // Store the full snapshot (photos included) so GetPhoto can pull from
    // the cache without re-reading the card.
    m_deps.readCache.put(m_deps.cardKey, *result.snapshot);

    // Emit the typed identity result BEFORE Finished (strict ordering
    // contract). Inline, but a channel can still fail to encode or post it:
    // fail closed rather than emit Finished(Ok) with no result.
    if (!emitResult(ResultPayload{*result.snapshot})) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.result_failed",
               "Failed to deliver the operation result");
        return;
    }
    finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
}

} // namespace LibreSCRS::Agent::Operations
