// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Agent/backend/AgentTransport.h>

#include <chrono>
#include <functional>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

// Recording double over the frozen AgentTransport membrane. Captures the typed
// presence deltas, the worker->loop marshaling closures and the client-liveness
// handlers so a test can replay them deterministically without a real dispatch
// thread: runPosted() drains the immediate-post queue in order, and
// fireDisconnect() invokes EVERY registered handler in registration order with a
// caller token (mirroring the additive multi-subscriber production contract —
// AgentService registers op auto-cancel then lease revoke).
struct FakeAgentTransport final : AgentTransport
{
    std::vector<ReaderState> publishedReaders;
    std::vector<CardState> publishedCards;
    std::vector<ObjectId> withdrawn;
    std::vector<std::pair<ObjectId, PropertyDelta>> propertyUpdates;

    std::vector<std::function<void()>> posted;
    std::vector<std::pair<std::chrono::microseconds, std::function<void()>>> postedAfter;
    std::vector<std::function<void(CallerToken)>> disconnectHandlers;

    void publishReader(const ReaderState& reader) override
    {
        publishedReaders.push_back(reader);
    }
    void publishCard(const CardState& card) override
    {
        publishedCards.push_back(card);
    }
    void withdraw(ObjectId object) override
    {
        withdrawn.push_back(object);
    }
    void updateProperties(ObjectId reader, const PropertyDelta& delta) override
    {
        propertyUpdates.emplace_back(reader, delta);
    }

    void post(std::function<void()> fn) override
    {
        posted.push_back(std::move(fn));
    }
    void postAfter(std::chrono::microseconds delay, std::function<void()> fn) override
    {
        postedAfter.emplace_back(delay, std::move(fn));
    }
    void onClientDisconnect(std::function<void(CallerToken)> handler) override
    {
        disconnectHandlers.push_back(std::move(handler));
    }

    // Test helpers (not part of the interface).
    void runPosted()
    {
        auto pending = std::move(posted);
        posted.clear();
        for (auto& fn : pending) {
            if (fn) {
                fn();
            }
        }
    }
    void fireDisconnect(const CallerToken& caller)
    {
        // Fire EVERY registered handler in registration order (production's
        // additive multi-subscriber contract), not last-wins.
        for (const auto& handler : disconnectHandlers) {
            if (handler) {
                handler(caller);
            }
        }
    }
};

} // namespace LibreSCRS::Agent
