// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <chrono>
#include <functional>

namespace LibreSCRS::Agent {

// The client membrane + its dispatch thread. Merges three former seams
// (object-publish, event-loop poster, client-liveness) because on each platform
// they are one cohesive transport+threading model. Linux: the D-Bus ObjectManager +
// sd-event/eventfd + NameOwnerChanged. macOS: XPC endpoint + dispatch +
// connection-invalidation. The core never touches wire paths or Variants — the
// backend owns the ObjectId<->path mapping and all property tagging.
class AgentTransport
{
public:
    virtual ~AgentTransport() = default;

    // Presence object tree (published through the AgentTransport backend).
    virtual void publishReader(const ReaderState& reader) = 0;
    virtual void publishCard(const CardState& card) = 0;
    virtual void withdraw(ObjectId object) = 0;
    virtual void updateProperties(ObjectId reader, const PropertyDelta& delta) = 0;

    // Worker -> loop marshaling onto the dispatch thread.
    virtual void post(std::function<void()> fn) = 0;
    virtual void postAfter(std::chrono::microseconds delay, std::function<void()> fn) = 0;

    // Client liveness (was NameOwnerChanged). ADDITIVE multi-subscriber: every
    // registered handler fires, in registration order, on each disconnect, with
    // the disconnecting client's token. Production registers two (OperationManager
    // auto-cancel, then Pkcs11Broker lease revoke); the order is the contract.
    // Handlers are append-only and wired once during single-threaded startup.
    virtual void onClientDisconnect(std::function<void(CallerToken)> handler) = 0;
};

} // namespace LibreSCRS::Agent
