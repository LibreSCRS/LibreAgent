// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The shared AgentClient contract, instantiated over the socket transport.
//
// There are no claims here. They live in the installed header this includes,
// and the other host's tree instantiates the same header over its own client.
// What this file supplies is the traits type: the socket double's script, and
// nothing else.

#include "fakes/FakeSocketAgent.h"

#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>
#include <LibreSCRS/Agent/pkcs11/testing/AgentClientContract.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace {

namespace T = LibreSCRS::Agent::Test;
namespace P = LibreSCRS::Pkcs11Agent;
namespace W = LibreSCRS::Agent::Wire;
using P::Testing::Refusal;

// RFC 5280 keyEncipherment, so the served cert is a complete one rather than a
// cert-shaped placeholder.
constexpr std::uint32_t kKeyEncipherment = 1U << 2;

// Short budgets: the contract parks no call behind a delay, and the shipped
// ten-minute interactive budget is only a ceiling here.
constexpr P::SocketTimeouts kFastBudgets{/*publicDataSecs=*/2, /*interactiveSecs=*/8};

/// The wire's own spelling for a contract refusal.
///
/// This is the DOUBLE's script, not the client's table: the fake writes the
/// token onto the wire and SocketAgentClient reads it back through its own
/// mapping, which is the code under test. A switch rather than a lookup, so a
/// Refusal appended to the contract is a build failure here.
W::SyncError wireNameFor(Refusal r) noexcept
{
    switch (r) {
    case Refusal::UserNotLoggedIn:
        return W::SyncError::UserNotLoggedIn;
    case Refusal::NotAuthorized:
        return W::SyncError::NotAuthorized;
    case Refusal::AuthFailed:
        return W::SyncError::AuthFailed;
    case Refusal::Cancelled:
        return W::SyncError::Cancelled;
    case Refusal::KeyNotFound:
        return W::SyncError::KeyNotFound;
    case Refusal::UnknownCard:
        return W::SyncError::UnknownCard;
    case Refusal::NotSupported:
        return W::SyncError::NotSupported;
    case Refusal::RateLimited:
        return W::SyncError::RateLimited;
    case Refusal::Communication:
        return W::SyncError::CommunicationError;
    }
    return W::SyncError::CommunicationError;
}

struct SocketContractHarness
{
    std::unique_ptr<T::FakeSocketAgent> fake;
    std::unique_ptr<P::SocketAgentClient> impl;

    P::AgentClient& client()
    {
        return *impl;
    }
};

struct SocketContractTraits
{
    using Harness = SocketContractHarness;

    static std::string reader()
    {
        return "r1";
    }
    static std::string certId()
    {
        return "certid-1";
    }

    // PkLogin's reply is a bare ack: this wire has no lease-duration field.
    static bool carriesLeaseDuration()
    {
        return false;
    }

    static std::unique_ptr<Harness> serving()
    {
        return make({});
    }

    static std::unique_ptr<Harness> refusingLogin(Refusal r)
    {
        const W::SyncError e = wireNameFor(r);
        return make([e](T::FakeSocketAgent& fake) { fake.failCall(T::Call::PkLogin, e); });
    }

    static std::unique_ptr<Harness> unreachable()
    {
        // An address of the shape the double would have bound, with nothing
        // listening on it. Not a malformed path: an address a client can try
        // and fail to reach is what a stopped agent leaves behind.
        auto h = std::make_unique<Harness>();
        h->impl = std::make_unique<P::SocketAgentClient>(T::makeSocketPath("t7-absent"), kFastBudgets);
        return h;
    }

private:
    static std::unique_ptr<Harness> make(const std::function<void(T::FakeSocketAgent&)>& script)
    {
        auto h = std::make_unique<Harness>();
        h->fake = std::make_unique<T::FakeSocketAgent>();
        h->fake->addReader(reader(), /*hasCard=*/true, "c1");
        h->fake->addCert("c1", certId(), /*signingCapable=*/true, kKeyEncipherment);
        if (script) {
            script(*h->fake);
        }
        h->fake->start();
        h->impl = std::make_unique<P::SocketAgentClient>(h->fake->path(), kFastBudgets);
        return h;
    }
};

} // namespace

namespace LibreSCRS::Pkcs11Agent::Testing {

INSTANTIATE_TYPED_TEST_SUITE_P(Socket, AgentClientContract, ::SocketContractTraits);

} // namespace LibreSCRS::Pkcs11Agent::Testing
