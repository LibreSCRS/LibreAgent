// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The double's own suite. A fake that quietly stops resembling an agent takes
// every suite built on it with it, and each of those would still be green.

#include "fakes/FakeSocketAgent.h"

#include <LibreSCRS/Agent/wire/ClientCodec.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>

#include <gtest/gtest.h>
#include <unistd.h>

#include <optional>
#include <variant>

namespace {

namespace T = LibreSCRS::Agent::Test;
namespace W = LibreSCRS::Agent::Wire;

/// Send one request and read exactly one frame back, decoded as a reply.
std::optional<W::DecodedReply> roundTrip(int fd, const W::Request& req, std::uint64_t id)
{
    EXPECT_TRUE(W::sendFrame(fd, W::encodeRequest(req, id)).has_value());
    auto frame = W::recvFrame(fd);
    if (!frame.has_value())
        return std::nullopt;
    return W::parseReply(frame->body, {});
}

std::optional<W::DecodedEvent> readEvent(int fd)
{
    auto frame = W::recvFrame(fd);
    if (!frame.has_value())
        return std::nullopt;
    return W::parseEvent(frame->body, {});
}

TEST(FakeSocketAgent, AnswersGetStateWithTheReadersItWasGiven)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1", /*signingCapable=*/true);
    fake.start();

    const int fd = T::connectTo(fake.path());
    ASSERT_GE(fd, 0);

    // Hello first. An agent that answered GetState before a handshake would let
    // a client skip the feature negotiation and never notice it had.
    const auto ack = roundTrip(fd, W::Hello{W::kProtocolVersion, std::string{"test"}}, 1);
    ASSERT_TRUE(ack.has_value());
    ASSERT_TRUE(std::holds_alternative<W::HelloAck>(ack->reply));

    const auto state = roundTrip(fd, W::GetState{}, 2);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->requestId, 2U);
    const auto* sr = std::get_if<W::StateReply>(&state->reply);
    ASSERT_NE(sr, nullptr);
    ASSERT_EQ(sr->readers.size(), 1U);
    EXPECT_EQ(sr->readers[0].handle, "r1");
    EXPECT_TRUE(sr->readers[0].hasCard);
    ASSERT_TRUE(sr->readers[0].card.has_value());
    EXPECT_EQ(*sr->readers[0].card, "c1");
    ASSERT_EQ(sr->cards.size(), 1U);
    EXPECT_EQ(sr->cards[0].reader, "r1");

    ::close(fd);
}

// The event opt-out has to be caught on the WIRE: an agent reading the flag
// out of its own default rather than out of the frame would behave identically
// for the client that wants events and wrongly for the one that does not.
TEST(FakeSocketAgent, HelloCarriesTheEventOptOutAcrossTheSocket)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.start();

    const int fd = T::connectTo(fake.path());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(roundTrip(fd, W::Hello{W::kProtocolVersion, std::string{"test"}}, 1).has_value());
    EXPECT_TRUE(fake.lastHello().wantsEvents) << "a Hello that omits the key asks for events";
    ::close(fd);

    const int fd2 = T::connectTo(fake.path());
    ASSERT_GE(fd2, 0);
    ASSERT_TRUE(roundTrip(fd2, W::Hello{W::kProtocolVersion, std::string{"test"}, false}, 1).has_value());
    EXPECT_FALSE(fake.lastHello().wantsEvents) << "the opt-out survived the frame";
    ::close(fd2);
}

TEST(FakeSocketAgent, DeliversAnOperationAsThreeFramesInOrder)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1", /*signingCapable=*/true);
    fake.start();

    const int fd = T::connectTo(fake.path());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(roundTrip(fd, W::Hello{W::kProtocolVersion, std::nullopt}, 1).has_value());

    // OpStarted -> OpResultReady(CertList) -> OpFinished. A fake that replied
    // with the list inline would let a client that never drives an operation
    // pass every later suite in this tree.
    const auto started = roundTrip(fd, W::ReadCertificates{"c1"}, 2);
    ASSERT_TRUE(started.has_value());
    const auto* op = std::get_if<W::OpStarted>(&started->reply);
    ASSERT_NE(op, nullptr);

    const auto ready = readEvent(fd);
    ASSERT_TRUE(ready.has_value());
    const auto* rr = std::get_if<W::OpResultReady>(&ready->event);
    ASSERT_NE(rr, nullptr);
    EXPECT_EQ(rr->op, op->op);
    const auto* list = std::get_if<W::CertListResult>(&rr->result);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(list->certs.size(), 1U);
    EXPECT_EQ(list->certs[0].certId, "certid-1");

    const auto finished = readEvent(fd);
    ASSERT_TRUE(finished.has_value());
    const auto* fin = std::get_if<W::OpFinished>(&finished->event);
    ASSERT_NE(fin, nullptr);
    EXPECT_EQ(fin->op, op->op);

    ::close(fd);
}

TEST(FakeSocketAgent, CanInterleaveAnUnrelatedEventInsideAnOperation)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.interleaveEventInsideNextOperation();
    fake.start();

    const int fd = T::connectTo(fake.path());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(roundTrip(fd, W::Hello{W::kProtocolVersion, std::nullopt}, 1).has_value());
    ASSERT_TRUE(roundTrip(fd, W::ReadCertificates{"c1"}, 2).has_value());

    // Without this the client's "discard what is not mine" rule is never
    // exercised by anything.
    const auto stray = readEvent(fd);
    ASSERT_TRUE(stray.has_value());
    EXPECT_NE(std::get_if<W::CardAdded>(&stray->event), nullptr);

    const auto ready = readEvent(fd);
    ASSERT_TRUE(ready.has_value());
    EXPECT_NE(std::get_if<W::OpResultReady>(&ready->event), nullptr);

    ::close(fd);
}

TEST(FakeSocketAgent, CanRefuseACallWithEachNameTheWireHas)
{
    // A double that always succeeds hides the half of the mapping that matters,
    // so each refusal the module maps has to be producible here.
    const W::SyncError names[] = {
        W::SyncError::UserNotLoggedIn, W::SyncError::NotAuthorized,      W::SyncError::AuthFailed,
        W::SyncError::KeyNotFound,     W::SyncError::UnknownCard,        W::SyncError::NotSupported,
        W::SyncError::RateLimited,     W::SyncError::CommunicationError,
    };
    for (const auto want : names) {
        T::FakeSocketAgent fake;
        fake.addReader("r1", /*hasCard=*/true, "c1");
        fake.failCall(T::Call::PkLogin, want);
        fake.start();

        const int fd = T::connectTo(fake.path());
        ASSERT_GE(fd, 0);
        ASSERT_TRUE(roundTrip(fd, W::Hello{W::kProtocolVersion, std::nullopt}, 1).has_value());
        const auto reply = roundTrip(fd, W::PkLogin{"r1"}, 2);
        ASSERT_TRUE(reply.has_value());
        const auto* err = std::get_if<W::ErrInfo>(&reply->reply);
        ASSERT_NE(err, nullptr);
        const auto* sync = std::get_if<W::SyncError>(&err->code);
        ASSERT_NE(sync, nullptr);
        EXPECT_EQ(*sync, want);
        ::close(fd);
    }
}

} // namespace
