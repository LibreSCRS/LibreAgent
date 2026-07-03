// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-and-behaviour lock for the five shared backend doubles under
// tests/fakes/. Each fake is a concrete recording implementation of a frozen
// backend interface (OperationChannel, Prompter, Authorizer, AgentTransport,
// LogSink); this suite instantiates each through its interface and asserts the
// recording contract so the doubles cannot silently drift from the interfaces.

#include "fakes/FakeAgentTransport.h"
#include "fakes/FakeAuthorizer.h"
#include "fakes/FakeLogSink.h"
#include "fakes/FakeOperationChannel.h"
#include "fakes/FakePrompter.h"

#include <LibreSCRS/Agent/backend/Logging.h>

#include <LibreSCRS/Secure/String.h>
#include <gtest/gtest.h>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

TEST(FakeOperationChannel, RecordsEmitsInOrder)
{
    FakeOperationChannel ch;
    OperationChannel& iface = ch;

    iface.emitPropertiesChanged();
    EXPECT_TRUE(iface.emitResult(ResultPayload{PhotoResult{}})); // inline fake never fails to deliver
    iface.emitFinished(OperationStatus::Ok, ErrorCode::None, "done.key", "done");

    EXPECT_EQ(ch.propsChanged, 1);
    ASSERT_EQ(ch.results.size(), 1u);
    ASSERT_EQ(ch.finished.size(), 1u);
    EXPECT_EQ(ch.finished[0].status, OperationStatus::Ok);
    EXPECT_EQ(ch.finished[0].code, ErrorCode::None);
    EXPECT_EQ(ch.finished[0].msgKey, "done.key");
    EXPECT_EQ(ch.finished[0].msgFallback, "done");
}

TEST(FakePrompter, ReturnsSeededResultAndRecordsCall)
{
    FakePrompter p;
    p.canResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"654321"}, ""};
    PrompterClientBase& iface = p;

    const PromptResult r = iface.requestCan(PromptOptions{});

    EXPECT_EQ(r.status, PromptStatus::Ok);
    ASSERT_EQ(p.calls.size(), 1u);
    EXPECT_EQ(p.calls[0], FakePrompter::Kind::Can);
    iface.cancel();
    EXPECT_EQ(p.cancels, 1);
}

TEST(FakeAuthorizer, AllowAllThenScopedAllowList)
{
    FakeAuthorizer authz;
    Authorizer& iface = authz;
    const CallerToken caller{":1.42"};

    EXPECT_TRUE(iface.authorize(kActionSign, caller));

    authz.allowAll = false;
    authz.allow(kActionConfigure);
    EXPECT_TRUE(iface.authorize(kActionConfigure, caller));
    EXPECT_FALSE(iface.authorize(kActionSign, caller));

    ASSERT_EQ(authz.calls.size(), 3u);
    EXPECT_EQ(authz.calls[0].second, caller);
}

TEST(FakeAgentTransport, RecordsDeltasPostAndDisconnect)
{
    FakeAgentTransport tx;
    AgentTransport& iface = tx;

    iface.publishReader(ReaderState{ObjectId{1}, "reader-0", false, ObjectId{}});
    iface.publishCard(CardState{ObjectId{2}, ObjectId{1}, 0, {}});
    iface.updateProperties(ObjectId{1}, PropertyDelta{true, ObjectId{2}});
    iface.withdraw(ObjectId{2});

    EXPECT_EQ(tx.publishedReaders.size(), 1u);
    EXPECT_EQ(tx.publishedCards.size(), 1u);
    EXPECT_EQ(tx.propertyUpdates.size(), 1u);
    ASSERT_EQ(tx.withdrawn.size(), 1u);
    EXPECT_EQ(tx.withdrawn[0], ObjectId{2});

    int ran = 0;
    iface.post([&ran] { ++ran; });
    EXPECT_EQ(ran, 0); // recorded, not yet run
    tx.runPosted();
    EXPECT_EQ(ran, 1);

    // Additive multi-subscriber: EVERY registered handler fires, in registration
    // order, on each disconnect (production wires op auto-cancel then lease revoke).
    std::vector<int> order;
    CallerToken gone;
    iface.onClientDisconnect([&order, &gone](CallerToken c) {
        order.push_back(1);
        gone = std::move(c);
    });
    iface.onClientDisconnect([&order](CallerToken) { order.push_back(2); });
    tx.fireDisconnect(CallerToken{":1.99"});
    EXPECT_EQ(gone, CallerToken{":1.99"});
    EXPECT_EQ(order, (std::vector<int>{1, 2}));
}

TEST(FakeLogSink, CapturesInjectedLines)
{
    FakeLogSink sink;
    sink.install();

    log::info("hello");
    log::warn("careful");

    // The facade hands the sink a fully-formatted line (priority prefix +
    // category + level + message + newline) together with the severity — the
    // fake captures both verbatim.
    ASSERT_EQ(sink.lines.size(), 2u);
    EXPECT_EQ(sink.lines[0].first, log::Level::Info);
    EXPECT_NE(sink.lines[0].second.find("hello"), std::string::npos);
    EXPECT_EQ(sink.lines[1].first, log::Level::Warn);
    EXPECT_NE(sink.lines[1].second.find("careful"), std::string::npos);
}
