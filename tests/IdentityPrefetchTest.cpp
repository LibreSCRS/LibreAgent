// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The background identity read: it fills the per-card read cache and nothing
// else. The flow has no prompter and no secret cache to reach; the operation
// puts a snapshot only when nobody cancelled the read and the agent is not
// shutting down.
#include "operations/IdentityPrefetchFlow.h"
#include "operations/PrefetchIdentityOperation.h"

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include "fakes/FakeLogSink.h"

#include <gtest/gtest.h>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <utility>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

std::unique_ptr<CardSessionHolder> makeHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver));
}

class FakeReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback = {}) override
    {
        ++reads;
        if (duringRead) {
            duringRead();
        }
        return outcome;
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
    ReadOutcome outcome;
    int reads = 0;
    std::function<void()> duringRead; ///< runs inside the read, as a cancel racing it would
};

// A value that must never reach a log line.
constexpr const char* kSecretField = "ANA-SECRET-GIVEN-NAME";

CardReadSnapshot someSnapshot()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    snap.groups.push_back({"personal",
                           "group.personal",
                           "Personal",
                           {{"given_name", "field.given_name", "Given name", FieldType::Text, kSecretField, {}}}});
    return snap;
}

constexpr const char* kCard = "card-P";

struct Rig
{
    std::unique_ptr<CardSessionHolder> holder = makeHolder();
    FakeReader reader;
    CardReadCache readCache;
    std::string cardType;
    int cardTypeCalls = 0;
    LibreSCRS::CancelSource shutdown;

    Rig()
    {
        reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, someSnapshot(), ""};
    }

    std::unique_ptr<PrefetchIdentityOperation> makeOp()
    {
        auto op = std::make_unique<PrefetchIdentityOperation>(PrefetchIdentityOperation::Deps{
            .holder = holder.get(),
            .reader = reader,
            .readCache = readCache,
            .cardKey = kCard,
            .readerName = "FakeReader",
            .onCardType =
                [this](const std::string& t) {
                    cardType = t;
                    ++cardTypeCalls;
                },
        });
        op->bindShutdownToken(shutdown.token());
        return op;
    }

    IdentityPrefetchFlow::Result runFlow(LibreSCRS::CancelToken token)
    {
        IdentityPrefetchFlow flow(IdentityPrefetchFlowDeps{
            .holder = *holder,
            .reader = reader,
            .cardKey = kCard,
            .readerName = "FakeReader",
            .token = std::move(token),
            .onCardType =
                [this](const std::string& t) {
                    cardType = t;
                    ++cardTypeCalls;
                },
        });
        return flow.run();
    }
};

} // namespace

TEST(IdentityPrefetch, SuccessFillsTheCacheAndReportsCardType)
{
    Rig rig;
    auto op = rig.makeOp();
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 1);
    const auto cached = rig.readCache.get(kCard);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->groups.size(), 1u);
    EXPECT_EQ(rig.cardType, "rs-eid");
    EXPECT_EQ(rig.cardTypeCalls, 1);
}

TEST(IdentityPrefetch, CachedEntryCausesNoRead)
{
    Rig rig;
    rig.readCache.put(kCard, someSnapshot());
    auto op = rig.makeOp();
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 0);
    EXPECT_EQ(rig.cardTypeCalls, 0);
}

TEST(IdentityPrefetch, CancelBeforeReadReadsNothing)
{
    Rig rig;
    auto op = rig.makeOp();
    op->requestCancel();
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 0);
    EXPECT_FALSE(rig.readCache.get(kCard).has_value());
    EXPECT_EQ(rig.cardTypeCalls, 0);
}

TEST(IdentityPrefetch, CancelAfterReadSkipsThePut)
{
    Rig rig;
    auto op = rig.makeOp();
    rig.reader.duringRead = [&] { op->requestCancel(); };
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 1);
    EXPECT_FALSE(rig.readCache.get(kCard).has_value()) << "a cancelled prefetch must not write the cache";
    EXPECT_EQ(rig.cardTypeCalls, 0);
}

TEST(IdentityPrefetch, FlowReportsCancelledWhenTheTokenTripsDuringTheRead)
{
    Rig rig;
    LibreSCRS::CancelSource source;
    rig.reader.duringRead = [&] { source.requestCancel(); };
    const auto result = rig.runFlow(source.token());

    EXPECT_EQ(result.outcome, FlowOutcome::Cancelled);
    EXPECT_FALSE(result.snapshot.has_value());
    EXPECT_EQ(rig.cardTypeCalls, 0);
}

TEST(IdentityPrefetch, ShutdownAfterReadSkipsThePut)
{
    Rig rig;
    auto op = rig.makeOp();
    rig.reader.duringRead = [&] { rig.shutdown.requestCancel(); };
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 1);
    EXPECT_FALSE(rig.readCache.get(kCard).has_value()) << "a prefetch finished during shutdown must not write";
}

TEST(IdentityPrefetch, FailedReadSkipsThePut)
{
    Rig rig;
    rig.reader.outcome = ReadOutcome{ReadOutcome::Status::AuthFailed, std::nullopt, "wrong secret"};
    auto op = rig.makeOp();
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 1);
    EXPECT_FALSE(rig.readCache.get(kCard).has_value());
    EXPECT_EQ(rig.cardTypeCalls, 0);
}

TEST(IdentityPrefetch, FlowMapsAFailedReadToItsErrorCode)
{
    Rig rig;
    rig.reader.outcome = ReadOutcome{ReadOutcome::Status::AuthFailed, std::nullopt, "wrong secret"};
    const auto result = rig.runFlow(LibreSCRS::CancelToken{});

    EXPECT_EQ(result.outcome, FlowOutcome::Error);
    EXPECT_EQ(result.code, ErrorCode::AuthFailed);
    EXPECT_FALSE(result.snapshot.has_value());
}

TEST(IdentityPrefetch, PrefetchLogsWithoutFieldValues)
{
    FakeLogSink sink;
    sink.install();
    {
        Rig rig;
        rig.makeOp()->runOnWorker();
        Rig cached;
        cached.readCache.put(kCard, someSnapshot());
        cached.makeOp()->runOnWorker();
    }
    std::string all;
    for (const auto& [level, line] : sink.lines) {
        all += line;
    }
    EXPECT_NE(all.find("identity prefetch: reader=\"FakeReader\" card=card-P"), std::string::npos) << all;
    EXPECT_NE(all.find("identity prefetch done: card=card-P outcome=ok"), std::string::npos) << all;
    EXPECT_NE(all.find("identity prefetch done: card=card-P outcome=cached"), std::string::npos) << all;
    EXPECT_EQ(all.find(kSecretField), std::string::npos) << "a field value reached the log";
    EXPECT_EQ(all.find("rs-eid"), std::string::npos) << "the card type is read data too";
}

TEST(IdentityPrefetch, MissingHolderFailsAndIsLogged)
{
    FakeLogSink sink;
    sink.install();
    Rig rig;
    rig.holder.reset();
    rig.makeOp()->runOnWorker();
    std::string all;
    for (const auto& [level, line] : sink.lines) {
        all += line;
    }
    EXPECT_EQ(rig.reader.reads, 0);
    EXPECT_FALSE(rig.readCache.get(kCard).has_value());
    EXPECT_NE(all.find("identity prefetch done: card=card-P outcome=failed"), std::string::npos) << all;
}

// The background read is as unattended as a stuck card gets, so it runs under
// the same watchdog as every other operation: it arms once, at the start of the
// read. The arm is placed after the checks that do no card I/O, so a read that
// never touches the card never starts a timer.
TEST(IdentityPrefetch, TheReadArmsTheWatchdogOnce)
{
    Rig rig;
    auto op = rig.makeOp();
    op->runOnWorker();
    EXPECT_EQ(op->watchdogArmAttempts(), 1u);
}

TEST(IdentityPrefetch, ACachedEntryArmsNoWatchdog)
{
    Rig rig;
    rig.readCache.put(kCard, someSnapshot());
    auto op = rig.makeOp();
    op->runOnWorker();
    EXPECT_EQ(op->watchdogArmAttempts(), 0u);
}

TEST(IdentityPrefetch, AMissingHolderArmsNoWatchdog)
{
    Rig rig;
    rig.holder.reset();
    auto op = rig.makeOp();
    op->runOnWorker();
    EXPECT_EQ(op->watchdogArmAttempts(), 0u);
}
