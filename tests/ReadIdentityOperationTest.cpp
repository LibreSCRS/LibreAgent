// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Worker-side semantics. A fake OperationChannel captures emits; Fake seams
// drive the flow. No bus, no LM.

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/ReadIdentityOperation.h>

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include "fakes/FakeLogSink.h"
#include "operations/GroupRelay.h"
#include "operations/IdentityGroupFeed.h"
#include <gtest/gtest.h>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <sstream>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

struct EmittedFinish
{
    std::uint32_t status;
    std::uint32_t errorCode;
};

class FakeOperationChannel final : public OperationChannel
{
public:
    void emitFinished(OperationStatus status, ErrorCode errorCode, std::string_view, std::string_view) noexcept override
    {
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(errorCode)});
    }
    void emitPropertiesChanged() noexcept override {}
    bool emitResult(const ResultPayload& result) noexcept override
    {
        if (const auto* snap = std::get_if<CardReadSnapshot>(&result)) {
            identityEmits.push_back(*snap);
        }
        return deliver;
    }
    void emitGroup(const GroupSnapshot& group) noexcept override
    {
        if (onGroup) {
            onGroup(group.groupKey);
        }
        groupKeys.push_back(group.groupKey);
    }
    std::function<void(const std::string&)> onGroup; ///< runs just before a group is recorded
    std::vector<std::string> groupKeys;
    bool deliver = true; ///< false models a channel that fails to encode or post
    std::vector<EmittedFinish> finishes;
    std::vector<CardReadSnapshot> identityEmits;
};
static_assert(std::variant_size_v<ResultPayload> == 6,
              "ResultPayload is a closed variant: 5 Card1 result arms (Identity/Certificates/Photo/Sign/SignBatch) + "
              "the Credentials1 arm");

inline std::unique_ptr<CardSessionHolder> makeHolder()
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
                     GroupReadCallback onGroup = {}) override
    {
        ++reads;
        // Stream the groups of the outcome, as a plugin does, ahead of returning it.
        if (onGroup && outcome.snapshot) {
            for (const auto& group : outcome.snapshot->groups) {
                onGroup(group);
            }
        }
        return outcome;
    }
    // Not exercised by this suite (ReadTokenInfoOperationTest owns dedicated
    // coverage); a well-formed default keeps this class non-abstract.
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
    ReadOutcome outcome;
    int reads = 0; ///< how many times the card was actually walked
};
// These suites never renegotiate a CAN prompt into an MRZ read (their fake
// readers prompt for nothing), so the ready-made no-op deposit seam keeps the
// operation's reference well-formed without a plugin registry.
NullCredentialDepositor depositor;

class FakePrompter final : public PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
};

CardReadSnapshot snapshotWithPhoto()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    snap.groups.push_back({"personal",
                           "group.personal",
                           "Personal",
                           {{"given_name", "field.given_name", "Given name", FieldType::Text, "ANA", {}}}});
    snap.groups.push_back({"photo",
                           "group.photo",
                           "Photo",
                           {{"portrait", "field.portrait", "Portrait", FieldType::Photo, "", {0xFF, 0xD8, 0xFF}}}});
    return snap;
}

} // namespace

TEST(ReadIdentityOperation, SuccessPathPopulatesCacheEmitsResultThenFinishes)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, snapshotWithPhoto(), ""};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    ReadIdentityOperation op(std::move(adaptor),
                             ReadIdentityOperation::Deps{
                                 .holder = holder.get(),
                                 .reader = reader,
                                 .depositor = depositor,
                                 .prompter = prompter,
                                 .serializer = serializer,
                                 .credentials = credCache,
                                 .readCache = readCache,
                                 .cardKey = "card-A",
                                 .readerName = "FakeReader",
                                 .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
                             },
                             state);

    std::stringstream captured;
    std::streambuf* saved = std::clog.rdbuf(captured.rdbuf());
    op.runOnWorker();
    std::clog.rdbuf(saved);
    const std::string logged = captured.str();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, 0u) << "OperationStatus::Ok";
    EXPECT_EQ(raw->finishes[0].errorCode, 0u);

    ASSERT_EQ(raw->identityEmits.size(), 1u);
    EXPECT_EQ(raw->identityEmits[0].cardType, "rs-eid");

    auto cached = readCache.get("card-A");
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->groups.size(), 2u) << "cache stores the full snapshot (photos included)";

    // The flow's audit line must name THIS reader, not read empty -- proving
    // ReadIdentityOperation.cpp's `.readerName = m_deps.readerName,` forward
    // actually reaches the flow (content asserted at the LA level; this is
    // the one LL-side check that a regression dropping the forward would
    // still be caught here, not only at LA).
    EXPECT_NE(logged.find("reader=\"FakeReader\""), std::string::npos) << logged;
}

// A re-read of a still-seated card (master-detail browsing / a reader switch
// back to it) must be served from the per-card read cache — the same cache
// GetPhoto already consults and that ReadIdentity itself populates — instead of
// re-walking the eID data groups. Without this the identity half of the cache
// is write-only from ReadIdentity's side, so every switch re-reads the card
// (the "reader switch is slow" symptom).
TEST(ReadIdentityOperation, SecondReadOfSameCardServesFromCacheWithoutReWalking)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, snapshotWithPhoto(), ""};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    // First ReadIdentity: walks the card, populates the cache, emits the result.
    {
        auto adaptor = std::make_unique<FakeOperationChannel>();
        auto* raw = adaptor.get();
        auto state = std::make_shared<OperationState>();
        ReadIdentityOperation op(std::move(adaptor),
                                 ReadIdentityOperation::Deps{
                                     .holder = holder.get(),
                                     .reader = reader,
                                     .depositor = depositor,
                                     .prompter = prompter,
                                     .serializer = serializer,
                                     .credentials = credCache,
                                     .readCache = readCache,
                                     .cardKey = "card-A",
                                     .readerName = "FakeReader",
                                     .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
                                 },
                                 state);
        op.runOnWorker();
        ASSERT_EQ(raw->finishes.size(), 1u);
        EXPECT_EQ(raw->finishes[0].status, 0u);
        ASSERT_EQ(raw->identityEmits.size(), 1u);
    }
    ASSERT_EQ(reader.reads, 1) << "the first read walks the card";
    ASSERT_TRUE(readCache.get("card-A").has_value()) << "the first read populates the cache";

    // Second ReadIdentity on the SAME still-seated card: served from cache — no
    // second card walk — yet it still emits the typed result and finishes Ok.
    {
        auto adaptor = std::make_unique<FakeOperationChannel>();
        auto* raw = adaptor.get();
        auto state = std::make_shared<OperationState>();
        ReadIdentityOperation op(std::move(adaptor),
                                 ReadIdentityOperation::Deps{
                                     .holder = holder.get(),
                                     .reader = reader,
                                     .depositor = depositor,
                                     .prompter = prompter,
                                     .serializer = serializer,
                                     .credentials = credCache,
                                     .readCache = readCache,
                                     .cardKey = "card-A",
                                     .readerName = "FakeReader",
                                     .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
                                 },
                                 state);
        op.runOnWorker();
        ASSERT_EQ(raw->finishes.size(), 1u);
        EXPECT_EQ(raw->finishes[0].status, 0u) << "a cached re-read still finishes Ok";
        ASSERT_EQ(raw->identityEmits.size(), 1u) << "a cached re-read still emits Identity1.Result";
        EXPECT_EQ(raw->identityEmits[0].cardType, "rs-eid");
    }
    EXPECT_EQ(reader.reads, 1) << "a second ReadIdentity on the same seated card must NOT re-walk it";
}

// A cache hit is where a client's read of personal data now lands (the
// background read fills the cache first), so it must leave the same audit line
// the card walk does -- and never a field value.
TEST(ReadIdentityOperation, CacheHitLogsTheRequest)
{
    FakeLogSink sink;
    sink.install();
    CardReadSnapshot snap = snapshotWithPhoto();
    snap.groups[0].fields[0].textValue = "ZORAN-DISTINCT-VALUE";
    CardReadCache readCache;
    readCache.put("card-A", snap);
    auto holder = makeHolder();
    FakeReader reader;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;

    auto state = std::make_shared<OperationState>();
    ReadIdentityOperation op(std::make_unique<FakeOperationChannel>(),
                             ReadIdentityOperation::Deps{
                                 .holder = holder.get(),
                                 .reader = reader,
                                 .depositor = depositor,
                                 .prompter = prompter,
                                 .serializer = serializer,
                                 .credentials = credCache,
                                 .readCache = readCache,
                                 .cardKey = "card-A",
                                 .readerName = "FakeReader",
                                 .requester = "firefox",
                                 .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
                             },
                             state);
    op.runOnWorker();

    ASSERT_EQ(reader.reads, 0) << "the cache must have served the read";
    std::string all;
    for (const auto& [level, line] : sink.lines) {
        all += line;
    }
    EXPECT_NE(all.find("identity read requested"), std::string::npos) << all;
    EXPECT_NE(all.find("requester=firefox"), std::string::npos) << all;
    EXPECT_NE(all.find("card=card-A"), std::string::npos) << all;
    EXPECT_NE(all.find("(cache)"), std::string::npos) << all;
    EXPECT_EQ(all.find("ZORAN-DISTINCT-VALUE"), std::string::npos) << "a field value reached the log";
}

TEST(ReadIdentityOperation, FlowErrorMapsToFinishedError)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::CommunicationError, std::nullopt, "card removed"};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    ReadIdentityOperation op(std::move(adaptor),
                             ReadIdentityOperation::Deps{
                                 .holder = holder.get(),
                                 .reader = reader,
                                 .depositor = depositor,
                                 .prompter = prompter,
                                 .serializer = serializer,
                                 .credentials = credCache,
                                 .readCache = readCache,
                                 .cardKey = "card-A",
                                 .readerName = "FakeReader",
                                 .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
                             },
                             state);
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, 2u) << "OperationStatus::Error";
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
    EXPECT_TRUE(raw->identityEmits.empty()) << "no Identity1.Result on error path";
    EXPECT_FALSE(readCache.get("card-A").has_value()) << "cache not populated on error";
}

// A result the channel fails to deliver must not finish Ok: the client would
// get Finished(Ok) with no Result. Both the card walk and the cache hit.
TEST(ReadIdentityOperation, UndeliveredResultFinishesErrorOnWalkAndCacheHit)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, snapshotWithPhoto(), ""};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    for (int run = 0; run < 2; ++run) {
        auto adaptor = std::make_unique<FakeOperationChannel>();
        adaptor->deliver = false;
        auto* raw = adaptor.get();
        ReadIdentityOperation op(std::move(adaptor),
                                 ReadIdentityOperation::Deps{
                                     .holder = holder.get(),
                                     .reader = reader,
                                     .depositor = depositor,
                                     .prompter = prompter,
                                     .serializer = serializer,
                                     .credentials = credCache,
                                     .readCache = readCache,
                                     .cardKey = "card-A",
                                     .readerName = "FakeReader",
                                     .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
                                 },
                                 std::make_shared<OperationState>());
        op.runOnWorker();
        ASSERT_EQ(raw->finishes.size(), 1u) << "run " << run;
        EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
        EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
    }
    EXPECT_EQ(reader.reads, 1) << "the second run was the cache hit";
}

// --- attached to a background read of the same card --------------------------

namespace {

struct AttachRig
{
    std::unique_ptr<CardSessionHolder> holder = makeHolder();
    FakeReader reader;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;
    std::shared_ptr<OperationState> state = std::make_shared<OperationState>();
    FakeOperationChannel* channel = nullptr;

    AttachRig()
    {
        reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, snapshotWithPhoto(), ""};
    }

    std::unique_ptr<ReadIdentityOperation> makeOp(const std::string& cardKey = "card-A")
    {
        auto adaptor = std::make_unique<FakeOperationChannel>();
        channel = adaptor.get();
        return std::make_unique<ReadIdentityOperation>(
            std::move(adaptor),
            ReadIdentityOperation::Deps{
                .holder = holder.get(),
                .reader = reader,
                .depositor = depositor,
                .prompter = prompter,
                .serializer = serializer,
                .credentials = credCache,
                .readCache = readCache,
                .cardKey = cardKey,
                .readerName = "FakeReader",
                .requester = "firefox",
                .refusalGenerationAtPublish = LibreSCRS::Agent::PublishedRefusalGeneration{0},
            },
            state);
    }
};

GroupSnapshot groupWithKey(const std::string& key)
{
    return {key, "group." + key, key, {{"f", "field.f", "F", FieldType::Text, "V-" + key, {}}}};
}

std::string joined(const FakeLogSink& sink)
{
    std::string all;
    for (const auto& [level, line] : sink.lines) {
        all += line;
    }
    return all;
}

std::size_t occurrences(const std::string& text, const std::string& what)
{
    std::size_t n = 0;
    for (auto at = text.find(what); at != std::string::npos; at = text.find(what, at + 1)) {
        ++n;
    }
    return n;
}

} // namespace

TEST(ReadIdentityOperation, FollowsOnlyAnOpenFeedOfItsOwnCard)
{
    AttachRig rig;
    auto op = rig.makeOp("card-A");

    IdentityGroupFeed notOpen("card-A");
    EXPECT_FALSE(op->followIdentityGroupFeed(notOpen)) << "attached to a feed that had not begun";
    EXPECT_FALSE(op->groupRelay());

    IdentityGroupFeed other("card-B");
    other.beginRead();
    EXPECT_FALSE(op->followIdentityGroupFeed(other)) << "attached to another card's feed";

    IdentityGroupFeed own("card-A");
    own.beginRead();
    const auto relay = op->followIdentityGroupFeed(own);
    ASSERT_TRUE(relay);
    EXPECT_EQ(op->groupRelay(), relay);

    IdentityGroupFeed second("card-A");
    second.beginRead();
    EXPECT_FALSE(op->followIdentityGroupFeed(second)) << "an op follows one feed only";
    EXPECT_EQ(op->groupRelay(), relay);
    relay->closeAndWait();
}

// The audit line of the background source is written when the op attaches --
// before any group can be emitted from it -- and nothing else is added for it.
TEST(ReadIdentityOperation, AttachingWritesTheBackgroundReadLineBeforeTheFirstGroup)
{
    FakeLogSink sink;
    sink.install();
    AttachRig rig;
    auto op = rig.makeOp();
    IdentityGroupFeed feed("card-A");
    feed.beginRead();
    feed.record(groupWithKey("early"));
    const auto relay = op->followIdentityGroupFeed(feed);
    ASSERT_TRUE(relay);

    std::size_t linesAtFirstGroup = 0;
    rig.channel->onGroup = [&](const std::string&) {
        if (linesAtFirstGroup == 0) {
            linesAtFirstGroup = occurrences(joined(sink), "(background read)");
        }
    };
    EXPECT_EQ(occurrences(joined(sink), "(background read)"), 1u) << joined(sink);
    EXPECT_TRUE(rig.channel->groupKeys.empty()) << "a group was emitted before the release";

    relay->release();
    EXPECT_EQ(rig.channel->groupKeys, (std::vector<std::string>{"early"}));
    EXPECT_EQ(linesAtFirstGroup, 1u) << "the first group went out before its audit line";
    EXPECT_NE(joined(sink).find("requester=firefox"), std::string::npos);
    EXPECT_NE(joined(sink).find("card=card-A"), std::string::npos);
    relay->closeAndWait();
}

TEST(ReadIdentityOperation, AnAttachedCacheHitAddsNoCacheLine)
{
    FakeLogSink sink;
    sink.install();
    AttachRig rig;
    rig.readCache.put("card-A", snapshotWithPhoto());
    auto op = rig.makeOp();
    IdentityGroupFeed feed("card-A");
    feed.beginRead();
    ASSERT_TRUE(op->followIdentityGroupFeed(feed));
    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 0);
    ASSERT_EQ(rig.channel->finishes.size(), 1u);
    EXPECT_EQ(rig.channel->identityEmits.size(), 1u);
    const auto all = joined(sink);
    EXPECT_EQ(occurrences(all, "identity read requested"), 1u) << all;
    EXPECT_EQ(occurrences(all, "(background read)"), 1u) << all;
    EXPECT_EQ(all.find("(cache)"), std::string::npos) << all;
    EXPECT_TRUE(op->groupRelay()->isClosed()) << "doWork closes the relay before it uses the cache";
}

// The background read failed: the op reads the card itself (its own line is
// written), and a group it already delivered is not sent again.
TEST(ReadIdentityOperation, AfterAFailedBackgroundReadItReadsAndSkipsWhatItAlreadyDelivered)
{
    FakeLogSink sink;
    sink.install();
    AttachRig rig;
    auto op = rig.makeOp();
    IdentityGroupFeed feed("card-A");
    feed.beginRead();
    const auto relay = op->followIdentityGroupFeed(feed);
    ASSERT_TRUE(relay);
    feed.record(groupWithKey("personal"));
    relay->release();
    ASSERT_EQ(rig.channel->groupKeys, (std::vector<std::string>{"personal"}));
    feed.close(); // the read ended without a snapshot in the cache

    op->runOnWorker();

    EXPECT_EQ(rig.reader.reads, 1) << "the op reads the card for its caller";
    EXPECT_EQ(rig.channel->groupKeys, (std::vector<std::string>{"personal", "photo"}))
        << "'personal' must not be sent twice";
    ASSERT_EQ(rig.channel->identityEmits.size(), 1u);
    EXPECT_EQ(rig.channel->identityEmits[0].groups.size(), 2u) << "the Result is always the whole snapshot";
    ASSERT_EQ(rig.channel->finishes.size(), 1u);
    const auto all = joined(sink);
    EXPECT_EQ(occurrences(all, "(background read)"), 1u) << all;
    EXPECT_EQ(occurrences(all, "identity read requested"), 2u) << "its own read adds its own line: " << all;
}

TEST(ReadIdentityOperation, AnUnattachedOpStreamsEveryGroupAsBefore)
{
    AttachRig rig;
    auto op = rig.makeOp();
    op->runOnWorker();
    EXPECT_EQ(rig.channel->groupKeys, (std::vector<std::string>{"personal", "photo"}));
    EXPECT_FALSE(op->groupRelay());
}

// A path that ends an attached op without closing its relay would leave a
// possible emit into a freed op: the destructor says so and closes it.
TEST(ReadIdentityOperation, DestroyingAnAttachedOpWithAnOpenRelayIsLoggedAndClosesIt)
{
    FakeLogSink sink;
    sink.install();
    AttachRig rig;
    std::shared_ptr<GroupRelay> relay;
    {
        auto op = rig.makeOp();
        IdentityGroupFeed feed("card-A");
        feed.beginRead();
        relay = op->followIdentityGroupFeed(feed);
        ASSERT_TRUE(relay);
    }
    EXPECT_TRUE(relay->isClosed());
    bool errorLogged = false;
    for (const auto& [level, line] : sink.lines) {
        errorLogged = errorLogged || level == LibreSCRS::log::Level::Error;
    }
    EXPECT_TRUE(errorLogged) << joined(sink);
}

TEST(ReadIdentityOperation, ARelayClosedBeforeDestructionIsNotAnError)
{
    FakeLogSink sink;
    sink.install();
    AttachRig rig;
    {
        auto op = rig.makeOp();
        IdentityGroupFeed feed("card-A");
        feed.beginRead();
        const auto relay = op->followIdentityGroupFeed(feed);
        ASSERT_TRUE(relay);
        relay->closeAndWait();
    }
    for (const auto& [level, line] : sink.lines) {
        EXPECT_NE(level, LibreSCRS::log::Level::Error) << line;
    }
}
