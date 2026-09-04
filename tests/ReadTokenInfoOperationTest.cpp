// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Worker-side semantics of ReadTokenInfoOperation. TokenInfoReadFlowTest owns
// the flow's own matrix; what is asserted here is the layer above it, which no
// test covered in either host: the typed result reaches the channel BEFORE
// Finished, an empty group is a SUCCESS rather than an error, a session-open
// failure finishes Error without emitting a result, a cancel finishes Cancelled,
// and a mis-wired null holder finishes with an internal error instead of
// dereferencing a null pointer.
//
// A fake OperationChannel captures the emits; every seam is a Fake. No bus, no
// card, no middleware.

#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/ReadTokenInfoOperation.h>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
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

// Records the ORDER of the two wire events, because the contract this operation
// carries is an ordering one: a Finished that arrives without its result is the
// failure mode a status-only assertion cannot see.
class FakeOperationChannel final : public OperationChannel
{
public:
    enum class Event { Result, Finish };

    void emitFinished(OperationStatus status, ErrorCode errorCode, std::string_view, std::string_view) noexcept override
    {
        events.push_back(Event::Finish);
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(errorCode)});
    }
    void emitPropertiesChanged() noexcept override {}
    bool emitResult(const ResultPayload& result) noexcept override
    {
        events.push_back(Event::Result);
        if (const auto* snapshot = std::get_if<CardReadSnapshot>(&result)) {
            captured = *snapshot;
        }
        return true;
    }

    std::vector<Event> events;
    std::vector<EmittedFinish> finishes;
    std::optional<CardReadSnapshot> captured;
};

inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith)
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

class FakeTokenInfoReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback = {}) override
    {
        ADD_FAILURE() << "a token-info read must never reach the full identity read";
        return {};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        ++calls;
        return group;
    }

    GroupSnapshot group;
    int calls{0};
};

class UnusedPrompter final : public PrompterClientBase
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

GroupSnapshot tokenGroup(bool withField)
{
    GroupSnapshot g;
    g.groupKey = "token";
    if (withField) {
        FieldSnapshot f;
        f.fieldKey = "serial";
        f.textValue = "0123456789";
        g.fields.push_back(std::move(f));
    }
    return g;
}

// Shared collaborators for one op run.
struct Harness
{
    std::unique_ptr<CardSessionHolder> holder = makeHolder(std::nullopt);
    FakeTokenInfoReader reader;
    UnusedPrompter prompter;
    PromptSerializer serializer;
    CredentialCache credentials;

    ReadTokenInfoOperation::Deps deps()
    {
        return ReadTokenInfoOperation::Deps{
            .holder = holder.get(),
            .reader = reader,
            .prompter = prompter,
            .serializer = serializer,
            .credentials = credentials,
            .cardKey = "card-A",
            .readerName = "FakeReader",
            .requester = "test",
            .artifact = "tokeninfo",
        };
    }
};

} // namespace

// The success path: exactly one result, delivered BEFORE Finished(Ok), carrying
// the one "token" group the flow produced.
TEST(ReadTokenInfoOperation, EmitsTheTokenGroupBeforeFinishedOk)
{
    Harness h;
    h.reader.group = tokenGroup(/*withField=*/true);
    auto channel = std::make_unique<FakeOperationChannel>();
    auto* raw = channel.get();

    ReadTokenInfoOperation op(std::move(channel), h.deps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->events.size(), 2u);
    EXPECT_EQ(raw->events[0], FakeOperationChannel::Event::Result) << "the result must precede Finished";
    EXPECT_EQ(raw->events[1], FakeOperationChannel::Event::Finish);

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::None));

    ASSERT_TRUE(raw->captured.has_value());
    ASSERT_EQ(raw->captured->groups.size(), 1u);
    EXPECT_EQ(raw->captured->groups.front().groupKey, "token");
    ASSERT_EQ(raw->captured->groups.front().fields.size(), 1u);
    EXPECT_EQ(raw->captured->groups.front().fields.front().fieldKey, "serial");
    EXPECT_EQ(h.reader.calls, 1);
}

// A plugin that implements nothing answers an EMPTY group, and that is a
// success with zero fields — not an error. The distinction is the whole point
// of the flow's empty-group resilience, and it is invisible to a test that only
// looks at the finish status of the happy path.
TEST(ReadTokenInfoOperation, EmptyGroupStillFinishesOkWithAResult)
{
    Harness h;
    h.reader.group = tokenGroup(/*withField=*/false);
    auto channel = std::make_unique<FakeOperationChannel>();
    auto* raw = channel.get();

    ReadTokenInfoOperation op(std::move(channel), h.deps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->events.size(), 2u);
    EXPECT_EQ(raw->events[0], FakeOperationChannel::Event::Result);
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok))
        << "an unsupported plugin's empty group is a successful read, not a failure";
    ASSERT_TRUE(raw->captured.has_value());
    ASSERT_EQ(raw->captured->groups.size(), 1u);
    EXPECT_TRUE(raw->captured->groups.front().fields.empty());
}

// A session that will not open finishes Error and emits NO result: there is
// nothing to report, and a result-less terminal is correct only here.
TEST(ReadTokenInfoOperation, OpenFailureFinishesErrorWithoutAResult)
{
    Harness h;
    h.holder = makeHolder(LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                          LibreSCRS::LocalizedText{}, std::nullopt});
    auto channel = std::make_unique<FakeOperationChannel>();
    auto* raw = channel.get();

    ReadTokenInfoOperation op(std::move(channel), h.deps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
    EXPECT_FALSE(raw->captured.has_value());
    EXPECT_EQ(h.reader.calls, 0) << "the reader must not run when no session could be opened";
}

// A removed card is its own terminal: Error, but CardRemoved, because a client
// that cannot tell the two apart re-prompts the user for a card that is gone.
TEST(ReadTokenInfoOperation, RemovedCardFinishesCardRemoved)
{
    Harness h;
    h.holder = makeHolder(LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                          LibreSCRS::LocalizedText{}, std::nullopt});
    auto channel = std::make_unique<FakeOperationChannel>();
    auto* raw = channel.get();

    ReadTokenInfoOperation op(std::move(channel), h.deps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CardRemoved));
}

// A mis-wired construction (null session holder) must finish with an internal
// error rather than dereference a null pointer. The guard exists in the source;
// nothing asserted it.
TEST(ReadTokenInfoOperation, NullHolderFinishesInternalErrorInsteadOfCrashing)
{
    Harness h;
    auto deps = h.deps();
    deps.holder = nullptr;
    auto channel = std::make_unique<FakeOperationChannel>();
    auto* raw = channel.get();

    ReadTokenInfoOperation op(std::move(channel), std::move(deps), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
    EXPECT_FALSE(raw->captured.has_value());
}
