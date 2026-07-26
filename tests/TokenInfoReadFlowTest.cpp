// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of TokenInfoReadFlow. Every seam is a Fake; the flow runs
// synchronously on the test thread. The agent-side pkcs15 TokenInfo read
// (LmCardReader::readTokenInfo) is validated end-to-end on hardware — here
// the FakeReader returns a canned GroupSnapshot so the orchestration + the
// open/install-provider prelude + the empty-group resilience are exercised
// without a real card.
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/TokenInfoReadFlow.h>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

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
        return {}; // not exercised by this flow
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return group;
    }
    GroupSnapshot group;
};

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

class RecordingPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t phase) noexcept override
    {
        phases.push_back(phase);
    }
    std::vector<std::uint32_t> phases;
};

// Matches LmCardReader::readTokenInfo's happy-path shape for a supporting
// plugin (pkcs15): groupKey "token", label/serial_number/manufacturer.
GroupSnapshot makeTokenGroup()
{
    GroupSnapshot g;
    g.groupKey = "token";
    g.labelKey = "group.token";
    g.labelFallback = "Token Info";
    FieldSnapshot label;
    label.fieldKey = "label";
    label.labelKey = "field.label";
    label.labelFallback = "Label";
    label.type = FieldType::Text;
    label.textValue = "Test Token";
    g.fields.push_back(label);
    FieldSnapshot serial;
    serial.fieldKey = "serial_number";
    serial.labelKey = "field.serial_number";
    serial.labelFallback = "Serial Number";
    serial.type = FieldType::Text;
    serial.textValue = "0123456789";
    g.fields.push_back(serial);
    FieldSnapshot manufacturer;
    manufacturer.fieldKey = "manufacturer";
    manufacturer.labelKey = "field.manufacturer";
    manufacturer.labelFallback = "Manufacturer";
    manufacturer.type = FieldType::Text;
    manufacturer.textValue = "LibreSCRS";
    g.fields.push_back(manufacturer);
    return g;
}

struct Harness
{
    // Set BEFORE make() to drive an acquire failure (mirrors CertReadFlowTest's
    // Harness); the holder is built lazily in make().
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    std::unique_ptr<CardSessionHolder> holder;
    FakeTokenInfoReader reader;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    std::string requester = "test-client";

    // Default-populated group so the success scenario doesn't have to set it.
    Harness()
    {
        reader.group = makeTokenGroup();
    }

    TokenInfoReadFlow make()
    {
        holder = makeHolder(failWith);
        return TokenInfoReadFlow{TokenInfoReadFlowDeps{
            .holder = *holder,
            .reader = reader,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .readerName = "FakeReader",
            .requester = requester,
            .artifact = "token",
            .token = source.token(),
        }};
    }
};

} // namespace

TEST(TokenInfoReadFlow, HappyPathReturnsOneTokenGroup)
{
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, TokenInfoReadFlow::Outcome::Ok);
    EXPECT_EQ(result.code, ErrorCode::None);
    ASSERT_TRUE(result.snapshot.has_value());
    ASSERT_EQ(result.snapshot->groups.size(), 1u);
    const GroupSnapshot& g = result.snapshot->groups.front();
    EXPECT_EQ(g.groupKey, "token");
    ASSERT_EQ(g.fields.size(), 3u);
    EXPECT_EQ(g.fields[0].fieldKey, "label");
    EXPECT_EQ(g.fields[0].textValue, "Test Token");
    EXPECT_EQ(g.fields[1].fieldKey, "serial_number");
    EXPECT_EQ(g.fields[2].fieldKey, "manufacturer");

    auto acq = h.holder->acquire();
    ASSERT_TRUE(acq.has_value());
    EXPECT_TRUE(acq->session->hasCredentialProvider())
        << "the flow installs a credential provider on the held session (reset to a stateless no-op on exit)";
}

// The spec's empty-group resilience: a plugin that does not implement
// readTokenInfo (the LM base default) — or that found nothing — answers a
// group with zero fields, which is SUCCESS, never an error.
TEST(TokenInfoReadFlow, EmptyGroupIsStillSuccess)
{
    Harness h;
    h.reader.group = GroupSnapshot{}; // as LmCardReader::readTokenInfo normalizes it
    h.reader.group.groupKey = "token";
    h.reader.group.labelKey = "group.token";
    h.reader.group.labelFallback = "Token Info";

    auto result = h.make().run();
    EXPECT_EQ(result.outcome, TokenInfoReadFlow::Outcome::Ok);
    EXPECT_EQ(result.code, ErrorCode::None);
    ASSERT_TRUE(result.snapshot.has_value());
    ASSERT_EQ(result.snapshot->groups.size(), 1u);
    EXPECT_EQ(result.snapshot->groups.front().groupKey, "token");
    EXPECT_TRUE(result.snapshot->groups.front().fields.empty());
}

TEST(TokenInfoReadFlow, OpenErrorMapsToCommunicationError)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, TokenInfoReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CommunicationError);
    EXPECT_FALSE(result.snapshot.has_value());
}

TEST(TokenInfoReadFlow, NoCardPresentMapsToCardRemoved)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, TokenInfoReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CardRemoved);
}

TEST(TokenInfoReadFlow, CancelTokenPreEmpts)
{
    Harness h;
    h.source.requestCancel();
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, TokenInfoReadFlow::Outcome::Cancelled);
    EXPECT_EQ(result.code, ErrorCode::None);
}

TEST(TokenInfoReadFlow, EmitsAuditLineNamingRequesterReaderAndCard)
{
    // A PIN-free-in-the-common-case token-info read never reaches the
    // consent prompt, so the resolved requester would otherwise go
    // unrecorded. The flow must emit one journald audit line per request
    // naming requester + reader + card path (mirrors CertReadFlow).
    std::stringstream captured;
    std::streambuf* saved = std::clog.rdbuf(captured.rdbuf());

    Harness h;
    h.requester = "seahorse";
    (void)h.make().run();

    std::clog.rdbuf(saved);
    const std::string out = captured.str();
    EXPECT_NE(out.find("token-info read"), std::string::npos) << out;
    EXPECT_NE(out.find("requester=seahorse"), std::string::npos) << out;
    EXPECT_NE(out.find("FakeReader"), std::string::npos) << out;
    EXPECT_NE(out.find("card-A"), std::string::npos) << out;
}

TEST(TokenInfoReadFlow, AuditLineMarksUnknownRequesterWhenEmpty)
{
    std::stringstream captured;
    std::streambuf* saved = std::clog.rdbuf(captured.rdbuf());

    Harness h;
    h.requester = ""; // best-effort caller-identity resolution failed
    (void)h.make().run();

    std::clog.rdbuf(saved);
    const std::string out = captured.str();
    EXPECT_NE(out.find("requester=unknown"), std::string::npos) << out;
}
