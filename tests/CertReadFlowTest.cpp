// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of CertReadFlow. Every seam is a Fake; the flow runs
// synchronously on the test thread. The agent-side X.509 parsing
// (LmCertificateReader) is validated end-to-end on hardware — here the
// FakeCertReader returns canned CertSnapshots so the orchestration + the
// open/classify/install-provider prelude + status mapping are exercised
// without a real card.
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/CertReadFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <expected>
#include <iostream>
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

class FakeCertReader final : public CertificateReader
{
public:
    CertReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken) override
    {
        return outcome;
    }
    CertReadOutcome outcome;
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

CertSnapshot makeCert(std::string id, bool signing)
{
    CertSnapshot c;
    c.certId = std::move(id);
    c.signingCapable = signing;
    GroupSnapshot g;
    g.groupKey = "subject";
    FieldSnapshot f;
    f.fieldKey = "cn";
    f.labelFallback = "Common Name";
    f.type = FieldType::Text;
    f.textValue = "Test Subject";
    g.fields.push_back(std::move(f));
    c.fields.push_back(std::move(g));
    return c;
}

struct Harness
{
    // Set BEFORE make() to drive an acquire failure (mirrors the old
    // FakeOpener.failWith); the holder is built lazily in make().
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    std::unique_ptr<CardSessionHolder> holder;
    FakeCertReader certReader;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    std::string requester = "test-client";

    Harness()
    {
        CertReadOutcome out;
        out.status = CertReadOutcome::Status::Ok;
        out.certs.push_back(makeCert("aa", /*signing=*/true));
        out.certs.push_back(makeCert("bb", /*signing=*/false));
        certReader.outcome = std::move(out);
    }

    CertReadFlow make()
    {
        holder = makeHolder(failWith);
        return CertReadFlow{CertReadFlowDeps{
            .holder = *holder,
            .certReader = certReader,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .reader = "FakeReader",
            .requester = requester,
            .artifact = "certificates",
            .token = source.token(),
        }};
    }
};

} // namespace

TEST(CertReadFlow, HappyPathReturnsParsedCerts)
{
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Ok);
    EXPECT_EQ(result.code, ErrorCode::None);
    ASSERT_EQ(result.certs.size(), 2u);
    EXPECT_EQ(result.certs[0].certId, "aa");
    EXPECT_TRUE(result.certs[0].signingCapable);
    EXPECT_FALSE(result.certs[1].signingCapable);
    auto acq = h.holder->acquire();
    ASSERT_TRUE(acq.has_value());
    EXPECT_TRUE(acq->session->hasCredentialProvider())
        << "the flow installs a credential provider on the held session (reset to a stateless no-op on exit)";
}

TEST(CertReadFlow, OpenErrorMapsToCommunicationError)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CommunicationError);
}

TEST(CertReadFlow, NoCardPresentMapsToCardRemoved)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CardRemoved);
}

TEST(CertReadFlow, ReadCommunicationErrorMapsThrough)
{
    Harness h;
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::CommunicationError, {}, "card gone"};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CommunicationError);
}

TEST(CertReadFlow, CancelTokenPreEmpts)
{
    Harness h;
    h.source.requestCancel();
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Cancelled);
    EXPECT_EQ(result.code, ErrorCode::None);
}

TEST(CertReadFlow, EmitsAuditLineNamingRequesterReaderAndCard)
{
    // A PIN-free cert read never reaches the consent prompt, so the resolved
    // requester would otherwise go unrecorded. The flow must emit one journald
    // audit line per request naming requester + reader + card path.
    std::stringstream captured;
    std::streambuf* saved = std::clog.rdbuf(captured.rdbuf());

    Harness h;
    h.requester = "seahorse";
    (void)h.make().run();

    std::clog.rdbuf(saved);
    const std::string out = captured.str();
    EXPECT_NE(out.find("certificate read"), std::string::npos) << out;
    EXPECT_NE(out.find("requester=seahorse"), std::string::npos) << out;
    EXPECT_NE(out.find("FakeReader"), std::string::npos) << out;
    EXPECT_NE(out.find("card-A"), std::string::npos) << out;
}

TEST(CertReadFlow, AuditLineMarksUnknownRequesterWhenEmpty)
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
