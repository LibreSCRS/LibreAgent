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
#include <functional>
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

// Records every verify() call (by leaf DER) and answers either a fixed
// `verdict` or, when set, a per-call override keyed by the leaf DER --
// letting a test drive a distinct verdict per cert without depending on call
// order.
class FakeTrustVerifier final : public TrustVerifier
{
public:
    TrustVerdict verify(std::span<const std::uint8_t> leafDer, std::span<const std::vector<std::uint8_t>>) override
    {
        calls.emplace_back(leafDer.begin(), leafDer.end());
        if (verdictForDer) {
            return verdictForDer(calls.back());
        }
        return verdict;
    }
    TrustVerdict verdict{CertTrustStatus::Unknown, {}};
    std::function<TrustVerdict(const std::vector<std::uint8_t>&)> verdictForDer;
    std::vector<std::vector<std::uint8_t>> calls;
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
    FakeTrustVerifier trustVerifier;
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
        out.derBytes.push_back({0xAA});
        out.derBytes.push_back({0xBB});
        certReader.outcome = std::move(out);
    }

    CertReadFlow make()
    {
        holder = makeHolder(failWith);
        return CertReadFlow{CertReadFlowDeps{
            .holder = *holder,
            .certReader = certReader,
            .trustVerifier = trustVerifier,
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

namespace {

std::optional<std::string> securityField(const CertSnapshot& s, const std::string& token)
{
    for (const auto& g : s.fields) {
        if (g.groupKey != "security") {
            continue;
        }
        for (const auto& f : g.fields) {
            if (f.fieldKey == token) {
                return f.textValue;
            }
        }
    }
    return std::nullopt;
}

} // namespace

// The flow must call the injected TrustVerifier once per returned cert (fed
// its DER, index-aligned with the CertReadOutcome) and stitch each verdict's
// status/tokens into the matching CertSnapshot -- not a shared/global verdict
// applied to every cert alike.
TEST(CertReadFlow, CallsTrustVerifierPerCertAndAppliesEachVerdict)
{
    Harness h;
    h.trustVerifier.verdictForDer = [](const std::vector<std::uint8_t>& der) -> TrustVerdict {
        if (der == std::vector<std::uint8_t>{0xAA}) {
            return TrustVerdict{CertTrustStatus::Trusted, {"trusted"}};
        }
        return TrustVerdict{CertTrustStatus::Expired, {"expired"}};
    };

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, CertReadFlow::Outcome::Ok);
    ASSERT_EQ(result.certs.size(), 2u);
    ASSERT_EQ(h.trustVerifier.calls.size(), 2u);

    EXPECT_EQ(result.certs[0].trustStatus, static_cast<std::uint32_t>(CertTrustStatus::Trusted));
    EXPECT_EQ(result.certs[0].securityStatus, std::vector<std::string>{"trusted"});
    EXPECT_EQ(securityField(result.certs[0], "trusted"), "trusted");

    EXPECT_EQ(result.certs[1].trustStatus, static_cast<std::uint32_t>(CertTrustStatus::Expired));
    EXPECT_EQ(result.certs[1].securityStatus, std::vector<std::string>{"expired"});
    EXPECT_EQ(securityField(result.certs[1], "expired"), "expired");
}

// Every verdict the closed vocabulary defines round-trips through the flow:
// numeric trustStatus + the matching single security-status token, each
// riding the "security" fields-group.
class CertReadFlowVerdictTest : public ::testing::TestWithParam<std::pair<CertTrustStatus, std::string>>
{};

TEST_P(CertReadFlowVerdictTest, MapsStatusAndToken)
{
    const auto [status, token] = GetParam();
    Harness h;
    h.trustVerifier.verdict = TrustVerdict{status, {token}};

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, CertReadFlow::Outcome::Ok);
    for (const auto& cert : result.certs) {
        EXPECT_EQ(cert.trustStatus, static_cast<std::uint32_t>(status));
        EXPECT_EQ(cert.securityStatus, std::vector<std::string>{token});
        EXPECT_EQ(securityField(cert, token), token);
    }
}

INSTANTIATE_TEST_SUITE_P(
    EachVerdict, CertReadFlowVerdictTest,
    ::testing::Values(std::pair{CertTrustStatus::Trusted, std::string{"trusted"}},
                     std::pair{CertTrustStatus::UntrustedRoot, std::string{"untrusted-root"}},
                     std::pair{CertTrustStatus::BrokenChain, std::string{"broken-chain"}},
                     std::pair{CertTrustStatus::InvalidCertificate, std::string{"invalid"}},
                     std::pair{CertTrustStatus::Expired, std::string{"expired"}},
                     std::pair{CertTrustStatus::Revoked, std::string{"revoked"}},
                     std::pair{CertTrustStatus::OfflineUnverified, std::string{"offline-unverified"}}));

// The offline/no-TSL path is a VALID Ok outcome carrying OfflineUnverified +
// "offline-unverified" -- never an error, and never silently downgraded to
// the bare Unknown sentinel (which stays reserved for "no verdict tokens at
// all", asserted separately below).
TEST(CertReadFlow, OfflinePathYieldsOfflineUnverifiedNotError)
{
    Harness h;
    h.trustVerifier.verdict = TrustVerdict{CertTrustStatus::OfflineUnverified, {"offline-unverified"}};

    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Ok);
    EXPECT_EQ(result.code, ErrorCode::None);
    ASSERT_EQ(result.certs.size(), 2u);
    for (const auto& cert : result.certs) {
        EXPECT_EQ(cert.trustStatus, static_cast<std::uint32_t>(CertTrustStatus::OfflineUnverified));
        EXPECT_EQ(cert.securityStatus, std::vector<std::string>{"offline-unverified"});
    }
}

// A verdict with NO tokens (plain Unknown, never assessed) must not append a
// stray empty "security" group to the wire fields dict.
TEST(CertReadFlow, EmptySecurityStatusAppendsNoSecurityGroup)
{
    Harness h;
    h.trustVerifier.verdict = TrustVerdict{CertTrustStatus::Unknown, {}};

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, CertReadFlow::Outcome::Ok);
    for (const auto& cert : result.certs) {
        EXPECT_EQ(cert.trustStatus, static_cast<std::uint32_t>(CertTrustStatus::Unknown));
        EXPECT_TRUE(cert.securityStatus.empty());
        for (const auto& g : cert.fields) {
            EXPECT_NE(g.groupKey, "security");
        }
    }
}
