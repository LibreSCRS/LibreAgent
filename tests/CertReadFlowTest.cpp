// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of CertReadFlow. Every seam is a Fake; the flow runs
// synchronously on the test thread. The agent-side X.509 parsing
// (LmCertificateReader) is validated end-to-end on hardware — here the
// FakeCertReader returns canned CertSnapshots so the orchestration + the
// open/classify/install-provider prelude + status mapping are exercised
// without a real card.
#include <LibreSCRS/Agent/cache/AttemptContext.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/CertReadFlow.h>
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (the card's re-prompt signal)
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <atomic>
#include <cstdint>
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
    CertReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList&,
                         LibreSCRS::CancelToken) override
    {
        ++reads;
        // Production LM invokes the flow-installed credential provider from
        // INSIDE readCertificates on a channel cache miss. CardSession exposes
        // no accessor for the installed provider, so a hermetic reader fake can
        // only model that callback through a hook the test wires to the flow's
        // own provider — see CertReadFlow::credentialProvider().
        if (onRead) {
            onRead(reads, session);
        }
        return outcome;
    }
    CertReadOutcome outcome;
    int reads = 0;
    // Called at the top of every read with the 1-based pass index.
    std::function<void(int, LibreSCRS::SmartCard::CardSession&)> onRead;
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
    PromptResult requestCan(const PromptOptions& opts) override
    {
        ++canPrompts;
        lastCanOptions = opts;
        if (canOverride.has_value()) {
            return *canOverride;
        }
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
    int canPrompts = 0;
    // Retry context the cache stamped onto the most recent CAN prompt.
    PromptOptions lastCanOptions;
    // Scripted reply for the CAN prompt, overriding the default (Error) above
    // -- lets a test simulate e.g. an expired entry window (Timeout).
    std::optional<PromptResult> canOverride;
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

LibreSCRS::Auth::AuthRequirement paceReq(LibreSCRS::Auth::PaceSecretKind kind)
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{}, kind, std::nullopt,
                                                           LibreSCRS::LocalizedText{});
}

// A PACE requirement carrying the rejected-retry reason LM sets ONLY on a
// re-prompt after a wrong-secret rejection in the same activation. The provider
// evicts and re-prompts on THIS shape, never on a bare same-kind re-invocation.
LibreSCRS::Auth::AuthRequirement rejectedPaceReq(LibreSCRS::Auth::PaceSecretKind kind)
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{}, kind, std::nullopt,
                                                           LibreSCRS::Auth::ErrorKeys::preReadAuthFailed());
}

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

INSTANTIATE_TEST_SUITE_P(EachVerdict, CertReadFlowVerdictTest,
                         ::testing::Values(std::pair{CertTrustStatus::Trusted, std::string{"trusted"}},
                                           std::pair{CertTrustStatus::UntrustedRoot, std::string{"untrusted-root"}},
                                           std::pair{CertTrustStatus::BrokenChain, std::string{"broken-chain"}},
                                           std::pair{CertTrustStatus::InvalidCertificate, std::string{"invalid"}},
                                           std::pair{CertTrustStatus::Expired, std::string{"expired"}},
                                           std::pair{CertTrustStatus::Revoked, std::string{"revoked"}},
                                           std::pair{CertTrustStatus::OfflineUnverified,
                                                     std::string{"offline-unverified"}}));

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

// --- The rejected pre-read secret is marked wrong EXACTLY once -------------

TEST(CertReadFlow, AuthFailedAfterProviderMarkedCountsOneAttempt)
{
    // The card rejected the pre-read secret and asked for it again, so the
    // provider already evicted + recorded that value on this operation's own
    // retry context. When the walk then unwinds as AuthFailed, the flow's own
    // mark must NOT count the SAME rejected value a second time: the
    // operation's attempt count is 1, not 2. An inflated count renders a
    // wrong attempt number and can evict one refusal early.
    Harness h;
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::AuthFailed, {}, "auth rejected"};

    auto flow = h.make();
    h.certReader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        // Models LM's on-cache-miss provider callback inside readCertificates,
        // carrying the card's re-prompt signal.
        static_cast<void>(flow.credentialProvider()(rejectedPaceReq(LibreSCRS::Auth::PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(flow.attemptContext().attempts(), 1u)
        << "one rejected value, one mark: the provider's mark and the flow's must not stack";
}

TEST(CertReadFlow, AuthFailedWithoutProviderMarkStillMarksCredentialWrong)
{
    // The counterpart pin: when the provider never saw a rejection signal (the
    // value now live for LM is UNMARKED), the flow's own mark is the only one
    // there is and must still fire — evicting the wrong secret AND recording
    // the retry context. Deleting the flow-side mark is NOT the fix for the
    // double count above.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"000000"});
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::AuthFailed, {}, "auth rejected"};

    auto flow = h.make();
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::AuthFailed);
    EXPECT_FALSE(h.cache.hasCan("card-A")) << "a wrong secret is evicted so a retry re-prompts";
    EXPECT_EQ(flow.attemptContext().attempts(), 1u) << "the flow recorded the retry context";
}

TEST(CertReadFlow, ExpiredPromptDoesNotMarkCredentialWrong)
{
    // An entry window that closed on the clock collected NOTHING. Treating the
    // activation failure that follows as a rejection would evict a value
    // nobody supplied and spend one of the three PACE attempts for free -- the
    // same defect fixed on the identity read path (see IdentityReadFlowTest's
    // test of the same name). The cert flow shares the credential provider
    // and this AuthFailed branch, so it shared the bug until the same guard
    // existed here too.
    Harness h;
    h.prompter.canOverride = PromptResult{PromptStatus::Timeout, std::nullopt, "expired"};
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::AuthFailed, {}, "auth failed"};

    auto flow = h.make();
    h.certReader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(LibreSCRS::Auth::PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.code, ErrorCode::EntryExpired);
    EXPECT_EQ(flow.attemptContext().attempts(), 0u)
        << "an expiry collected nothing, so it is not a rejection and must not count";
}

TEST(CertReadFlow, DismissedPromptCancelsAndDoesNotMarkCredentialWrong)
{
    // The cancel twin of the expiry test above, and the same shared provider
    // and AuthFailed branch, so the same defect: a dismissed window presented
    // NOTHING to the card, yet the activation failure that follows was charged
    // as a rejection and reported as AuthFailed -- blaming the card for the
    // holder's own decision and spending a PACE attempt on it.
    Harness h;
    h.prompter.canOverride = PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::AuthFailed, {}, "Authentication failed."};

    auto flow = h.make();
    h.certReader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(LibreSCRS::Auth::PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Cancelled)
        << "the holder dismissed the window -- that is a cancellation, not a card-side failure";
    EXPECT_EQ(result.code, ErrorCode::None);
    EXPECT_EQ(result.msgFallback.find("uthentication"), std::string::npos)
        << "no message may claim an authentication that was never attempted";
    EXPECT_EQ(flow.attemptContext().attempts(), 0u)
        << "a dismissal presented nothing, so it is not a rejection and must not count";
}

TEST(CertReadFlow, RefusedPromptSurfacesCapabilityMissingWithRemedyMessage)
{
    // The fourth signal, distinct from the three above: the agent REFUSED to
    // raise the prompt at all, because the helper is too old to be told which
    // window to dismiss. No discriminating test anywhere pinned the actual
    // remedy MESSAGE this reports -- only the code -- so a change or
    // truncation of the string (the one thing here the holder can act on)
    // would pass unnoticed.
    Harness h;
    h.prompter.canOverride = PromptResult{PromptStatus::HelperTooOld, std::nullopt, "helper out of date"};
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::AuthFailed, {}, "Authentication failed."};

    auto flow = h.make();
    h.certReader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(LibreSCRS::Auth::PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CapabilityMissing);
    // Pinned as a LITERAL, not FlowPrelude::kHelperTooOldMsgFallback: comparing
    // the result against the very same constant the flow copied it from would
    // pass no matter what that constant said -- it would just be checking the
    // pass-through, not the text. This is the actual remedy string, spelled out,
    // so an edit to the constant that changes what the holder is told breaks here.
    EXPECT_EQ(result.msgFallback, "The credential window helper is out of date; restart your session.")
        << "the remedy message must survive verbatim -- it is the one thing the holder can act on";
}

TEST(CertReadFlow, CredentialProviderIsClearedAtFlowExit)
{
    // The provider captures cache/prompter/serializer/phaseSink BY REFERENCE,
    // and every one of those is bounded by run(). A member left callable past
    // run() is a loaded gun pointed at dead references -- and it holds the
    // run's cardKey/requester/artifact captures alive with it.
    Harness h;
    auto flow = h.make();
    h.certReader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        EXPECT_TRUE(static_cast<bool>(flow.credentialProvider())) << "callable while the run is live";
    };
    static_cast<void>(flow.run());

    EXPECT_FALSE(static_cast<bool>(flow.credentialProvider())) << "and empty once run() has returned";
}

TEST(CertReadFlow, StructuralFailureLeavesTheCredentialAlone)
{
    // Only AuthFailed punishes the credential: a structural failure leaves the
    // cached secret and the attempt counter untouched.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    h.certReader.outcome = CertReadOutcome{CertReadOutcome::Status::UnsupportedCard, {}, "no PKI applet"};

    auto flow = h.make();
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, CertReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::UnsupportedCard);
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "a structural failure must never evict/punish the credential";
    EXPECT_EQ(flow.attemptContext().attempts(), 0u) << "and records no retry context";
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
