// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of IdentityReadFlow. Every seam is a Fake; the flow
// is run synchronously on the test thread.
//
// The plugin self-activates its secure channel inside readCard, so the flow
// no longer drives channel activation. The credential provider is installed
// unconditionally; the FakeReader stands in for readCard and the test drives
// the captured provider directly to assert the AwaitingConsent transition
// (production LM invokes it inside readCard on a channel cache miss).

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using LibreSCRS::Auth::PaceSecretKind;
using LibreSCRS::Auth::PreReadAuthMethod;

namespace {

LibreSCRS::Auth::AuthRequirement paceReq(PaceSecretKind kind)
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{}, kind, std::nullopt,
                                                           LibreSCRS::LocalizedText{});
}

class FakeReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken) override
    {
        return outcome;
    }
    ReadOutcome outcome;
};

class FakePrompter final : public PrompterClientBase
{
public:
    // Records the options of the last requestCan/Mrz call so tests can assert
    // the flow populated the client-supplied requester/artifact chrome. The
    // returned secret lets the provider lambda complete a cache-miss prompt.
    PromptOptions lastCanOptions;
    PromptOptions lastMrzOptions;

    PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{};
    }
    PromptResult requestCan(const PromptOptions& opts) override
    {
        lastCanOptions = opts;
        PromptResult r;
        r.status = PromptStatus::Ok;
        r.secret = LibreSCRS::Secure::String{"654321"};
        return r;
    }
    PromptResult requestMrz(const PromptOptions& opts) override
    {
        lastMrzOptions = opts;
        PromptResult r;
        r.status = PromptStatus::Ok;
        r.secret = LibreSCRS::Secure::String{"MRZSECRET"};
        return r;
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

// Build a holder whose factory either fails with @p failWith or returns a
// detached session, and whose resolver yields an empty candidate list. The flow
// only stores the shared_ptr and passes a CardSession& downstream; tests
// construct a detached session via the LM-provided test factory.
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

struct Harness
{
    // Set BEFORE make() to drive an open/acquire failure (mirrors the old
    // FakeOpener.failWith). The holder is built lazily in make() so this is
    // honoured.
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    std::unique_ptr<CardSessionHolder> holder;
    FakeReader reader;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;

    // Default-Ok outcome so the success scenarios don't have to set it.
    // Tests that need a non-Ok read overwrite reader.outcome after
    // construction (Harness h; h.reader.outcome = ...; h.make().run()).
    Harness()
    {
        CardReadSnapshot snap;
        snap.cardType = "fake-card";
        reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, std::move(snap), ""};
    }

    // Defaults exercised by the requester/artifact chrome assertions; tests
    // that don't care simply leave them at these values.
    std::string requester = "Mozilla Firefox";
    std::string artifact = "identity";

    IdentityReadFlow make()
    {
        holder = makeHolder(failWith);
        return IdentityReadFlow{IdentityReadFlowDeps{
            .holder = *holder,
            .reader = reader,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .requester = requester,
            .artifact = artifact,
            .token = source.token(),
        }};
    }
};

} // namespace

TEST(IdentityReadFlow, HappyCaseInstallsProviderUnconditionally)
{
    // The provider is installed unconditionally on the held session: the plugin
    // self-activates inside readCard and only then invokes the provider on a
    // channel cache miss. The flow-scope guard resets it to a stateless no-op on
    // exit — either way the held session carries an installed provider.
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    EXPECT_EQ(result.code, ErrorCode::None);
    ASSERT_TRUE(result.snapshot.has_value());
    EXPECT_EQ(result.snapshot->cardType, "fake-card");
    auto acq = h.holder->acquire();
    ASSERT_TRUE(acq.has_value());
    EXPECT_TRUE(acq->session->hasCredentialProvider()) << "the flow installs a credential provider on the held session";
}

TEST(IdentityReadFlow, OpenErrorMapsToCommunicationError)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CommunicationError);
}

TEST(IdentityReadFlow, NoCardPresentMapsToCardRemoved)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CardRemoved);
}

TEST(IdentityReadFlow, ReadAuthFailedMapsToAuthFailed)
{
    // A wrong PACE/BAC secret now surfaces from readCard (the plugin's
    // self-activation failed) as an AuthFailed read outcome.
    Harness h;
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::AuthFailed, std::nullopt, "auth rejected"};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::AuthFailed);
}

TEST(IdentityReadFlow, AuthFailedEvictsCachedSecretForThisCard)
{
    // Wrong-CAN/MRZ handling: a wrong pre-read secret surfaces from readCard as
    // an AuthFailed outcome. Before returning the error, the flow must evict the
    // cached secret for this card so a retry re-prompts instead of replaying the
    // wrong secret from cache.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"000000"}); // a stale/wrong CAN
    ASSERT_TRUE(h.cache.hasCan("card-A"));

    h.reader.outcome = ReadOutcome{ReadOutcome::Status::AuthFailed, std::nullopt, "auth rejected"};
    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::AuthFailed);
    EXPECT_FALSE(h.cache.hasCan("card-A")) << "the wrong CAN must be evicted on auth failure so a retry re-prompts";
}

TEST(IdentityReadFlow, SuccessfulReadDoesNotEvictCachedSecret)
{
    // The eviction is strictly the auth-failure path: a successful read must
    // leave the cached pre-read secret in place (it is the per-insertion CAN
    // and may be reused by a follow-up GetPhoto without re-prompting).
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});

    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "a successful read must not evict the cached CAN";
}

TEST(IdentityReadFlow, CancelledReadDoesNotEvictCachedSecret)
{
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});

    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};
    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Cancelled);
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "a user cancel must not evict the cached CAN";
}

TEST(IdentityReadFlow, ReadParseErrorMapsToParseError)
{
    Harness h;
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::ParseError, std::nullopt, "malformed"};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::ParseError);
}

TEST(IdentityReadFlow, ReadCancelledMapsToCancelled)
{
    // A user-cancelled prompt inside readCard surfaces as a Cancelled read
    // outcome (the plugin propagates the provider's cancellation).
    Harness h;
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Cancelled);
    EXPECT_EQ(result.code, ErrorCode::None);
}

TEST(IdentityReadFlow, ReadCardRemovedMapsToCommunicationError)
{
    Harness h;
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::CommunicationError, std::nullopt, "card gone"};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CommunicationError);
}

TEST(IdentityReadFlow, CancelTokenPreEmptsAfterOpen)
{
    Harness h;
    h.source.requestCancel();
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Cancelled);
    EXPECT_EQ(result.code, ErrorCode::None);
}

TEST(IdentityReadFlow, ProviderLambdaRoutesOnRequirementAndFiresAwaitingConsent)
{
    // The read provider lambda must transition the phase sink to AwaitingConsent
    // (2) BEFORE invoking the prompter, and route off the AuthRequirement it
    // receives (paceKind selects CAN vs MRZ). This exercises
    // FlowPrelude::makeReadCredentialProvider directly (production LM invokes it
    // inside readCard on a channel cache miss).
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    // Seed the cache so the lambda resolves from cache (no prompter needed)
    // and returns a CAN entry keyed off the requirement.
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    auto cred = provider(paceReq(PaceSecretKind::Can));
    EXPECT_EQ(cred.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    ASSERT_NE(cred.find("can"), nullptr);

    EXPECT_NE(std::find(h.phaseSink.phases.begin(), h.phaseSink.phases.end(),
                        static_cast<std::uint32_t>(OperationPhase::AwaitingConsent)),
              h.phaseSink.phases.end())
        << "AwaitingConsent phase must be recorded by the provider lambda";
}

TEST(IdentityReadFlow, ProviderLambdaPopulatesRequesterAndArtifactOnPrompt)
{
    // The consent prompt must name WHO is asking (requester) and
    // WHAT is being read (artifact). On a cache miss the provider lambda
    // forwards both into PromptOptions; the prompter renders them as
    // client-supplied chrome. Drive the provider on an empty cache so it hits
    // the prompter path.
    Harness h;
    h.requester = "Mozilla Firefox";
    h.artifact = "identity";
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    // Empty cache -> the lambda prompts -> FakePrompter records the options.
    auto cred = provider(paceReq(PaceSecretKind::Can));
    EXPECT_EQ(cred.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.lastCanOptions.requester, "Mozilla Firefox")
        << "the prompt must carry the requesting client's identity";
    EXPECT_EQ(h.prompter.lastCanOptions.artifact, "identity") << "the prompt must name the artifact being read";
}

TEST(IdentityReadFlow, ProviderLambdaForwardsRequesterToMrzPrompt)
{
    // Same contract on the MRZ (BAC) branch — the requester/artifact must reach
    // whichever secret kind the requirement selects.
    Harness h;
    h.requester = "/usr/bin/seahorse";
    h.artifact = "identity";
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    auto cred = provider(paceReq(PaceSecretKind::Mrz));
    EXPECT_EQ(cred.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.lastMrzOptions.requester, "/usr/bin/seahorse");
    EXPECT_EQ(h.prompter.lastMrzOptions.artifact, "identity");
}

TEST(IdentityReadFlow, AuthenticatingThenReadingFireAroundTheRead)
{
    // Authenticating then Reading both fire before the read (the read seam
    // performs activation internally). AwaitingConsent does NOT fire unless
    // the provider is invoked, which the FakeReader does not do.
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);

    const auto& phases = h.phaseSink.phases;
    const auto findAt = [&](OperationPhase p) {
        return std::find(phases.begin(), phases.end(), static_cast<std::uint32_t>(p));
    };
    EXPECT_EQ(findAt(OperationPhase::AwaitingConsent), phases.end())
        << "AwaitingConsent must NOT fire when the provider is not invoked";
    auto authenticating = findAt(OperationPhase::Authenticating);
    auto reading = findAt(OperationPhase::Reading);
    ASSERT_NE(authenticating, phases.end());
    ASSERT_NE(reading, phases.end());
    EXPECT_LT(authenticating, reading) << "Authenticating must precede Reading";
}
