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
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (M5' rejection signal)
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

// A PACE requirement carrying the rejected-retry reason LM sets ONLY on a
// re-prompt after a wrong-secret rejection in the same activation (M5'). The
// A2 provider evicts and re-prompts on THIS shape, never on a bare same-kind
// re-invocation.
LibreSCRS::Auth::AuthRequirement rejectedPaceReq(PaceSecretKind kind)
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{}, kind, std::nullopt,
                                                           LibreSCRS::Auth::ErrorKeys::preReadAuthFailed());
}

class FakeReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback onGroup = {}) override
    {
        if (onGroup) {
            for (const GroupSnapshot& g : groupsToStream) {
                onGroup(g);
            }
        }
        return outcome;
    }
    ReadOutcome outcome;
    // Scripted groups streamed (in order) via onGroup, BEFORE this returns
    // outcome — models the plugin's own progressive delivery. Empty
    // (default) streams nothing, exactly like production's onGroup==empty.
    std::vector<GroupSnapshot> groupsToStream;

    // Not exercised by this flow's suite (TokenInfoReadFlowTest.cpp owns the
    // dedicated fake); a well-formed default keeps this class non-abstract.
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class RecordingGroupSink final : public GroupSink
{
public:
    void groupReady(const GroupSnapshot& group) noexcept override
    {
        groups.push_back(group);
    }
    std::vector<GroupSnapshot> groups;
};

class FakePrompter final : public PrompterClientBase
{
public:
    // Records the options of the last requestCan/Mrz call so tests can assert
    // the flow populated the client-supplied requester/artifact chrome. The
    // returned secret lets the provider lambda complete a cache-miss prompt.
    PromptOptions lastCanOptions;
    PromptOptions lastMrzOptions;
    // Count actual prompts so a test can distinguish a real re-prompt from a
    // silent cache replay (the A2 eviction contract).
    int canPrompts = 0;
    int mrzPrompts = 0;

    PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{};
    }
    PromptResult requestCan(const PromptOptions& opts) override
    {
        ++canPrompts;
        lastCanOptions = opts;
        PromptResult r;
        r.status = PromptStatus::Ok;
        r.secret = LibreSCRS::Secure::String{"654321"};
        return r;
    }
    PromptResult requestMrz(const PromptOptions& opts) override
    {
        ++mrzPrompts;
        lastMrzOptions = opts;
        PromptResult r;
        r.status = PromptStatus::Ok;
        // A conforming 3-line MRZ payload (TD3 specimen): the credential adapter
        // now VERIFIES the payload (grammar + ICAO 7-3-1 check digits), so a
        // placeholder string would be rejected as malformed.
        r.secret = LibreSCRS::Secure::String{"L898902C36\n7408122\n1204159"};
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
    RecordingGroupSink groupSink;
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
            .groupSink = groupSink,
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

TEST(IdentityReadFlow, StreamsGroupsToSinkInOrderBeforeReturning)
{
    // The reader streams 3 groups via onGroup before its read() call returns;
    // the flow must forward every one, in order, to the group sink -- and do
    // so BEFORE run() itself returns (so a caller emitting groupSink calls as
    // wire pushes can never emit a group after its own Result).
    Harness h;
    GroupSnapshot g1;
    g1.groupKey = "personal";
    GroupSnapshot g2;
    g2.groupKey = "address";
    GroupSnapshot g3;
    g3.groupKey = "document";
    h.reader.groupsToStream = {g1, g2, g3};

    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    ASSERT_EQ(h.groupSink.groups.size(), 3u);
    EXPECT_EQ(h.groupSink.groups[0].groupKey, "personal");
    EXPECT_EQ(h.groupSink.groups[1].groupKey, "address");
    EXPECT_EQ(h.groupSink.groups[2].groupKey, "document");
}

TEST(IdentityReadFlow, NoGroupsStreamedWhenReaderStreamsNone)
{
    // Default Harness reader streams nothing (groupsToStream is empty) --
    // the sink must see zero calls, mirroring an agent build with no
    // streaming surface at all.
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    EXPECT_TRUE(h.groupSink.groups.empty());
}

TEST(IdentityReadFlow, StreamedGroupsAreIgnoredOnAFailedRead)
{
    // A candidate may stream a group and then still fail the overall read;
    // the flow forwards whatever streamed (a documented hint-only caveat --
    // see LmCardReader::read's own comment) but the ERROR outcome itself is
    // unaffected by streaming having happened at all.
    Harness h;
    GroupSnapshot g1;
    g1.groupKey = "personal";
    h.reader.groupsToStream = {g1};
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::ParseError, std::nullopt, "malformed"};

    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::ParseError);
    ASSERT_EQ(h.groupSink.groups.size(), 1u);
    EXPECT_EQ(h.groupSink.groups[0].groupKey, "personal");
}

// --- A2: never replay a rejected pre-read secret (sec I3 re-key) ------------

TEST(IdentityReadFlow, RejectedRetryPromptEvictsAndRepromptsWithContext)
{
    // When the incoming AuthRequirement carries the rejected-retry reason LM
    // sets ONLY on a re-prompt after a wrong-secret rejection in the same
    // activation (M5'), the provider must EVICT the just-rejected cached value
    // and re-prompt WITH retry context -- never silently replay the rejected
    // secret from cache (CredentialCache.h cache-hit branch bypassed BY
    // EVICTION).
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    // First prompt (empty reason) collects and caches a CAN.
    auto first = provider(paceReq(PaceSecretKind::Can));
    ASSERT_EQ(first.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.canPrompts, 1);
    ASSERT_TRUE(h.cache.hasCan("card-A"));

    // Second invocation carries the M5' rejection signal: evict the cached CAN
    // and PROMPT AGAIN (not replay); the re-prompt must carry attempt==2 and
    // lastError==preReadAuthFailed().key.
    auto second = provider(rejectedPaceReq(PaceSecretKind::Can));
    ASSERT_EQ(second.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.canPrompts, 2) << "the rejected value must be re-prompted, not replayed from cache";
    EXPECT_EQ(h.prompter.lastCanOptions.attempt, 2u) << "the re-prompt numbers this the second attempt";
    EXPECT_EQ(h.prompter.lastCanOptions.lastError, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key)
        << "the re-prompt carries the rejecting failure's msgKey";
}

TEST(IdentityReadFlow, PaceUnsupportedFallbackDoesNotMarkCredentialWrong)
{
    // sec I3 pin: a same-kind re-invocation WITHOUT the rejection signal (the
    // PACE->BAC fallback / multi-candidate walk -- same kind, EMPTY reason) is
    // NOT a rejection. The provider must serve the NEVER-REJECTED value from
    // cache with no prompt and no eviction (replaying a rejected secret is what
    // A2 prevents; replaying a correct one is required -- rev1's bare
    // second-invocation rule would have evicted a correct MRZ). Passes
    // vacuously today; reddens only if A2 regresses to invocation-counting.
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    auto first = provider(paceReq(PaceSecretKind::Mrz));
    ASSERT_EQ(first.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.mrzPrompts, 1);
    ASSERT_TRUE(h.cache.hasMrz("card-A"));

    auto second = provider(paceReq(PaceSecretKind::Mrz)); // same kind, EMPTY reason -- no rejection
    EXPECT_EQ(second.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.mrzPrompts, 1) << "a same-kind re-invocation with no rejection serves the cache, no re-prompt";
    EXPECT_TRUE(h.cache.hasMrz("card-A"))
        << "no eviction: the never-rejected MRZ stays cached (no markCredentialWrong)";
}

TEST(IdentityReadFlow, FirstInvocationStillUsesWarmCache)
{
    // A2 keys on the REJECTION SIGNAL, not on cache age or invocation count: a
    // cache warmed BEFORE the run (fresh provider) serves the hit with zero
    // prompts.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    auto cred = provider(paceReq(PaceSecretKind::Can));
    EXPECT_EQ(cred.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.canPrompts, 0) << "a warm cache serves with zero prompts";
    EXPECT_TRUE(h.cache.hasCan("card-A"));
}

TEST(IdentityReadFlow, RejectedSecretIsMarkedWrongExactlyOnce)
{
    // Double-mark guard (sec I3): each rejected value is marked EXACTLY once, so
    // the retry-context attempt number stays truthful. Two successive rejection
    // signals must bump the attempt by exactly ONE each (2, then 3) -- never
    // double-count a single rejected value.
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    ASSERT_EQ(provider(paceReq(PaceSecretKind::Can)).status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_EQ(h.prompter.canPrompts, 1);

    provider(rejectedPaceReq(PaceSecretKind::Can)); // marks the first rejected value exactly once
    EXPECT_EQ(h.prompter.canPrompts, 2);
    EXPECT_EQ(h.prompter.lastCanOptions.attempt, 2u) << "one rejection -> second attempt";

    provider(rejectedPaceReq(PaceSecretKind::Can)); // marks the second (distinct) rejected value exactly once
    EXPECT_EQ(h.prompter.canPrompts, 3);
    EXPECT_EQ(h.prompter.lastCanOptions.attempt, 3u)
        << "two distinct rejections -> third attempt, not inflated (each value marked exactly once)";
}

// --- M4: structural failures stop punishing the credential -----------------

TEST(IdentityReadFlow, StructuralPaceFailureDoesNotMarkCredentialWrong)
{
    // A STRUCTURAL pre-read failure (the document does not support PACE)
    // surfaces as UnsupportedCard, NOT AuthFailed -- so the flow's
    // AuthFailed-only markCredentialWrong branch skips credential punishment for
    // free. The pre-seeded CAN stays cached (a structural failure is not the
    // CAN's fault); since markCredentialWrong is the only thing that evicts AND
    // records retry context, an intact cache proves no retry context was
    // recorded either.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    h.reader.outcome =
        ReadOutcome{ReadOutcome::Status::UnsupportedCard, std::nullopt, "document does not support PACE"};

    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::UnsupportedCard);
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "a structural failure must never evict/punish the credential";
}

TEST(IdentityReadFlow, WrongSecretStillMarksCredentialWrong)
{
    // Regression pin: a genuine wrong pre-read secret (AuthFailed) still evicts
    // the cached CAN AND records retry context -- A2/M4 must not weaken the real
    // wrong-credential path.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"000000"});
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::AuthFailed, std::nullopt, "auth rejected"};

    auto result = h.make().run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::AuthFailed);
    EXPECT_FALSE(h.cache.hasCan("card-A")) << "a wrong secret is evicted so a retry re-prompts";

    // The retry context was recorded: the next prompt for this card is numbered 2.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);
    provider(paceReq(PaceSecretKind::Can));
    EXPECT_EQ(h.prompter.canPrompts, 1);
    EXPECT_EQ(h.prompter.lastCanOptions.attempt, 2u) << "markCredentialWrong recorded retry context";
}
