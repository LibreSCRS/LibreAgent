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

#include "fakes/FakeCredentialDepositor.h"

#include <LibreSCRS/Agent/cache/MrzPayload.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/ConsentPhaseScope.h>
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>       // LmCredentialDepositor, resolveDepositTargets
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (M5' rejection signal)
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
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

// ICAO Doc 9303 TD3 canonical specimen (UTO / ERIKSSON / L898902C3) in the
// prompter's canonical three-line payload shape — a published specimen, never a
// real document's secret.
constexpr std::string_view kTd3MrzPayload{"L898902C36\n7408122\n1204159"};

class FakeReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                     LibreSCRS::CancelToken, GroupReadCallback onGroup = {}) override
    {
        ++reads;
        lastCandidateCount = candidates.size();
        // Production LM invokes the flow-installed credential provider from
        // INSIDE readCard on a channel cache miss. CardSession exposes no
        // accessor for the installed provider, so a hermetic reader fake can
        // only model that callback through a hook the test wires to the flow's
        // own provider — see IdentityReadFlow::credentialProvider().
        if (onRead) {
            onRead(reads, session);
        }
        if (onGroup && (streamOnCall == 0 || streamOnCall == reads)) {
            for (const GroupSnapshot& g : groupsToStream) {
                onGroup(g);
            }
        }
        if (!scripted.empty()) {
            const std::size_t idx = std::min(static_cast<std::size_t>(reads - 1), scripted.size() - 1);
            return scripted[idx];
        }
        return outcome;
    }
    ReadOutcome outcome;
    // Per-call outcomes for the renegotiation leg (index 0 = first read); the
    // LAST entry repeats for any further call, so a test that scripts two
    // passes still answers a (contract-violating) third one deterministically.
    // Empty (default) answers `outcome` on every call.
    std::vector<ReadOutcome> scripted;
    // Scripted groups streamed (in order) via onGroup, BEFORE this returns
    // outcome — models the plugin's own progressive delivery. Empty
    // (default) streams nothing, exactly like production's onGroup==empty.
    std::vector<GroupSnapshot> groupsToStream;
    // 0 (default) streams on every pass; N streams only on the Nth pass, so a
    // renegotiation test can assert WHICH pass the groups came from.
    int streamOnCall = 0;
    // Called at the top of every read with the 1-based pass index.
    std::function<void(int, LibreSCRS::SmartCard::CardSession&)> onRead;
    int reads = 0;
    std::size_t lastCandidateCount = 0;

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
        if (throwOnCan) {
            // A prompter transport that fails mid-dialog. The read provider's
            // catch-all turns this into an error result, so nothing downstream
            // ever sees the exception -- which is exactly why the phase must be
            // handed back by a scope rather than by a call before the return.
            throw std::runtime_error("prompter transport failed mid-dialog");
        }
        if (canOverride.has_value()) {
            return *canOverride;
        }
        PromptResult r;
        r.status = PromptStatus::Ok;
        r.secret = LibreSCRS::Secure::String{"654321"};
        return r;
    }
    // Scripted reply for the CAN prompt, overriding the plain Ok above.
    std::optional<PromptResult> canOverride;
    // Make the CAN prompt throw instead of replying (see requestCan).
    bool throwOnCan = false;
    // The prompter honoured the in-dialog switch: an Ok carrying an MRZ
    // payload plus the kind actually collected.
    void answerCanWithMrz(std::string_view payload)
    {
        canOverride = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{payload}, "",
                                   LibreSCRS::Auth::PaceSecretKind::Mrz};
    }
    void cancelCan()
    {
        canOverride = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
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

// Non-secret observations shared out of the const plugin entry points
// (candidates are shared_ptr<const CardPlugin>, so a candidate cannot record
// into itself).
struct ProbeRecorder
{
    int canHandleConnectionCalls{0};
};

// Candidate double advertising an arbitrary manifest capability set and
// recording the AID-probe entry point. The deposit seam must NEVER reach that
// entry point: on the eMRTD plugin it wipes the per-session credential store
// and emits plain APDUs that desync an open secure-messaging tunnel.
class RecordingCandidate final : public LibreSCRS::Plugin::CardPlugin
{
public:
    RecordingCandidate(std::string id, LibreSCRS::Plugin::CardCapabilities caps,
                       std::shared_ptr<ProbeRecorder> rec = nullptr)
        : m_caps(caps), m_rec(std::move(rec))
    {
        setIdentity(std::move(id), "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return m_caps;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    bool canHandleConnection(std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) const override
    {
        if (m_rec) {
            ++m_rec->canHandleConnectionCalls;
        }
        return true;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    LibreSCRS::Plugin::CardCapabilities m_caps;
    std::shared_ptr<ProbeRecorder> m_rec;
};

// A travel-document candidate: the only family with a CAN/MRZ duality, so the
// only one the flow may offer the alternative kind for.
inline CandidateList emrtdCandidates(std::shared_ptr<ProbeRecorder> rec = nullptr)
{
    using LibreSCRS::Plugin::CardCapabilities;
    return {std::make_shared<RecordingCandidate>(
        "emrtd-stub",
        static_cast<CardCapabilities>(static_cast<std::uint32_t>(CardCapabilities::IdentityData) |
                                      static_cast<std::uint32_t>(CardCapabilities::EmrtdCrypto)),
        std::move(rec))};
}

// An identity candidate with no eMRTD crypto: no CAN/MRZ duality, so no offer.
inline CandidateList plainIdentityCandidates()
{
    return {std::make_shared<RecordingCandidate>("plain-stub", LibreSCRS::Plugin::CardCapabilities::IdentityData)};
}

// Build a holder whose factory either fails with @p failWith or returns a
// detached session, and whose resolver yields @p candidates. The flow
// only stores the shared_ptr and passes a CardSession& downstream; tests
// construct a detached session via the LM-provided test factory.
inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith,
                                                     CandidateList candidates = {})
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [candidates = std::move(candidates)](std::span<const std::uint8_t>,
                                                         LibreSCRS::SmartCard::CardSession&) { return candidates; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

struct Harness
{
    // Set BEFORE make() to drive an open/acquire failure (mirrors the old
    // FakeOpener.failWith). The holder is built lazily in make() so this is
    // honoured.
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    // Candidate list the holder's resolver answers with (empty by default, so
    // every pre-existing scenario keeps its no-candidate holder).
    CandidateList candidates;
    std::unique_ptr<CardSessionHolder> holder;
    FakeReader reader;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    RecordingGroupSink groupSink;
    FakeCredentialDepositor depositor;
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
        holder = makeHolder(failWith, candidates);
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
            .depositor = depositor,
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

TEST(ConsentPhaseScope, ReturnsTheOperationToAMachinePhaseSoTheCardIsWatchedAgain)
{
    // The class contract in isolation: consent is a bounded excursion, and the
    // scope is what closes it. Entering disarms the per-op watchdog; leaving
    // must re-enter an arming phase, or the card I/O after the prompt is
    // unbounded.
    RecordingPhaseSink sink;
    {
        ConsentPhaseScope consent{sink};
        EXPECT_EQ(sink.phases.back(), static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
    }
    EXPECT_EQ(sink.phases.back(), static_cast<std::uint32_t>(OperationPhase::Authenticating))
        << "the card I/O after the prompt would run with no watchdog";
}

TEST(IdentityReadFlow, ProviderLambdaClosesTheConsentExcursionSoThePostPromptReadIsWatched)
{
    // The call site, not the class: the read provider is where the prompt is
    // actually raised, from INSIDE the plugin's readCard -- so everything the
    // card does after the holder types (the activation the secret unlocks, then
    // the data-group reads) happens while this lambda's phase is still current.
    // Leaving that phase at AwaitingConsent leaves the watchdog disarmed for all
    // of it, which is an unbounded SCardTransmit away from a frozen worker. The
    // flow's own Authenticating/Reading pair does not rescue this: it fires
    // BEFORE the read, and the only pair after it belongs to the MRZ-deposit
    // branch, which the ordinary CAN path never enters.
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    // Empty cache -> the lambda takes the real prompter path.
    auto cred = provider(paceReq(PaceSecretKind::Can));
    EXPECT_EQ(cred.status, LibreSCRS::Auth::CredentialResult::Status::Ok);

    const auto& phases = h.phaseSink.phases;
    ASSERT_FALSE(phases.empty());
    EXPECT_NE(std::find(phases.begin(), phases.end(), static_cast<std::uint32_t>(OperationPhase::AwaitingConsent)),
              phases.end())
        << "the prompt must still surface as AwaitingConsent";
    EXPECT_EQ(phases.back(), static_cast<std::uint32_t>(OperationPhase::Authenticating))
        << "the provider returned with the operation still parked in AwaitingConsent: the watchdog is disarmed "
           "and the card I/O that follows the prompt has no bound at all";
}

TEST(IdentityReadFlow, ProviderLambdaClosesTheConsentExcursionEvenWhenThePromptThrows)
{
    // Why the excursion is a SCOPE and not a call before the return. The prompt
    // body is wrapped in a catch-all that maps any throw to an error result, so
    // a hand-back placed on the normal path is simply skipped when the prompter
    // transport fails mid-dialog -- and LM, which sees only an error result,
    // walks on to its next candidate and issues more card I/O with the watchdog
    // still disarmed. The scope's destructor runs on the unwind, so the phase
    // comes back on this path too.
    Harness h;
    h.prompter.throwOnCan = true;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed);

    auto cred = provider(paceReq(PaceSecretKind::Can));
    EXPECT_NE(cred.status, LibreSCRS::Auth::CredentialResult::Status::Ok)
        << "a prompter that threw cannot have produced a usable secret";

    const auto& phases = h.phaseSink.phases;
    ASSERT_FALSE(phases.empty());
    EXPECT_EQ(phases.back(), static_cast<std::uint32_t>(OperationPhase::Authenticating))
        << "the throwing path left the operation parked in AwaitingConsent with the watchdog disarmed";
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

// --- A3: renegotiate a CAN prompt into an MRZ read -------------------------
//
// The prompter honoured the in-dialog switch, so the CAN prompt came back with
// an MRZ payload. The credential cache parks it in the flow's choice sink and
// unwinds the walk as a cancellation; the flow then deposits the parsed trio
// into the candidate plugins and re-runs the read ONCE.

TEST(IdentityReadFlow, RenegotiationDepositsAndRerunsOnce)
{
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.answerCanWithMrz(kTd3MrzPayload);

    CardReadSnapshot snap;
    snap.cardType = "fake-passport";
    h.reader.scripted = {
        ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"},
        ReadOutcome{ReadOutcome::Status::Ok, std::move(snap), ""},
    };
    GroupSnapshot personal;
    personal.groupKey = "personal";
    h.reader.groupsToStream = {personal};
    h.reader.streamOnCall = 2; // groups belong to the SECOND (post-deposit) pass

    auto flow = h.make();
    h.reader.onRead = [&flow](int pass, LibreSCRS::SmartCard::CardSession&) {
        if (pass == 1) {
            // Models LM's on-cache-miss provider callback inside readCard.
            static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
        }
    };
    const auto result = flow.run();

    EXPECT_EQ(h.reader.reads, 2) << "exactly one re-run after the deposit";
    ASSERT_EQ(h.depositor.deposits.size(), 1u);
    EXPECT_EQ(h.depositor.deposits[0].documentNumber, "L898902C3") << "check digit stripped for the plugin keys";
    EXPECT_EQ(h.depositor.deposits[0].dateOfBirth, "740812");
    EXPECT_EQ(h.depositor.deposits[0].dateOfExpiry, "120415");
    EXPECT_EQ(h.depositor.deposits[0].candidateCount, 1u) << "the identity candidates are offered the deposit";
    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    ASSERT_TRUE(result.snapshot.has_value());
    EXPECT_EQ(result.snapshot->cardType, "fake-passport");
    ASSERT_EQ(h.groupSink.groups.size(), 1u) << "the groups streamed are the re-run's";
    EXPECT_EQ(h.groupSink.groups[0].groupKey, "personal");
    EXPECT_TRUE(h.cache.hasMrz("card-A")) << "the chosen MRZ is cached for the rest of this insertion";
}

TEST(IdentityReadFlow, RenegotiationRunsReadExactlyTwice)
{
    // Hostile loop: the second pass ALSO ends cancelled with the sink refilled
    // (the cached MRZ short-circuit re-arms it). The one-shot rule must hold —
    // no third card walk, and a non-Ok final result.
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.answerCanWithMrz(kTd3MrzPayload);
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};

    auto flow = h.make();
    h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(h.reader.reads, 2) << "the re-run happens at most once, ever";
    EXPECT_NE(result.outcome, IdentityReadFlow::Outcome::Ok);
    EXPECT_EQ(h.depositor.deposits.size(), 1u) << "one renegotiation, one deposit";
}

TEST(IdentityReadFlow, MalformedChosenPayloadFailsWithoutCachePoison)
{
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.answerCanWithMrz("garbage");
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};

    auto flow = h.make();
    h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_FALSE(h.cache.hasMrz("card-A")) << "a payload that does not parse must never be cached";
    EXPECT_TRUE(h.depositor.deposits.empty()) << "nothing may be deposited from an unparsed payload";
    EXPECT_EQ(h.reader.reads, 1) << "no re-run without a usable secret";
}

TEST(IdentityReadFlow, CachedMrzShortCircuitsWithoutPrompting)
{
    // A repeat read WITHIN the same insertion renegotiates silently: the
    // provider fills the sink straight from the cache and never prompts. (A
    // re-insert mints a new cardKey and prompts once -- widening the key is
    // forbidden, it would serve one document's MRZ to another.)
    Harness h;
    auto sink = std::make_shared<LibreSCRS::Agent::MrzChoiceSink>();
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    h.cache.putMrz("card-A", LibreSCRS::Secure::String{kTd3MrzPayload});

    auto provider = FlowPrelude::makeReadCredentialProvider(
        h.cache, h.prompter, h.serializer, h.phaseSink, "card-A", h.requester, h.artifact, h.source.token(),
        prompterFailed, /*userCancelled=*/{}, /*providerMarkedWrong=*/{}, /*offerMrzAlternative=*/true, sink);

    const auto cred = provider(paceReq(PaceSecretKind::Can));

    EXPECT_EQ(cred.status, LibreSCRS::Auth::CredentialResult::Status::UserCancelled);
    EXPECT_EQ(h.prompter.canPrompts, 0) << "a cached MRZ renegotiates with zero dialogs";
    ASSERT_TRUE(sink->taken());
    const auto payload = sink->take();
    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(payload->view(), kTd3MrzPayload);
}

TEST(IdentityReadFlow, ALaterEmptyReasonInvocationLeavesTheMarkedFlagAlone)
{
    // Multi-candidate walk, both prompts dismissed. Invocation 1 carries the
    // rejection signal: it marks the cached CAN wrong (evicting it) and its
    // re-prompt is cancelled, so the flag tells the flow's AuthFailed arm the
    // marking is already done. Invocation 2 is a later candidate's
    // empty-reason retry, also cancelled: it marked nothing and owns nothing,
    // so it must leave the flag ALONE — clearing it here is how one wrong CAN
    // used to count as two failed attempts.
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto marked = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(h.cache, h.prompter, h.serializer, h.phaseSink, "card-A",
                                                            h.requester, h.artifact, h.source.token(), prompterFailed,
                                                            /*userCancelled=*/{}, marked);
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"000000"});
    h.prompter.cancelCan();

    const auto first = provider(rejectedPaceReq(PaceSecretKind::Can));
    ASSERT_NE(first.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_FALSE(h.cache.hasCan("card-A")) << "the rejection signal must evict";
    EXPECT_TRUE(marked->load()) << "the marking invocation must set the flag";

    const auto second = provider(paceReq(PaceSecretKind::Can));
    ASSERT_NE(second.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    EXPECT_TRUE(marked->load()) << "an empty-reason invocation that marked nothing cleared the flag — "
                                   "the flow will mark the same wrong CAN a second time";
}

TEST(IdentityReadFlow, GenuineUserCancelStillCancels)
{
    // No chosen kind, no sink content: a dismissed dialog is still a cancel.
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.cancelCan();
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};

    auto flow = h.make();
    h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Cancelled);
    EXPECT_EQ(result.code, ErrorCode::None);
    EXPECT_EQ(h.reader.reads, 1) << "no re-run on a genuine cancel";
    EXPECT_TRUE(h.depositor.deposits.empty());
}

TEST(IdentityReadFlow, RenegotiationAbortsOnCancelledToken)
{
    // The abandoned-worker guard wins over the renegotiation: a flow whose
    // token tripped must not put a SECOND card read past it.
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.answerCanWithMrz(kTd3MrzPayload);
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};

    auto flow = h.make();
    h.reader.onRead = [&flow, &h](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
        h.source.requestCancel();
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Cancelled);
    EXPECT_EQ(h.reader.reads, 1) << "the cancelled token stops the second read";
    EXPECT_TRUE(h.depositor.deposits.empty()) << "nothing is deposited past the guard";
    EXPECT_FALSE(h.cache.hasMrz("card-A")) << "no cache write past the guard";
}

TEST(IdentityReadFlow, UnconsumedSinkIsScrubbedAtFlowExit)
{
    // Same shape as the guarded abort above: the sink is filled and never
    // consumed. run()'s teardown must scrub it so no payload outlives the run.
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.answerCanWithMrz(kTd3MrzPayload);
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};

    auto flow = h.make();
    h.reader.onRead = [&flow, &h](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
        EXPECT_TRUE(flow.choiceSink()->taken()) << "the payload is parked while the run is live";
        h.source.requestCancel();
    };
    static_cast<void>(flow.run());

    EXPECT_FALSE(flow.choiceSink()->taken()) << "an unconsumed sink is disarmed at run() exit";
    EXPECT_FALSE(flow.choiceSink()->take().has_value()) << "and holds no payload";
}

TEST(IdentityReadFlow, OfferFlagComputedFromCandidates)
{
    // The offer is derived FROM THE CANDIDATE LIST in production code -- never
    // injected by the caller. Without this the whole choice feature can be
    // dead-wired with every other gate green.
    {
        Harness h;
        h.candidates = emrtdCandidates();
        auto flow = h.make();
        h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
            static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
        };
        static_cast<void>(flow.run());
        EXPECT_EQ(h.prompter.canPrompts, 1);
        EXPECT_EQ(h.prompter.lastCanOptions.altKinds, (std::vector<std::string>{"mrz"}))
            << "a travel-document candidate makes the CAN prompt offer the MRZ alternative";
    }
    {
        Harness h;
        h.candidates = plainIdentityCandidates();
        auto flow = h.make();
        h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
            static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
        };
        static_cast<void>(flow.run());
        EXPECT_EQ(h.prompter.canPrompts, 1);
        EXPECT_TRUE(h.prompter.lastCanOptions.altKinds.empty())
            << "a card with no CAN/MRZ duality must never advertise the alternative";
    }
}

TEST(IdentityReadFlow, AlternativeIsNotAdvertisedWithoutASinkToReceiveTheChoice)
{
    // The offer and the sink are ONE contract: requestCredential is handed the
    // sink only on the prompt that advertised the alternative, so advertising
    // with no sink invites a chosen-kind reply that has nowhere to land -- the
    // user switches to MRZ and the payload is dropped on the floor. Fail
    // closed: no sink, no offer.
    Harness h;
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);
    auto provider = FlowPrelude::makeReadCredentialProvider(
        h.cache, h.prompter, h.serializer, h.phaseSink, "card-A", h.requester, h.artifact, h.source.token(),
        prompterFailed, /*userCancelled=*/{}, /*providerMarkedWrong=*/{}, /*offerMrzAlternative=*/true,
        /*mrzChoice=*/{});

    static_cast<void>(provider(paceReq(PaceSecretKind::Can)));

    EXPECT_EQ(h.prompter.canPrompts, 1);
    EXPECT_TRUE(h.prompter.lastCanOptions.altKinds.empty())
        << "an alternative with nowhere to land must never be advertised";
}

TEST(IdentityReadFlow, RefusedDepositSurfacesTheMissingCapability)
{
    // No candidate could take the chosen MRZ, so the re-run cannot possibly
    // authenticate with it: the second walk re-asks for a CAN, the cached
    // payload renegotiates silently, and the read unwinds as that
    // renegotiation's own cancellation -- a SILENT cancel that spends a card
    // read and tells the user nothing. Say what actually happened: nothing on
    // this card can consume an MRZ.
    Harness h;
    h.candidates = emrtdCandidates();
    h.prompter.answerCanWithMrz(kTd3MrzPayload);
    h.depositor.accepted = false;
    h.reader.outcome = ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};

    auto flow = h.make();
    h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
    };
    const auto result = flow.run();

    EXPECT_EQ(result.outcome, IdentityReadFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CapabilityMissing);
    EXPECT_EQ(h.depositor.deposits.size(), 1u) << "the deposit was attempted once";
    EXPECT_EQ(h.reader.reads, 1) << "a refused deposit spends no second card read";
}

TEST(IdentityReadFlow, CredentialProviderIsClearedAtFlowExit)
{
    // The provider captures cache/prompter/serializer/phaseSink BY REFERENCE,
    // and every one of those is bounded by run(). A member left callable past
    // run() is a loaded gun pointed at dead references -- and it holds the
    // run's cardKey/requester/artifact captures alive with it.
    Harness h;
    auto flow = h.make();
    h.reader.onRead = [&flow](int, LibreSCRS::SmartCard::CardSession&) {
        EXPECT_TRUE(static_cast<bool>(flow.credentialProvider())) << "callable while the run is live";
        static_cast<void>(flow.credentialProvider()(paceReq(PaceSecretKind::Can)));
    };
    static_cast<void>(flow.run());

    EXPECT_FALSE(static_cast<bool>(flow.credentialProvider())) << "and empty once run() has returned";
}

TEST(IdentityReadFlow, DepositorUsesPureCandidateLookup)
{
    // Inside an open flow the deposit seam must resolve its non-const plugin
    // handles through the PURE, no-card-I/O registry lookup only. The
    // session-probing lookup wipes the eMRTD plugin's per-session credential
    // store (destroying the very deposit being made) and emits plain APDUs
    // that desync an open secure-messaging tunnel.
    //
    // The registry (LibreSCRS::Plugin::CardPluginService) is a concrete class
    // that loads shared objects off disk, so it admits no test double; the
    // contract is pinned from BOTH sides instead -- behaviourally (the seam
    // never probes the candidates it was handed) and structurally (the
    // resolution helper takes NO session, so the probing lookup is unreachable
    // from it, and the shipped source names neither probing entry point).
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    ASSERT_NE(session, nullptr);

    auto recorder = std::make_shared<ProbeRecorder>();
    const CandidateList candidates = emrtdCandidates(recorder);

    const auto dir = std::filesystem::temp_directory_path() / "librescrs-agent-empty-plugin-dir";
    std::filesystem::create_directories(dir);
    LibreSCRS::Plugin::CardPluginService registry{dir};

    MrzParts parts;
    parts.mrzInfo = LibreSCRS::Secure::String{"L898902C3674081221204159"};
    parts.documentNumber = LibreSCRS::Secure::String{"L898902C3"};
    parts.dateOfBirth = LibreSCRS::Secure::String{"740812"};
    parts.dateOfExpiry = LibreSCRS::Secure::String{"120415"};

    LmCredentialDepositor depositor{registry};
    CredentialDepositor& iface = depositor;
    EXPECT_FALSE(iface.depositMrz(*session, candidates, parts))
        << "an empty registry resolves no handle, so nothing is deposited";
    EXPECT_EQ(recorder->canHandleConnectionCalls, 0)
        << "the deposit seam must never AID-probe the candidates it was handed";
    EXPECT_TRUE(resolveDepositTargets(registry, candidates).empty());

    // Compile-level restriction: the resolution helper's signature carries no
    // CardSession at all, so the session-probing registry lookup cannot be
    // reached from it.
    static_assert(!std::is_invocable_v<decltype(&resolveDepositTargets), LibreSCRS::Plugin::CardPluginService&,
                                       const CandidateList&, LibreSCRS::SmartCard::CardSession&>,
                  "resolveDepositTargets must not accept a CardSession");

    // Structural pin over the shipped seam source (line comments stripped, so
    // the guard is about CODE, not prose).
    std::string source;
    {
        std::ifstream in{LIBREAGENT_LMSEAMS_CPP};
        ASSERT_TRUE(in.good()) << "seam source not wired: " << LIBREAGENT_LMSEAMS_CPP;
        std::stringstream buffer;
        buffer << in.rdbuf();
        source = buffer.str();
    }
    std::string code;
    code.reserve(source.size());
    for (std::size_t i = 0; i < source.size(); ++i) {
        if (source[i] == '/' && i + 1 < source.size() && source[i + 1] == '/') {
            while (i < source.size() && source[i] != '\n') {
                ++i;
            }
        }
        if (i < source.size()) {
            code.push_back(source[i]);
        }
    }
    EXPECT_NE(code.find("plugins()"), std::string::npos) << "the deposit seam resolves through the pure lookup";
    EXPECT_EQ(code.find("canHandleConnection"), std::string::npos)
        << "the deposit seam must never call the AID-probe entry point";
    EXPECT_EQ(code.find("findAllCandidates"), std::string::npos)
        << "the deposit seam must never call the session-probing candidate lookup";
}
