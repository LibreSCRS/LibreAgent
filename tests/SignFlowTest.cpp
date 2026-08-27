// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of SignFlow's CHANNEL-ESTABLISHMENT half -- the CAN/MRZ
// branch of its hand-rolled credential provider. That branch is the one that
// routes through CredentialCache, so it owns the card's rejection detection,
// this operation's PACE attempt allowance, and the eviction a real rejection
// must trigger. Every seam is a Fake; the flow runs synchronously on the test
// thread, and the fake signer drives the INSTALLED provider on the real path
// (production LM invokes it inside the signing walk on a channel cache miss),
// so nothing here asserts against a provider the test built.
//
// Deliberately mirrors BatchSignFlowTest's harness: the two flows carry the
// same provider preamble, and a matching pair of tests is what catches them
// drifting apart. The signing-PIN branch and the terminal status mapping are
// covered against the LM seam elsewhere (LmSeamsRoutingTest) and by the batch
// flow's own suite.
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptPolicy.h>  // kMaxPaceAttempts
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SignFlow.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (the card's rejection signal)
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

class StubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    StubPlugin(std::string id, LibreSCRS::Plugin::CardCapabilities caps) : m_caps(caps)
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

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    LibreSCRS::Plugin::CardCapabilities m_caps;
};

std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> mkSigning(std::string id)
{
    return std::make_shared<StubPlugin>(std::move(id), LibreSCRS::Plugin::CardCapabilities::PKI |
                                                           LibreSCRS::Plugin::CardCapabilities::PinManagement);
}

std::unique_ptr<CardSessionHolder> makeHolder(CandidateList candidates)
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [candidates = std::move(candidates)](std::span<const std::uint8_t>,
                                                         LibreSCRS::SmartCard::CardSession&) { return candidates; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

class FakePrompter final : public PrompterClientBase
{
public:
    int pinCalls = 0;
    PromptResult pinResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"}, ""};

    PromptResult requestPin(const PromptOptions&) override
    {
        ++pinCalls;
        return pinResult;
    }
    // Counts REAL CAN dialogs, telling them apart from a silent cache replay
    // and from a request the cap refused before it ever got here. That
    // distinction is the whole measurement: a wired-but-inert cap and a working
    // one produce the same final status and differ only in this number.
    int canCalls = 0;
    PromptResult canResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    PromptOptions lastCanOptions;

    PromptResult requestCan(const PromptOptions& options) override
    {
        ++canCalls;
        lastCanOptions = options;
        return canResult;
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

LibreSCRS::Auth::AuthRequirement canReq(bool rejected)
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(
        LibreSCRS::SmartCard::AppletAid{}, LibreSCRS::Auth::PaceSecretKind::Can, std::nullopt,
        rejected ? LibreSCRS::Auth::ErrorKeys::preReadAuthFailed() : LibreSCRS::LocalizedText{});
}

// Models the terminal signing op. Before asking for the PIN it drives one CAN
// requirement per entry in `canScript`, each entry saying whether that
// requirement carries the card's rejection signal (true) or no reason at all
// (false) -- the two shapes LM actually produces inside ONE activation.
class FakeSigner final : public Signer
{
public:
    int calls = 0;
    std::string cardPin = "1234";
    std::vector<bool> canScript;
    std::vector<LibreSCRS::Auth::CredentialResult> canResults;

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList&, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken) override
    {
        ++calls;
        for (const bool rejected : canScript) {
            canResults.push_back(credentials(canReq(rejected)));
        }

        const auto req =
            LibreSCRS::Auth::AuthRequirement::forSigning(LibreSCRS::LocalizedText{"", "PIN", {}}, std::nullopt);
        const auto result = credentials(req);
        if (result.status == LibreSCRS::Auth::CredentialResult::Status::UserCancelled) {
            SignOutcome out;
            out.status = SignOutcome::Status::Cancelled;
            return out;
        }
        if (result.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
            SignOutcome out;
            out.status = SignOutcome::Status::CommunicationError;
            return out;
        }
        const auto* pin = result.find(LibreSCRS::PrompterWire::kKindPin);
        if (pin == nullptr || std::string{pin->view()} != cardPin) {
            SignOutcome out;
            out.status = SignOutcome::Status::AuthFailed;
            return out;
        }
        SignOutcome out;
        out.status = SignOutcome::Status::Ok;
        out.signedDocumentBytes = params.inputDocument;
        out.signedDocumentBytes.push_back(0xAA); // trivial "signature" marker
        out.resolvedFormat = params.format;
        out.resolvedLevel = params.level;
        out.chainComplete = true;
        return out;
    }
};

struct Harness
{
    std::unique_ptr<CardSessionHolder> holder;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    FakeSigner signer;

    static SignParams baseParams()
    {
        SignParams p;
        p.certId = "abc123";
        p.inputDocument = {0x01};
        p.format = "pades";
        p.level = "b-b";
        p.packaging = "enveloped";
        return p;
    }

    SignFlow make()
    {
        holder = makeHolder(CandidateList{mkSigning("stub-plugin")});
        return SignFlow{SignFlowDeps{
            .holder = *holder,
            .signer = signer,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .requester = "test-client",
            .params = baseParams(),
            .token = source.token(),
        }};
    }
};

// One cold request followed by @p rejections rejection-signalled ones.
std::vector<bool> coldThenRejections(std::size_t rejections)
{
    std::vector<bool> script{false};
    script.insert(script.end(), rejections, true);
    return script;
}

} // namespace

// --- the card's rejection signal, and this operation's allowance -------------

// The channel-establishment secret carries this operation's own AttemptContext,
// so it shares the PACE cap with the read flows: three genuine rejections
// exhaust THIS operation's allowance and a fourth request must be refused
// before raising a dialog -- not merely wired to a counter that stays at zero.
TEST(SignFlow, ThePaceCapBitesOnTheChannelEstablishmentPath)
{
    Harness h;
    h.signer.canScript = coldThenRejections(kMaxPaceAttempts);

    const auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok) << "the uncached PIN half is untouched by the channel cap";

    ASSERT_EQ(h.signer.canResults.size(), kMaxPaceAttempts + 1);
    for (std::size_t i = 0; i < kMaxPaceAttempts; ++i) {
        EXPECT_EQ(h.signer.canResults[i].status, LibreSCRS::Auth::CredentialResult::Status::Ok)
            << "request " << i << " should still be allowed to ask";
    }
    EXPECT_EQ(h.prompter.canCalls, static_cast<int>(kMaxPaceAttempts))
        << "each of the first three requests raised a real dialog";
    EXPECT_EQ(h.signer.canResults.back().status, LibreSCRS::Auth::CredentialResult::Status::Error)
        << "the fourth request must be refused, not prompted -- the whole point of the cap";
}

TEST(SignFlow, EachRejectionMovesTheRetryContextByExactlyOne)
{
    // The number the dialog shows is the observable. Rejection N must produce
    // prompt N+1: never a jump (one rejected value counted twice) and never a
    // stall (a provider that detects nothing, which looks perfectly healthy
    // right up until the cap silently never bites). Three requests, and the
    // claim is checked on the LAST -- with two, "first" and "last" agree by
    // accident.
    Harness h;
    h.signer.canScript = coldThenRejections(2);

    (void)h.make().run();

    ASSERT_EQ(h.prompter.canCalls, 3) << "cold, then a re-prompt after each of the two rejections";
    EXPECT_EQ(h.prompter.lastCanOptions.attempt, 3u) << "two distinct rejections -> the third attempt, not the fifth";
    EXPECT_EQ(h.prompter.lastCanOptions.lastError, LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key)
        << "the re-prompt says why it is asking again";
}

TEST(SignFlow, EmptyReasonReinvocationsAreNotRejectionsAndReplayTheCache)
{
    // The provider must key on the card's REJECTION SIGNAL, never on invocation
    // counting. Same-kind re-invocations carrying no reason at all (a PACE->BAC
    // fallback, a multi-candidate walk) are not rejections: the collected value
    // is still live and is replayed from cache, silently, however many arrive.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    h.signer.canScript = {false, false, false, false};

    (void)h.make().run();

    ASSERT_EQ(h.signer.canResults.size(), 4u);
    for (std::size_t i = 0; i < h.signer.canResults.size(); ++i) {
        EXPECT_EQ(h.signer.canResults[i].status, LibreSCRS::Auth::CredentialResult::Status::Ok)
            << "request " << i << " is served from cache";
    }
    EXPECT_EQ(h.prompter.canCalls, 0) << "not one of them raised a dialog";
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "and none of them evicted a value the card never rejected";
}

TEST(SignFlow, ARejectionSignalAfterAnUnansweredWindowIsNotARejection)
{
    // Measured on a live agent, on the read path this flow's provider mirrors:
    // when the previous prompt yielded NOTHING -- the clock closed it, or the
    // holder dismissed it -- no secret ever reached the card. Its activation
    // fails anyway and it re-invokes carrying the SAME reason a genuinely wrong
    // value earns. Acting on it there evicts a value nobody supplied, spends
    // one of the three PACE attempts, and puts "the value entered was not
    // accepted" in front of a holder who entered nothing.
    //
    // The empty window is SEEDED rather than produced by a live expiry on
    // purpose: a real one also bumps the card's refusal generation, and the
    // queued-refusal gate would then silence the follow-up before the predicate
    // under test was ever consulted. This isolates the predicate.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    h.cache.noteLastPromptYieldedNothing("card-A", true);
    h.signer.canScript = {true}; // the card's rejection signal, first thing

    (void)h.make().run();

    EXPECT_TRUE(h.cache.hasCan("card-A"))
        << "nothing was presented, so nothing was rejected -- the cached secret must survive";
    EXPECT_EQ(h.prompter.canCalls, 0) << "and the surviving secret is served from cache, with no dialog";
    ASSERT_EQ(h.signer.canResults.size(), 1u);
    EXPECT_EQ(h.signer.canResults[0].status, LibreSCRS::Auth::CredentialResult::Status::Ok);
}

TEST(SignFlow, ARejectionSignalAfterAnAnsweredWindowStillEvicts)
{
    // The companion that keeps the test above from passing vacuously. Identical
    // setup except that the last prompt DID yield a secret, which is the whole
    // difference: this one is a real rejection, so the cached value is evicted
    // and a fresh dialog is raised.
    Harness h;
    h.cache.putCan("card-A", LibreSCRS::Secure::String{"000000"});
    h.cache.noteLastPromptYieldedNothing("card-A", false);
    h.signer.canScript = {true};

    (void)h.make().run();

    EXPECT_EQ(h.prompter.canCalls, 1) << "a real rejection re-prompts";
    EXPECT_EQ(h.prompter.lastCanOptions.attempt, 2u) << "and the re-prompt is numbered as the second attempt";
    ASSERT_TRUE(h.cache.getCan("card-A").has_value());
    EXPECT_EQ(h.cache.getCan("card-A")->view(), std::string_view{"123456"})
        << "the rejected value was evicted; what is cached now is what the fresh dialog collected";
}
