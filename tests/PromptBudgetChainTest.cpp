// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// How long ONE request may keep a holder in front of dialogs.
//
// kMaxSequentialPromptBudget is a number; what makes it true is this file. It
// drives the three seams that collect credentials -- the read flows' shared
// provider, SignFlow's unified provider, BatchSignFlow's -- with a prompter
// that RECORDS the order of prompt kinds, and asserts that the deadlines of
// one request's chain add up to no more than the budget. A new chain that
// exceeded it would break a case here rather than quietly outliving whatever
// transport carries its prompts.
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/cache/AttemptContext.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptPolicy.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SignFlow.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <numeric>
#include <sstream>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// The prompt kind a seam actually asked for, in the order it asked. Counting
// calls per kind would not answer the question: the budget is about a CHAIN,
// so what matters is which kinds one request runs one after the other.
class RecordingPrompter final : public PrompterClientBase
{
public:
    std::vector<PromptKind> chain;
    int totalCalls = 0;

    PromptResult pinResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"}, ""};
    PromptResult canResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    PromptResult mrzResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};

    PromptResult requestPin(const PromptOptions&) override
    {
        record(PromptKind::Pin);
        return pinResult;
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        record(PromptKind::Can);
        return canResult;
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        record(PromptKind::Mrz);
        return mrzResult;
    }
    PinChangePromptResult requestPinChange(const PromptOptions&) override
    {
        record(PromptKind::ChangePin);
        PinChangePromptResult r;
        r.status = PromptStatus::Ok;
        r.current = LibreSCRS::Secure::String{"1234"};
        r.newPin = LibreSCRS::Secure::String{"5678"};
        return r;
    }

private:
    void record(PromptKind k)
    {
        chain.push_back(k);
        ++totalCalls;
    }
};

// Drop // line comments and /* */ blocks so a doc comment that NAMES a
// function is not counted as a call to it.
std::string stripComments(const std::string& source)
{
    std::string code;
    code.reserve(source.size());
    for (std::size_t i = 0; i < source.size(); ++i) {
        if (source[i] == '/' && i + 1 < source.size() && source[i + 1] == '/') {
            while (i < source.size() && source[i] != '\n') {
                ++i;
            }
        } else if (source[i] == '/' && i + 1 < source.size() && source[i + 1] == '*') {
            i += 2;
            while (i + 1 < source.size() && !(source[i] == '*' && source[i + 1] == '/')) {
                ++i;
            }
            ++i;
            continue;
        }
        if (i < source.size()) {
            code.push_back(source[i]);
        }
    }
    return code;
}

std::chrono::milliseconds chainCost(const std::vector<PromptKind>& chain)
{
    return std::accumulate(chain.begin(), chain.end(), std::chrono::milliseconds{0},
                           [](std::chrono::milliseconds acc, PromptKind k) { return acc + deadlineFor(k); });
}

class RecordingPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t) noexcept override {}
};

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

CandidateList signingCandidate()
{
    return {std::make_shared<StubPlugin>("stub-plugin", LibreSCRS::Plugin::CardCapabilities::PKI |
                                                            LibreSCRS::Plugin::CardCapabilities::PinManagement)};
}

std::unique_ptr<CardSessionHolder> makeHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) {
        return signingCandidate();
    };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

LibreSCRS::Auth::AuthRequirement canRequirement()
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{},
                                                           LibreSCRS::Auth::PaceSecretKind::Can, std::nullopt,
                                                           LibreSCRS::LocalizedText{});
}

LibreSCRS::Auth::AuthRequirement mrzRequirement()
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{},
                                                           LibreSCRS::Auth::PaceSecretKind::Mrz, std::nullopt,
                                                           LibreSCRS::LocalizedText{});
}

LibreSCRS::Auth::AuthRequirement signingRequirement()
{
    return LibreSCRS::Auth::AuthRequirement::forSigning(
        LibreSCRS::LocalizedText{.key = "", .defaultText = "PIN", .placeholders = {}}, std::nullopt);
}

// Drives the channel-establishment secret and then the signing PIN through
// whatever provider the flow installed -- the chain a real signature runs.
class ChainDrivingSigner final : public Signer
{
public:
    // The channel secret this signer asks for. Mrz is what the budget assert
    // is measured against: an Mrz -> Pin chain is 360 s and does not fit.
    LibreSCRS::Auth::PaceSecretKind channelKind = LibreSCRS::Auth::PaceSecretKind::Can;
    int calls = 0;

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList&, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken) override
    {
        ++calls;
        (void)credentials(channelKind == LibreSCRS::Auth::PaceSecretKind::Mrz ? mrzRequirement() : canRequirement());
        (void)credentials(signingRequirement());
        SignOutcome out;
        out.status = SignOutcome::Status::Ok;
        out.signedDocumentBytes = params.inputDocument;
        out.resolvedFormat = params.format;
        out.resolvedLevel = params.level;
        return out;
    }
};

SignParams baseParams()
{
    SignParams p;
    p.certId = "abc123";
    p.inputDocument = {'%', 'P', 'D', 'F'};
    p.format = "pades";
    p.level = "b-b";
    p.packaging = "enveloped";
    p.displayName = "doc.pdf";
    return p;
}

// --- the three seams, each returning the chain ONE request ran --------------

// The read flows' shared provider, built exactly as every read flow builds it.
std::vector<PromptKind> runReadSeam(RecordingPrompter& prompter)
{
    CredentialCache cache;
    PromptSerializer serializer;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    const std::string cardKey = "card-read";
    auto attempts = std::make_shared<AttemptContext>(cache.refusalGenerationFor(cardKey));
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);

    const auto before = prompter.chain.size();
    auto provider =
        FlowPrelude::makeReadCredentialProvider(cache, prompter, serializer, phaseSink, cardKey, "test-client",
                                                "identity", source.token(), attempts, prompterFailed);
    // A contactless card asks for the channel secret first.
    const auto channel = provider(canRequirement());
    EXPECT_EQ(channel.status, LibreSCRS::Auth::CredentialResult::Status::Ok);
    // ... and a plugin that then wants a PIN gets no dialog from THIS seam:
    // the read provider serves only the cacheable channel secrets, so a read
    // chain is one prompt long however many times the card asks.
    (void)provider(signingRequirement());

    return {prompter.chain.begin() + static_cast<std::ptrdiff_t>(before), prompter.chain.end()};
}

std::vector<PromptKind> runSignSeam(RecordingPrompter& prompter, LibreSCRS::Auth::PaceSecretKind channelKind)
{
    auto holder = makeHolder();
    ChainDrivingSigner signer;
    signer.channelKind = channelKind;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;

    const auto before = prompter.chain.size();
    SignFlow flow{SignFlowDeps{
        .holder = *holder,
        .signer = signer,
        .prompter = prompter,
        .serializer = serializer,
        .cache = cache,
        .phaseSink = phaseSink,
        .cardKey = "card-sign",
        .requester = "test-client",
        .params = baseParams(),
        .token = source.token(),
    }};
    (void)flow.run();
    EXPECT_EQ(signer.calls, 1);

    return {prompter.chain.begin() + static_cast<std::ptrdiff_t>(before), prompter.chain.end()};
}

std::vector<PromptKind> runBatchSeam(RecordingPrompter& prompter)
{
    auto holder = makeHolder();
    ChainDrivingSigner signer;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    BatchPinHolder pinHolder;
    LibreSCRS::CancelSource source;
    std::vector<BatchDocumentInput> documents{BatchDocumentInput{"invoice-1.pdf", {0x01}},
                                              BatchDocumentInput{"invoice-2.pdf", {0x02}}};

    const auto before = prompter.chain.size();
    BatchSignFlow flow{BatchSignFlowDeps{
        .holder = *holder,
        .signer = signer,
        .prompter = prompter,
        .serializer = serializer,
        .cache = cache,
        .phaseSink = phaseSink,
        .pinHolder = pinHolder,
        .cardKey = "card-batch",
        .requester = "test-client",
        .params = baseParams(),
        .documents = documents,
        .token = source.token(),
    }};
    (void)flow.run();
    EXPECT_EQ(signer.calls, 2) << "both documents were signed under one consent";

    return {prompter.chain.begin() + static_cast<std::ptrdiff_t>(before), prompter.chain.end()};
}

} // namespace

TEST(PromptBudgetChain, ReadingACardStaysWithinTheBudget)
{
    RecordingPrompter prompter;
    const auto chain = runReadSeam(prompter);

    EXPECT_EQ(chain, (std::vector<PromptKind>{PromptKind::Can}))
        << "the read provider serves the channel secret and refuses a PIN without prompting";
    EXPECT_LE(chainCost(chain), kMaxSequentialPromptBudget);
}

TEST(PromptBudgetChain, SigningOneDocumentStaysWithinTheBudget)
{
    RecordingPrompter prompter;
    const auto chain = runSignSeam(prompter, LibreSCRS::Auth::PaceSecretKind::Can);

    EXPECT_EQ(chain, (std::vector<PromptKind>{PromptKind::Can, PromptKind::Pin}));
    EXPECT_LE(chainCost(chain), kMaxSequentialPromptBudget);
}

TEST(PromptBudgetChain, SigningABatchStaysWithinTheBudget)
{
    RecordingPrompter prompter;
    const auto chain = runBatchSeam(prompter);

    EXPECT_EQ(chain, (std::vector<PromptKind>{PromptKind::Can, PromptKind::Pin}))
        << "the second document reuses the consent the first one collected";
    EXPECT_LE(chainCost(chain), kMaxSequentialPromptBudget);
}

// The budget bounds what these three seams do, which is only a bound on the
// agent if they are ALL of the seams that collect credentials. That is a
// question about the SOURCE, not about a recording: a fourth call site raises
// no dialog in this binary until someone drives it, and would sit unmeasured
// behind a green run. So this case counts the call sites on disk.
//
// Structural, because the thing being counted is a call site and not a
// behaviour: every production caller of CredentialCache::requestCredential
// must be one of the three this file drives. A new one breaks this case, which
// is where a fourth chain gets added and the budget re-derived.
TEST(PromptBudgetChain, ThreeProductionCallSitesCollectCredentials)
{
    const std::filesystem::path root{LIBREAGENT_SRC_DIR};
    ASSERT_TRUE(std::filesystem::is_directory(root)) << "source tree not wired: " << LIBREAGENT_SRC_DIR;

    std::map<std::string, int> found;
    int filesRead = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator{root}) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto ext = entry.path().extension().string();
        if (ext != ".cpp" && ext != ".h") {
            continue;
        }
        std::ifstream in{entry.path()};
        ASSERT_TRUE(in.good()) << "unreadable source: " << entry.path();
        std::stringstream buffer;
        buffer << in.rdbuf();
        ++filesRead;
        const auto code = stripComments(buffer.str());
        // Count the CALLS, not the mentions: the doc comments around these
        // sites name the function too, which is why the comments come out
        // first.
        std::size_t at = 0;
        int calls = 0;
        const std::string needle = ".requestCredential(";
        while ((at = code.find(needle, at)) != std::string::npos) {
            ++calls;
            at += needle.size();
        }
        if (calls > 0) {
            found.emplace(std::filesystem::relative(entry.path(), root).generic_string(), calls);
        }
    }

    // A grep that read nothing would agree with every expectation below.
    ASSERT_GT(filesRead, 20) << "the scan found almost no sources -- it is measuring the wrong tree";

    const std::map<std::string, int> expected{
        {"operations/BatchSignFlow.cpp", 1},
        {"operations/FlowPrelude.cpp", 1},
        {"operations/SignFlow.cpp", 1},
    };
    EXPECT_EQ(found, expected) << "every production caller must be one of the three chains measured above";
}

// One prompter across all three seams: the dialogs they raise, in order, are
// exactly the three chains and nothing else. Asserting the WHOLE sequence
// rather than its length is what makes an unplanned dialog visible -- a count
// compared against a sum of slices of the same recording cannot fail.
TEST(PromptBudgetChain, TheThreeSeamsRaiseExactlyTheseDialogs)
{
    RecordingPrompter prompter;
    (void)runReadSeam(prompter);
    (void)runSignSeam(prompter, LibreSCRS::Auth::PaceSecretKind::Can);
    (void)runBatchSeam(prompter);

    EXPECT_EQ(prompter.chain, (std::vector<PromptKind>{PromptKind::Can, PromptKind::Can, PromptKind::Pin,
                                                       PromptKind::Can, PromptKind::Pin}));
    EXPECT_LE(chainCost(prompter.chain), 3 * kMaxSequentialPromptBudget) << "three requests, three budgets";
}

// The bound is not vacuous: a chain that opens with the MRZ form instead of
// the CAN one is 300 s + 60 s and does not fit. The constant is the sum of the
// two longest forms ONE request may run in sequence, not the sum of every form
// that exists.
TEST(PromptBudgetChain, AnMrzThenPinChainWouldNotFit)
{
    EXPECT_GT(deadlineFor(PromptKind::Mrz) + deadlineFor(PromptKind::Pin), kMaxSequentialPromptBudget);
    EXPECT_LE(deadlineFor(PromptKind::Can) + deadlineFor(PromptKind::Pin), kMaxSequentialPromptBudget);
}
