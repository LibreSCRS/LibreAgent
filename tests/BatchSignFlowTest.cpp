// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of BatchSignFlow. Every seam is a Fake; the flow runs
// synchronously on the test thread. Covers: entry-count validation, the
// unified credential provider (ask-once, cached-thereafter, no re-prompt
// after a halt), halt-on-wrong/blocked-credential row marking, the PIN
// holder's wipe-on-every-exit-path contract, and the terminal Ok-iff-any-
// row-signed matrix. The LM signer-error mapping itself (does LmSigner
// actually classify a real PinVerificationFailed/CardBlocked into the two
// statuses this flow halts on) is a SEPARATE seam-level concern this fake
// signer cannot observe -- see LmSeamsRoutingTest.cpp's LmSeamsResultMapping
// cases.
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptPolicy.h>  // kMaxPaceAttempts
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h> // ErrorKeys::preReadAuthFailed (the card's re-prompt signal)
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
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
    // The options passed on the FIRST (and, per the ask-once contract, only)
    // requestPin() call -- so a test can assert the consent shape without
    // needing its own recording wrapper.
    std::optional<PromptOptions> lastOptions;

    PromptResult requestPin(const PromptOptions& options) override
    {
        ++pinCalls;
        lastOptions = options;
        return pinResult;
    }
    // Counts real CAN prompts, distinguishing them from a cache replay or a
    // capped call that never reached here -- the PACE-cap test below needs
    // this to see whether the fourth request actually raised a dialog.
    int canCalls = 0;
    PromptResult canResult{PromptStatus::Error, std::nullopt, "uninitialised"};
    PromptResult requestCan(const PromptOptions&) override
    {
        ++canCalls;
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

// Models the terminal per-document signing op. Every call fetches the
// credential provider's PIN on the REAL path (proving the cache/ask-once
// behaviour end to end, not a fake that ignores the provider): a PIN that
// does not match `cardPin` maps to AuthFailed, mirroring LmSigner's own
// PinVerificationFailed -> AuthFailed classification. `scriptedStatus`
// overrides the outcome AFTER a successful PIN match, keyed by the 1-based
// call index, so a test can force CardBlocked or a non-halting per-row
// failure (KeyNotFound, InvalidDocument, ...) on a specific document without
// touching the PIN itself.
class FakeSigner final : public Signer
{
public:
    int calls = 0;
    std::string cardPin = "1234";
    std::map<int, SignOutcome::Status> scriptedStatus;
    std::vector<std::vector<std::uint8_t>> receivedDocs;
    // When set (consulted only on the FIRST sign() call), drives this many
    // CAN requirement calls through the installed provider BEFORE requesting
    // the PIN -- the first cold (empty reason), every subsequent one carrying
    // the card's rejection signal (reasonForUser == preReadAuthFailed()),
    // mirroring a real wrong-CAN retry cycle within one activation. Lets a
    // test drive the channel-establishment path directly and observe whether
    // the PACE cap actually refuses a request, not just whether it is wired.
    int canCallsToScript = 0;
    std::vector<LibreSCRS::Auth::CredentialResult> canResults;

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList&, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken) override
    {
        ++calls;
        receivedDocs.push_back(params.inputDocument);

        if (calls == 1 && canCallsToScript > 0) {
            using LibreSCRS::Auth::PaceSecretKind;
            for (int i = 0; i < canCallsToScript; ++i) {
                const auto canReq = LibreSCRS::Auth::AuthRequirement::forPaceSecret(
                    LibreSCRS::SmartCard::AppletAid{}, PaceSecretKind::Can, std::nullopt,
                    i == 0 ? LibreSCRS::LocalizedText{} : LibreSCRS::Auth::ErrorKeys::preReadAuthFailed());
                canResults.push_back(credentials(canReq));
            }
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

        const auto it = scriptedStatus.find(calls);
        const auto status = (it != scriptedStatus.end()) ? it->second : SignOutcome::Status::Ok;
        SignOutcome out;
        out.status = status;
        if (status == SignOutcome::Status::Ok) {
            out.signedDocumentBytes = params.inputDocument;
            out.signedDocumentBytes.push_back(0xAA); // trivial "signature" marker
            out.resolvedFormat = params.format;
            out.resolvedLevel = params.level;
            out.chainComplete = true;
        }
        return out;
    }
};

std::vector<BatchDocumentInput> threeDocuments()
{
    return {
        BatchDocumentInput{"invoice-1.pdf", {0x01}},
        BatchDocumentInput{"invoice-2.pdf", {0x02}},
        BatchDocumentInput{"invoice-3.pdf", {0x03}},
    };
}

struct Harness
{
    std::unique_ptr<CardSessionHolder> holder;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    FakeSigner signer;
    BatchPinHolder pinHolder;
    std::vector<BatchDocumentInput> documents{threeDocuments()};

    SignParams baseParams()
    {
        SignParams p;
        p.certId = "abc123";
        p.format = "pades";
        p.level = "b-b";
        p.packaging = "enveloped";
        return p;
    }

    BatchSignFlow make()
    {
        holder = makeHolder(CandidateList{mkSigning("stub-plugin")});
        return BatchSignFlow{BatchSignFlowDeps{
            .holder = *holder,
            .signer = signer,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .pinHolder = pinHolder,
            .cardKey = "card-A",
            .requester = "test-client",
            .params = baseParams(),
            .documents = documents,
            .token = source.token(),
        }};
    }
};

} // namespace

// --- isValidBatchDocumentCount: pure, direct coverage -----------------------

TEST(BatchSignFlowEntryGate, ZeroIsInvalid)
{
    EXPECT_FALSE(isValidBatchDocumentCount(0));
}
TEST(BatchSignFlowEntryGate, OneIsValid)
{
    EXPECT_TRUE(isValidBatchDocumentCount(1));
}
TEST(BatchSignFlowEntryGate, TwelveIsValid)
{
    EXPECT_TRUE(isValidBatchDocumentCount(12));
}
TEST(BatchSignFlowEntryGate, ThirteenIsInvalid)
{
    EXPECT_FALSE(isValidBatchDocumentCount(13));
}

// --- entry validation, exercised through the flow itself --------------------

TEST(BatchSignFlow, ZeroDocumentsIsRefusedBeforeTouchingAnySeam)
{
    Harness h;
    h.documents.clear();
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::InvalidRequest);
    EXPECT_TRUE(r.rows.empty());
    EXPECT_EQ(h.prompter.pinCalls, 0) << "an invalid batch never reaches the prompter";
    EXPECT_EQ(h.signer.calls, 0) << "an invalid batch never reaches the signer";
    EXPECT_TRUE(h.pinHolder.wiped()) << "wiped() is true on every run() exit, even the earliest refusal";
}

TEST(BatchSignFlow, ThirteenDocumentsIsRefused)
{
    Harness h;
    h.documents.clear();
    for (int i = 0; i < 13; ++i) {
        h.documents.push_back(BatchDocumentInput{"doc" + std::to_string(i) + ".pdf", {0x01}});
    }
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::InvalidRequest);
    EXPECT_TRUE(r.rows.empty());
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_EQ(h.signer.calls, 0);
    EXPECT_TRUE(h.pinHolder.wiped()) << "wiped() is true on every run() exit, even the earliest refusal";
}

// --- consent + ask-once -----------------------------------------------------

TEST(BatchSignFlow, ConsentOptionsCarryEveryDocumentsDisplayName)
{
    Harness h;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Ok);
    ASSERT_TRUE(h.prompter.lastOptions.has_value());
    EXPECT_EQ(h.prompter.lastOptions->artifact, "signature-batch")
        << "artifact stays the TRUSTED agent-owned category token, never a client-supplied name";
    ASSERT_EQ(h.prompter.lastOptions->artifacts.size(), 3u);
    EXPECT_EQ(h.prompter.lastOptions->artifacts[0], "invoice-1.pdf");
    EXPECT_EQ(h.prompter.lastOptions->artifacts[1], "invoice-2.pdf");
    EXPECT_EQ(h.prompter.lastOptions->artifacts[2], "invoice-3.pdf");
    EXPECT_FALSE(h.prompter.lastOptions->description.empty()) << "a legacy description summary is always populated";
}

TEST(BatchSignFlow, PinIsAskedExactlyOnceAcrossEveryDocument)
{
    Harness h;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1) << "one consent covers the whole batch";
    EXPECT_EQ(h.signer.calls, 3) << "every document is attempted";
    ASSERT_EQ(r.rows.size(), 3u);
    for (const auto& row : r.rows) {
        EXPECT_EQ(row.code, ErrorCode::None);
        EXPECT_FALSE(row.signedBytes.empty());
    }
}

// The channel-establishment secret (CAN) now carries its own per-operation
// AttemptContext (see BatchSignFlow's credential-provider preamble), so it
// shares the PACE cap with the read flows: three genuine rejections exhaust
// THIS batch's allowance, and a fourth request must be refused before ever
// raising a dialog -- not merely wired to a parameter that stays at zero.
TEST(BatchSignFlow, ThePaceCapBitesOnTheChannelEstablishmentPath)
{
    Harness h;
    h.prompter.canResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    h.signer.canCallsToScript = static_cast<int>(kMaxPaceAttempts) + 1;

    auto flow = h.make();
    (void)flow.run();

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

TEST(BatchSignFlow, PinHolderIsWipedAfterASuccessfulBatch)
{
    Harness h;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Ok);
    EXPECT_TRUE(h.pinHolder.wiped());
    EXPECT_EQ(h.pinHolder.get(), nullptr);
}

// --- halt on wrong/blocked credential ---------------------------------------

TEST(BatchSignFlow, WrongPinHaltsTheRemainingDocumentsWithTheHaltCode)
{
    Harness h;
    h.signer.cardPin = "1234";
    h.prompter.pinResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"9999"}, ""}; // mismatch
    auto r = h.make().run();

    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Error) << "zero rows signed";
    EXPECT_EQ(r.code, ErrorCode::CredentialWrong);
    EXPECT_EQ(h.prompter.pinCalls, 1) << "no re-prompt after the halt";
    EXPECT_EQ(h.signer.calls, 1) << "only the first (halting) document is attempted";
    ASSERT_EQ(r.rows.size(), 3u);
    for (const auto& row : r.rows) {
        EXPECT_EQ(row.code, ErrorCode::CredentialWrong);
        EXPECT_TRUE(row.signedBytes.empty());
    }
    EXPECT_TRUE(h.pinHolder.wiped()) << "the halt path still wipes the PIN";
}

TEST(BatchSignFlow, CardBlockedHaltsTheRemainingDocumentsWithTheHaltCode)
{
    Harness h;
    h.signer.scriptedStatus[1] = SignOutcome::Status::CardBlocked; // first document's card reports blocked
    auto r = h.make().run();

    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::CredentialBlocked);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_EQ(h.signer.calls, 1) << "the remaining documents are never attempted";
    ASSERT_EQ(r.rows.size(), 3u);
    for (const auto& row : r.rows) {
        EXPECT_EQ(row.code, ErrorCode::CredentialBlocked);
    }
    EXPECT_TRUE(h.pinHolder.wiped());
}

TEST(BatchSignFlow, PartialSuccessThenHaltIsOkWithPerRowCodesAuthoritative)
{
    Harness h;
    h.signer.scriptedStatus[2] = SignOutcome::Status::AuthFailed; // second document halts
    auto r = h.make().run();

    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Ok) << ">= 1 row signed (the first)";
    EXPECT_EQ(h.signer.calls, 2) << "the third document is never attempted after the halt";
    ASSERT_EQ(r.rows.size(), 3u);
    EXPECT_EQ(r.rows[0].code, ErrorCode::None);
    EXPECT_FALSE(r.rows[0].signedBytes.empty());
    EXPECT_EQ(r.rows[1].code, ErrorCode::CredentialWrong);
    EXPECT_EQ(r.rows[2].code, ErrorCode::CredentialWrong) << "inherits the halt code without being attempted";
    EXPECT_TRUE(h.pinHolder.wiped());
}

// --- non-halting per-row failures --------------------------------------------

TEST(BatchSignFlow, ANonHaltingPerRowFailureDoesNotStopTheBatch)
{
    Harness h;
    h.signer.scriptedStatus[2] = SignOutcome::Status::KeyNotFound; // one bad document, not a credential problem
    auto r = h.make().run();

    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Ok);
    EXPECT_EQ(h.signer.calls, 3) << "every document is still attempted";
    ASSERT_EQ(r.rows.size(), 3u);
    EXPECT_EQ(r.rows[0].code, ErrorCode::None);
    EXPECT_EQ(r.rows[1].code, ErrorCode::KeyNotFound);
    EXPECT_EQ(r.rows[2].code, ErrorCode::None);
}

TEST(BatchSignFlow, AllRowsFailingNonHaltingYieldsErrorWithTheLastRowsCode)
{
    Harness h;
    h.signer.scriptedStatus[1] = SignOutcome::Status::InvalidDocument;
    h.signer.scriptedStatus[2] = SignOutcome::Status::InvalidDocument;
    h.signer.scriptedStatus[3] = SignOutcome::Status::InvalidDocument;
    auto r = h.make().run();

    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Error) << "zero rows signed";
    EXPECT_EQ(r.code, ErrorCode::InvalidDocument);
    EXPECT_EQ(h.signer.calls, 3) << "no halt: every document is independently attempted";
    ASSERT_EQ(r.rows.size(), 3u);
    for (const auto& row : r.rows) {
        EXPECT_EQ(row.code, ErrorCode::InvalidDocument);
    }
}

// --- cancellation -------------------------------------------------------------

TEST(BatchSignFlow, PrompterCancelMapsToCancelledAndWipesThePin)
{
    // The user declines the PIN prompt on document 1. FakeSigner's own
    // sign() call is what invokes the credential provider (mirroring the
    // real LmSigner path), so it IS called once for the first document --
    // it observes the cancelled credential result and returns
    // SignOutcome::Status::Cancelled, which the flow remaps to Cancelled
    // before ever building a row.
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Cancelled);
    EXPECT_TRUE(r.rows.empty());
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_EQ(h.signer.calls, 1) << "only the first document's sign() attempt observes the cancelled prompt";
    EXPECT_TRUE(h.pinHolder.wiped());
}

TEST(BatchSignFlow, TokenCancelledBeforeRunMapsCancelled)
{
    Harness h;
    ASSERT_TRUE(h.source.requestCancel());
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Cancelled);
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_EQ(h.signer.calls, 0);
    EXPECT_TRUE(h.pinHolder.wiped());
}

// --- phase sequencing ---------------------------------------------------------

TEST(BatchSignFlow, PhasesCoverConsentAndSigningExactlyOnceEachForTheFirstDocument)
{
    Harness h;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, BatchSignFlow::Outcome::Ok);
    const auto kAwaiting = static_cast<std::uint32_t>(OperationPhase::AwaitingConsent);
    const auto kSigning = static_cast<std::uint32_t>(OperationPhase::Signing);
    int awaitingCount = 0;
    for (const auto p : h.phaseSink.phases) {
        if (p == kAwaiting) {
            ++awaitingCount;
        }
    }
    EXPECT_EQ(awaitingCount, 1) << "AwaitingConsent fires only for the single, uncached prompt";
    bool sawSigning = false;
    for (const auto p : h.phaseSink.phases) {
        if (p == kSigning) {
            sawSigning = true;
        }
    }
    EXPECT_TRUE(sawSigning);
}
