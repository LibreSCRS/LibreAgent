// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of SignFlow's phase sequencing. The sign operation's
// pre-consent stretch does real on-card work (the anti-TOCTOU re-read, PACE
// establishment) inside the signer seam, and a client's pre-PIN window can
// name that work only if the flow sets Reading BEFORE the seam runs — a phase
// first set after the prompt leaves the window on its generic busy text. So
// the signer fake snapshots the recorded phases at its OWN entry: the claim
// is ordering against the seam, not membership in the final sequence.
//
// The harness deliberately mirrors BatchSignFlowTest's: every seam is a Fake,
// the flow runs synchronously on the test thread, and the fake signer drives
// the flow's installed provider on the real path.
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SignFlow.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <expected>
#include <memory>
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
    PromptResult pinResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"}, ""};

    PromptResult requestPin(const PromptOptions&) override
    {
        return pinResult;
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

// Models the terminal signing op: one uncached PIN request, then success. At
// ENTRY it snapshots what the flow has emitted so far — the on-card work this
// seam models starts here, so whatever phase should cover that work must
// already be in the snapshot.
class FakeSigner final : public Signer
{
public:
    const RecordingPhaseSink* sink = nullptr;
    std::string cardPin = "1234";
    std::vector<std::uint32_t> phasesAtEntry;

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList&, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken) override
    {
        if (sink != nullptr) {
            phasesAtEntry = sink->phases;
        }
        const auto req =
            LibreSCRS::Auth::AuthRequirement::forSigning(LibreSCRS::LocalizedText{"", "PIN", {}}, std::nullopt);
        const auto result = credentials(req);
        SignOutcome out;
        if (result.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
            out.status = SignOutcome::Status::CommunicationError;
            return out;
        }
        const auto* pin = result.find(LibreSCRS::PrompterWire::kKindPin);
        if (pin == nullptr || std::string{pin->view()} != cardPin) {
            out.status = SignOutcome::Status::AuthFailed;
            return out;
        }
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
        signer.sink = &phaseSink;
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

} // namespace

// --- the pre-PIN window's phase ----------------------------------------------

TEST(SignFlow, ReadingCoversThePreConsentWork)
{
    Harness h;
    const auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);

    const auto kReading = static_cast<std::uint32_t>(OperationPhase::Reading);

    // The seam entered with Reading already the operation's current phase — the
    // emit precedes the on-card work, which is the entire point.
    ASSERT_FALSE(h.signer.phasesAtEntry.empty()) << "the signer ran before any phase was set";
    EXPECT_EQ(h.signer.phasesAtEntry.back(), kReading);

    // The complete machine sequence for the no-CAN, b-b path, pinned in order:
    // pre-consent Reading, the consent window, then the post-consent pair. One
    // Reading total — nothing later re-enters it.
    const std::vector<std::uint32_t> expected{
        kReading,
        static_cast<std::uint32_t>(OperationPhase::AwaitingConsent),
        static_cast<std::uint32_t>(OperationPhase::Authenticating),
        static_cast<std::uint32_t>(OperationPhase::Signing),
    };
    EXPECT_EQ(h.phaseSink.phases, expected);
}
