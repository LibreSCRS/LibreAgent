// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of RawCryptoFlow. Every seam is a Fake; the flow runs
// synchronously on the test thread. This covers the orchestration shared with
// SignFlow (open + classify + install the unified PIN/CAN credential provider +
// watchdog-safe phase ordering) plus the raw-crypto-specific status mapping and
// the prompter-as-consent wiring — the terminal LmRawCrypto sign/decrypt op is
// injected as a function seam so no live card is needed.
//
// NOT covered here (they live inside LmRawCrypto, which uses real LM types + a
// live card): the per-family CardPlugin::sign / decipher routing and the
// anti-TOCTOU certId re-assert — those are hardware-validated.
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RawCryptoFlow.h>

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
#include <cstdint>
#include <expected>
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

inline std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> mkSigning(std::string id)
{
    return std::make_shared<StubPlugin>(std::move(id), LibreSCRS::Plugin::CardCapabilities::PKI |
                                                           LibreSCRS::Plugin::CardCapabilities::PinManagement);
}

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

struct Harness
{
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    CandidateList candidates;
    std::unique_ptr<CardSessionHolder> holder;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;

    // Injected terminal raw-crypto op. Models the PRODUCTION verify->op path: it
    // receives the PIN the flow collected from the prompter (non-null on the
    // first op of a lease, null once verified) and models a card that
    // verifies the PIN before the PSO — exactly what LmRawCrypto::signRaw does
    // (plugin->verifyPIN then plugin->sign). This pins the consent contract to
    // the real flow path, not to a fake that re-reads the provider.
    RawCryptoResult opResult{RawCryptoStatus::Ok, {'S', 'I', 'G'}};
    std::string cardPin = "1234"; // the PIN the modeled card accepts
    int opCalls = 0;
    int verifyCalls = 0;         // count of ops that received a PIN to verify
    bool sawPin = false;         // last verifying op saw a non-empty PIN
    bool sawNullPinOnce = false; // an op ran with null PIN (already-verified lease)

    // Lease verified state (mirrors LeaseManager's per-lease boolean).
    bool pinVerified = false;

    // Models the on-card channel's verified state — DISTINCT from the lease
    // boolean. The held opensc channel persists the PIN-verified state until the
    // idle-close drops it; after a drop the channel is fresh + unverified even
    // though the lease boolean is still true (the desync). The fake op
    // honours this: a null-PIN op against an UNVERIFIED channel fails CardError
    // (mirrors the on-card PSO returning SECURITY_STATUS, which LM folds to
    // CardError), exactly the wedge condition.
    bool channelVerified = false;

    // When set, the NEXT null-PIN op simulates the holder having silently dropped
    // + reacquired a fresh channel (idle-close): it flips channelVerified to false
    // before evaluating, so the op sees an unverified channel and CardErrors.
    bool dropChannelOnNextNullPinOp = false;

    RawCryptoOp op()
    {
        return [this](const CandidateList&, const std::string&, std::span<const std::uint8_t>,
                      const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession&,
                      LibreSCRS::CancelToken) -> RawCryptoResult {
            ++opCalls;
            if (pin != nullptr) {
                ++verifyCalls;
                sawPin = !pin->empty();
                // Model the on-card VERIFY: a wrong PIN is AuthFailed, never the
                // op (mirrors verifyPinOnCard mapping InvalidPin -> AuthFailed).
                if (std::string{pin->view()} != cardPin) {
                    return RawCryptoResult{RawCryptoStatus::AuthFailed, {}};
                }
                channelVerified = true; // a successful verify arms the channel
            } else {
                sawNullPinOnce = true;
                if (dropChannelOnNextNullPinOp) {
                    dropChannelOnNextNullPinOp = false;
                    channelVerified = false; // idle-close dropped the held channel
                }
                if (!channelVerified) {
                    // Fresh/unverified channel + no PIN: the on-card PSO fails
                    // security-status, which LM folds to CardError (NOT AuthFailed).
                    return RawCryptoResult{RawCryptoStatus::CardError, {}};
                }
            }
            return opResult;
        };
    }

    RawCryptoFlow make()
    {
        holder = makeHolder(failWith, candidates);
        return RawCryptoFlow{RawCryptoFlowDeps{
            .holder = *holder,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .requester = "test-client",
            .certId = "abc123",
            .signOp = op(),
            .decryptOp = op(),
            .token = source.token(),
            .isPinVerified = [this]() { return pinVerified; },
            .markPinVerified = [this]() { pinVerified = true; },
            .clearPinVerified = [this]() { pinVerified = false; },
        }};
    }
};

constexpr auto kAwaiting = static_cast<std::uint32_t>(OperationPhase::AwaitingConsent);
constexpr auto kSigning = static_cast<std::uint32_t>(OperationPhase::Signing);

bool contains(const std::vector<std::uint32_t>& v, std::uint32_t p)
{
    for (const auto x : v) {
        if (x == p) {
            return true;
        }
    }
    return false;
}

const std::vector<std::uint8_t> kInput{0x01, 0x02, 0x03, 0x04};

} // namespace

TEST(RawCryptoFlow, SignSuccessReturnsBytes)
{
    Harness h;
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(r.bytes, (std::vector<std::uint8_t>{'S', 'I', 'G'}));
    auto acq = h.holder->acquire();
    ASSERT_TRUE(acq.has_value());
    EXPECT_TRUE(acq->session->hasCredentialProvider())
        << "the flow installs its provider on the held session (reset to a stateless no-op on exit) so the "
           "holder-owned session never re-invokes the dangling flow-scoped lambda";
    EXPECT_EQ(h.opCalls, 1);
}

TEST(RawCryptoFlow, PinIsCollectedViaThePrompterAndVerifiedOnTheRealPath)
{
    // The PIN-as-consent flow must collect the signing PIN from the agent
    // prompter (uncached, never off the wire) and hand it to the terminal op,
    // which verifies it on-card BEFORE the PSO. This drives the REAL verify->op
    // path (the op only succeeds because it received the right PIN), not a fake
    // that re-reads the provider.
    Harness h;
    h.cardPin = "1234"; // matches FakePrompter's default
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1) << "the PIN came from the agent prompter";
    EXPECT_EQ(h.verifyCalls, 1) << "the terminal op received the PIN to verify on the first op";
    EXPECT_TRUE(h.sawPin);
    EXPECT_TRUE(contains(h.phaseSink.phases, kAwaiting));
    EXPECT_TRUE(contains(h.phaseSink.phases, kSigning));
}

TEST(RawCryptoFlow, WrongPinFromTheCardMapsAuthFailed)
{
    // The prompter returns a PIN the modeled card rejects: the op's verify step
    // returns AuthFailed, which must surface as AuthFailed (the host revokes the
    // lease + the next op re-prompts).
    Harness h;
    h.cardPin = "9999"; // prompter returns "1234" -> mismatch
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::AuthFailed);
    EXPECT_EQ(h.verifyCalls, 1) << "the verify ran on the real path";
    EXPECT_FALSE(h.pinVerified) << "a failed verify must NOT mark the lease verified";
}

TEST(RawCryptoFlow, FirstOpVerifiesThenSubsequentOpsSkipTheReprompt)
{
    // First op of a lease: prompt + verify, mark verified (which arms the modeled
    // on-card channel). Second op: skip the prompt (isPinVerified() true) and run
    // with a null PIN against the STILL-verified channel -> success. The PIN is
    // NEVER cached — only the boolean is. The fake op models the held channel's
    // verified state (a null-PIN op succeeds only because the channel stayed
    // verified), not a fake that ignores session state.
    Harness h;
    h.cardPin = "1234";
    auto flow1 = h.make();
    EXPECT_EQ(flow1.runSign(kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_EQ(h.verifyCalls, 1);
    EXPECT_TRUE(h.pinVerified) << "a successful verify+op marks the lease verified";
    EXPECT_TRUE(h.channelVerified) << "the verify armed the held channel";

    auto flow2 = h.make(); // new flow object, SAME lease state (pinVerified true)
    EXPECT_EQ(flow2.runSign(kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1) << "no re-prompt on a verified lease";
    EXPECT_EQ(h.verifyCalls, 1) << "no re-verify on a verified lease";
    EXPECT_TRUE(h.sawNullPinOnce) << "the subsequent op ran with a null (already-verified) PIN";
}

TEST(RawCryptoFlow, RecoversWhenTheHeldChannelDropsUnderAVerifiedLease)
{
    // The desync wedge + recovery: the lease idle-timeout (10 min) is much
    // longer than the holder's idle-close (45s), so a held channel can be silently
    // dropped + reacquired FRESH (unverified) while the lease boolean still says
    // pinVerified. The next op skips the verify (null PIN), the fresh channel's
    // on-card PSO fails security-status -> LM folds it to CardError (NOT
    // AuthFailed). Without recovery this wedges forever (the lease stays verified,
    // the host revokes only on AuthFailed). The flow must instead treat a
    // CardError on a verify-SKIPPED op as verify-state-loss: clear the lease,
    // re-prompt, re-verify, retry ONCE -> success.
    Harness h;
    h.cardPin = "1234";

    // First op: prompt + verify + mark verified (arms the channel + the lease).
    EXPECT_EQ(h.make().runSign(kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_TRUE(h.pinVerified);
    EXPECT_TRUE(h.channelVerified);

    // The holder idle-closes between ops: the NEXT null-PIN op sees a fresh,
    // unverified channel. The lease boolean is STILL true (the wedge condition).
    h.dropChannelOnNextNullPinOp = true;

    // Second op: skips the verify (lease still verified), the dropped channel
    // CardErrors, the flow recovers by re-prompting + re-verifying + retrying once.
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok) << "the flow recovered from the dropped channel";
    EXPECT_EQ(r.bytes, (std::vector<std::uint8_t>{'S', 'I', 'G'}));
    EXPECT_EQ(h.prompter.pinCalls, 2) << "recovery raised exactly one fresh PIN prompt";
    EXPECT_GE(h.verifyCalls, 2) << "the retry re-verified the PIN on-card";
    EXPECT_TRUE(h.pinVerified) << "the successful retry re-marks the lease verified";
}

TEST(RawCryptoFlow, RecoveryRetryThatStillFailsSurfacesTheError)
{
    // If the recovery retry (now with a real verify) STILL CardErrors, the flow
    // must surface CardError — never loop. Model a channel that stays dropped:
    // the first null-PIN op CardErrors (dropped), and even the re-verified retry
    // hits a card that fails the op (channel never re-arms). Exactly one extra
    // prompt at worst, then the error is surfaced.
    Harness h;
    h.cardPin = "1234";
    // Prime a verified lease (no on-card op yet — set the lease boolean directly).
    h.pinVerified = true;
    h.channelVerified = false;                                    // channel already dropped (idle-close)
    h.opResult = RawCryptoResult{RawCryptoStatus::CardError, {}}; // a card that keeps failing

    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.prompter.pinCalls, 1) << "exactly one recovery prompt, then give up";
    EXPECT_FALSE(h.pinVerified) << "the lease was cleared on the verify-state-loss path";
}

TEST(RawCryptoFlow, DecryptRoutesToDecryptOp)
{
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::Ok, {'P', 'T'}};
    auto r = h.make().runDecrypt(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(r.bytes, (std::vector<std::uint8_t>{'P', 'T'}));
    EXPECT_EQ(h.verifyCalls, 1) << "decrypt also verifies the PIN on the real path";
}

TEST(RawCryptoFlow, KeyNotFoundMaps)
{
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::KeyNotFound, {}};
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::KeyNotFound);
}

TEST(RawCryptoFlow, NotSupportedMaps)
{
    // The NAM-sign / NAM-decrypt degraded path: the resolving plugin has no raw
    // primitive -> NotSupported -> the host returns CKR_FUNCTION_NOT_SUPPORTED.
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::NotSupported, {}};
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::NotSupported);
}

TEST(RawCryptoFlow, CardErrorMaps)
{
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::CardError, {}};
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
}

TEST(RawCryptoFlow, PrompterCancelMapsCancelled)
{
    // The user declines the PIN prompt. The flow detects PromptStatus::Cancelled
    // BEFORE the terminal op and remaps to Cancelled (a user-declined consent is
    // never a card fault). The op never runs.
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Cancelled);
    EXPECT_EQ(h.opCalls, 0) << "no card op attempted when consent was declined";
}

TEST(RawCryptoFlow, PrompterErrorMapsCardError)
{
    // The prompter UI broke (Error, no secret): no PIN to verify, surface
    // CardError, never reach the card op.
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Error, std::nullopt, "prompter gone"};
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.opCalls, 0);
}

TEST(RawCryptoFlow, OpenFailedMapsCardError)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}};
    auto r = h.make().runSign(kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.opCalls, 0) << "no card op attempted when the session never opened";
}
