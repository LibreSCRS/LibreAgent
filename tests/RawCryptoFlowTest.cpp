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
#include <functional>
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
                                                     CandidateList candidates = {}, std::function<void()> onOpen = {})
{
    auto factory = [failWith = std::move(failWith), onOpen = std::move(onOpen)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (onOpen) {
            onOpen();
        }
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
    std::function<void()> onPin; // runs while the human is "typing"
    PromptResult requestPin(const PromptOptions&) override
    {
        ++pinCalls;
        if (onPin) {
            onPin();
        }
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

    // Injected terminal raw-crypto op. Models the PRODUCTION path: it receives
    // the PIN the flow collected from the prompter (non-null on the first op
    // of a lease and for a key the card marks, null once verified) and models
    // a card that checks the PIN inside the operation — LmRawCrypto::signRaw
    // deposits it with the plugin, which presents it in the same card
    // transaction as the PSO. This pins the consent contract to the real flow
    // path, not to a fake that re-reads the provider.
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

    // The card marks this key for consent per operation: a null-PIN op is
    // answered ConsentRequired without using the key, as LmRawCrypto does.
    bool keyAlwaysAuthenticates = false;
    // The host's prompt gate (the broker's per-caller limiter in production).
    bool promptAllowed = true;
    int allowPromptCalls = 0;
    bool wireGate = true; // false: the host hands the flow no prompt gate at all
    int sessionOpens = 0; // card-session opens the holder's factory served
    // The injected preflight: resolves a key (or refuses) the way
    // LmRawCrypto::preflight does, before any prompt.
    RawCryptoStatus preflightStatus = RawCryptoStatus::Ok;
    int preflightCalls = 0;
    std::optional<Mechanism> preflightMechanism;
    std::optional<Mechanism> opMechanism;
    bool wirePreflight = true; // false: the host hands the flow no preflight at all
    // The key file each operation was handed. Each preflight resolves a key of
    // its own (file 1, 2, ...), so a test can tell which resolution reached it.
    std::vector<std::uint16_t> opKeyFIDs;

    RawCryptoPreflightOp preflightOp()
    {
        return [this](const CandidateList&, const std::string&, Mechanism m, std::span<const std::uint8_t>,
                      LibreSCRS::SmartCard::CardSession&) -> RawCryptoPreflight {
            ++preflightCalls;
            preflightMechanism = m;
            if (preflightStatus != RawCryptoStatus::Ok) {
                return RawCryptoPreflight{.status = preflightStatus, .key = std::nullopt};
            }
            LibreSCRS::Plugin::CertificateData cd;
            cd.keyFID = static_cast<std::uint16_t>(preflightCalls);
            return RawCryptoPreflight{.status = RawCryptoStatus::Ok,
                                      .key = SigningSelection{.plugin = nullptr, .cert = std::move(cd)}};
        };
    }

    RawCryptoOp op()
    {
        return [this](const SigningSelection& key, Mechanism m, std::span<const std::uint8_t>,
                      const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession&,
                      LibreSCRS::CancelToken) -> RawCryptoResult {
            opMechanism = m;
            opKeyFIDs.push_back(key.cert.keyFID.value_or(0));
            ++opCalls;
            if (keyAlwaysAuthenticates && pin == nullptr) {
                return RawCryptoResult{RawCryptoStatus::ConsentRequired, {}, true};
            }
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
            RawCryptoResult r = opResult;
            r.alwaysAuthenticate = keyAlwaysAuthenticates;
            return r;
        };
    }

    RawCryptoFlow make()
    {
        holder = makeHolder(failWith, candidates, [this] { ++sessionOpens; });
        return RawCryptoFlow{RawCryptoFlowDeps{
            .holder = *holder,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .requester = "test-client",
            .certId = "abc123",
            .preflight = wirePreflight ? preflightOp() : RawCryptoPreflightOp{},
            .signOp = op(),
            .decryptOp = op(),
            .token = source.token(),
            .isPinVerified = [this]() { return pinVerified; },
            .markPinVerified = [this]() { pinVerified = true; },
            .clearPinVerified = [this]() { pinVerified = false; },
            .allowPrompt = wireGate ? std::function<bool()>{[this]() {
                ++allowPromptCalls;
                return promptAllowed;
            }}
                                    : std::function<bool()>{},
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
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
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
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
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
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
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
    EXPECT_EQ(flow1.runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_EQ(h.verifyCalls, 1);
    EXPECT_TRUE(h.pinVerified) << "a successful verify+op marks the lease verified";
    EXPECT_TRUE(h.channelVerified) << "the verify armed the held channel";

    auto flow2 = h.make(); // new flow object, SAME lease state (pinVerified true)
    EXPECT_EQ(flow2.runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
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
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_TRUE(h.pinVerified);
    EXPECT_TRUE(h.channelVerified);

    // The holder idle-closes between ops: the NEXT null-PIN op sees a fresh,
    // unverified channel. The lease boolean is STILL true (the wedge condition).
    h.dropChannelOnNextNullPinOp = true;

    // Second op: skips the verify (lease still verified), the dropped channel
    // CardErrors, the flow recovers by re-prompting + re-verifying + retrying once.
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
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

    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.prompter.pinCalls, 1) << "exactly one recovery prompt, then give up";
    EXPECT_FALSE(h.pinVerified) << "the lease was cleared on the verify-state-loss path";
}

TEST(RawCryptoFlow, AKeyTheCardMarksAsksForThePinOnEverySignature)
{
    // The card wants the PIN before every use of this key. The first signature
    // presents it and must NOT warm the lease; the second asks again.
    Harness h;
    h.keyAlwaysAuthenticates = true;
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_FALSE(h.pinVerified) << "a per-operation key must not mark the lease verified";
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 2) << "two signatures, two prompts";
    EXPECT_EQ(h.verifyCalls, 2);
}

TEST(RawCryptoFlow, AKeyTheCardMarksAsksEvenUnderAWarmLease)
{
    // Another key of the card warmed the lease. The marked key still asks, and
    // the lease stays warm for the others: nothing about it was wrong.
    Harness h;
    h.pinVerified = true;
    h.channelVerified = true;
    h.keyAlwaysAuthenticates = true;
    const auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_EQ(h.verifyCalls, 1) << "the retry carried this operation's PIN";
    EXPECT_TRUE(h.pinVerified) << "consent for one key is not a lost channel";
}

TEST(RawCryptoFlow, AMarkedKeyNeverReArmsALeaseResetDuringItsConsent)
{
    // The lease is reset while the human sits in the marked key's consent
    // prompt (a re-grant, a context-specific login). The marked key's
    // successful retry must not arm it again: the next ordinary-key op would
    // otherwise run with no prompt after an explicit reset.
    Harness h;
    h.pinVerified = true;
    h.channelVerified = true;
    h.keyAlwaysAuthenticates = true;
    h.prompter.onPin = [&h] { h.pinVerified = false; };
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    EXPECT_FALSE(h.pinVerified) << "a marked key never arms the lease, not even on the retry";
}

TEST(RawCryptoFlow, EveryPromptAsksTheHostFirst)
{
    // Charged per prompt, wherever it is raised.
    Harness marked; // a marked key under a warm lease prompts
    marked.pinVerified = true;
    marked.channelVerified = true;
    marked.keyAlwaysAuthenticates = true;
    EXPECT_EQ(marked.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(marked.allowPromptCalls, 1);

    Harness ordinary; // an ordinary key under the same lease prompts for nothing
    ordinary.pinVerified = true;
    ordinary.channelVerified = true;
    EXPECT_EQ(ordinary.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(ordinary.allowPromptCalls, 0);

    Harness lost; // the recovery re-prompt is a prompt too
    lost.pinVerified = true;
    lost.channelVerified = false;
    EXPECT_EQ(lost.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(lost.allowPromptCalls, 1);

    Harness cold; // and so is the first prompt of a lease
    EXPECT_EQ(cold.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(cold.allowPromptCalls, 1);
}

TEST(RawCryptoFlow, ARefusedPromptRaisesNothingAndSaysRateLimited)
{
    Harness h;
    h.promptAllowed = false;
    const auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::RateLimited);
    EXPECT_EQ(h.prompter.pinCalls, 0) << "a refused prompt is never shown";
    EXPECT_EQ(h.opCalls, 0) << "and the card is never touched";
    EXPECT_EQ(h.sessionOpens, 0) << "a refused cold prompt does not even open the card session";
    EXPECT_EQ(h.preflightCalls, 0) << "a caller over its budget is not even checked against the key";

    // A refused re-prompt under a warm lease: the marked key is never used.
    Harness warm;
    warm.pinVerified = true;
    warm.channelVerified = true;
    warm.keyAlwaysAuthenticates = true;
    warm.promptAllowed = false;
    EXPECT_EQ(warm.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::RateLimited);
    EXPECT_EQ(warm.prompter.pinCalls, 0);
    EXPECT_EQ(warm.verifyCalls, 0) << "no PIN reached the card";
}

TEST(RawCryptoFlow, AFlowHandedNoPromptGateRaisesNoPrompt)
{
    // A host that forgets to wire its per-caller budget must not get free
    // prompts: no gate is a refusal, never an unlimited budget.
    Harness h;
    h.wireGate = false;
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::RateLimited);
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_EQ(h.sessionOpens, 0);
    EXPECT_EQ(h.preflightCalls, 0) << "a caller over its budget is not even checked against the key";

    Harness warm; // the re-prompt for a marked key is refused the same way
    warm.wireGate = false;
    warm.pinVerified = true;
    warm.channelVerified = true;
    warm.keyAlwaysAuthenticates = true;
    EXPECT_EQ(warm.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::RateLimited);
    EXPECT_EQ(warm.prompter.pinCalls, 0);
    EXPECT_EQ(warm.verifyCalls, 0);
}

TEST(RawCryptoFlow, AnEmptyPinIsADismissedPromptNotAPin)
{
    // A prompter that answers Ok with nothing typed. An empty PIN handed to the
    // plugin erases its deposit, and the card would then run the operation on
    // whatever state the held session already carries. It must stop here, as a
    // dismissed prompt does: nothing reaches the card, the lease stays cold, and
    // the one prompt it cost is charged once.
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{}, ""};
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Cancelled);
    EXPECT_EQ(h.opCalls, 0) << "no operation without a PIN";
    EXPECT_FALSE(h.pinVerified) << "an empty answer never warms the lease";
    EXPECT_EQ(h.allowPromptCalls, 1);
    EXPECT_FALSE(contains(h.phaseSink.phases, kSigning));

    // A marked key under a warm lease: the consent re-prompt answered empty.
    Harness warm;
    warm.pinVerified = true;
    warm.channelVerified = true;
    warm.keyAlwaysAuthenticates = true;
    warm.prompter.pinResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{}, ""};
    EXPECT_EQ(warm.make().runDecrypt(Mechanism::RsaPkcs1Decrypt, kInput).outcome, RawCryptoFlow::Outcome::Cancelled);
    EXPECT_EQ(warm.opCalls, 1) << "only the PIN-less probe that asked for consent";
    EXPECT_EQ(warm.verifyCalls, 0) << "no PIN, empty or not, reached the card";
    EXPECT_EQ(warm.allowPromptCalls, 1);
}

TEST(RawCryptoFlow, AMarkedKeyThenAnOrdinaryKeyCostsAtMostOnePrompt)
{
    // A hash-on-card plugin holds no PIN after a marked key's operation. The
    // ordinary key's next op under the warm lease then fails on the card, and
    // the recovery asks once: one extra prompt, never a failed signature.
    Harness h;
    ASSERT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome,
              RawCryptoFlow::Outcome::Ok); // ordinary key: prompt, lease warm
    ASSERT_TRUE(h.pinVerified);
    h.keyAlwaysAuthenticates = true;
    ASSERT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome,
              RawCryptoFlow::Outcome::Ok); // marked key: its own prompt
    h.keyAlwaysAuthenticates = false;
    h.dropChannelOnNextNullPinOp = true; // the erased deposit, as the card sees it
    const auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.pinCalls, 3) << "first, marked, and exactly one recovery";
    EXPECT_TRUE(h.pinVerified) << "the recovered ordinary key re-arms the lease";
}

TEST(RawCryptoFlow, DecryptRoutesToDecryptOp)
{
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::Ok, {'P', 'T'}};
    auto r = h.make().runDecrypt(Mechanism::RsaPkcs1Decrypt, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(r.bytes, (std::vector<std::uint8_t>{'P', 'T'}));
    EXPECT_EQ(h.verifyCalls, 1) << "decrypt also verifies the PIN on the real path";
}

TEST(RawCryptoFlow, KeyNotFoundMaps)
{
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::KeyNotFound, {}};
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::KeyNotFound);
}

TEST(RawCryptoFlow, NotSupportedMaps)
{
    // The NAM-sign / NAM-decrypt degraded path: the resolving plugin has no raw
    // primitive -> NotSupported -> the host returns CKR_FUNCTION_NOT_SUPPORTED.
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::NotSupported, {}};
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::NotSupported);
}

TEST(RawCryptoFlow, CardErrorMaps)
{
    Harness h;
    h.cardPin = "1234";
    h.opResult = RawCryptoResult{RawCryptoStatus::CardError, {}};
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
}

TEST(RawCryptoFlow, PrompterCancelMapsCancelled)
{
    // The user declines the PIN prompt. The flow detects PromptStatus::Cancelled
    // BEFORE the terminal op and remaps to Cancelled (a user-declined consent is
    // never a card fault). The op never runs.
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::Cancelled);
    EXPECT_EQ(h.opCalls, 0) << "no card op attempted when consent was declined";
}

TEST(RawCryptoFlow, PrompterErrorMapsCardError)
{
    // The prompter UI broke (Error, no secret): no PIN to verify, surface
    // CardError, never reach the card op.
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Error, std::nullopt, "prompter gone"};
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.opCalls, 0);
}

TEST(RawCryptoFlow, OpenFailedMapsCardError)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}};
    auto r = h.make().runSign(Mechanism::RsaPkcs1Sign, kInput);
    EXPECT_EQ(r.outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.opCalls, 0) << "no card op attempted when the session never opened";
}

// A request the key refuses (wrong family, wrong length, a point off the
// curve) never asks for a PIN and never reaches the key. A cold lease was
// charged its prompt when the request arrived, before the card session was
// opened; a verified lease stays verified.
TEST(RawCryptoFlow, ARequestTheKeyRefusesRaisesNoPinPrompt)
{
    Harness cold;
    cold.preflightStatus = RawCryptoStatus::InvalidInput;
    EXPECT_EQ(cold.make().runSign(Mechanism::EcdsaSign, kInput).outcome, RawCryptoFlow::Outcome::InvalidInput);
    EXPECT_EQ(cold.allowPromptCalls, 1) << "the cold prompt is charged on entry, before the session opens";
    EXPECT_EQ(cold.sessionOpens, 1);
    EXPECT_EQ(cold.preflightCalls, 1);
    EXPECT_EQ(cold.prompter.pinCalls, 0) << "no PIN prompt for a request the key refuses";
    EXPECT_EQ(cold.opCalls, 0);

    Harness warm;
    warm.pinVerified = true;
    warm.channelVerified = true;
    warm.preflightStatus = RawCryptoStatus::InvalidInput;
    EXPECT_EQ(warm.make().runSign(Mechanism::EcdsaSign, kInput).outcome, RawCryptoFlow::Outcome::InvalidInput);
    EXPECT_EQ(warm.prompter.pinCalls, 0);
    EXPECT_EQ(warm.allowPromptCalls, 0) << "a verified lease is never charged";
    EXPECT_TRUE(warm.pinVerified) << "a refusal before the card never resets the lease";
}

// KeyNotFound and NotSupported decided before the prompt ask for nothing either.
TEST(RawCryptoFlow, ARefusalFromThePreflightAsksForNothing)
{
    for (const auto s : {RawCryptoStatus::KeyNotFound, RawCryptoStatus::NotSupported}) {
        Harness h;
        h.preflightStatus = s;
        const auto r = h.make().runDecrypt(Mechanism::RsaPkcs1Decrypt, kInput);
        EXPECT_NE(r.outcome, RawCryptoFlow::Outcome::Ok);
        EXPECT_EQ(h.prompter.pinCalls, 0);
        EXPECT_EQ(h.opCalls, 0);
    }
}

// The mechanism the caller named reaches both the check and the operation.
TEST(RawCryptoFlow, TheMechanismReachesThePreflightAndTheOperation)
{
    Harness h;
    EXPECT_EQ(h.make().runSign(Mechanism::EcdsaSign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.preflightMechanism, Mechanism::EcdsaSign);
    EXPECT_EQ(h.opMechanism, Mechanism::EcdsaSign);
}

// After a dropped channel the key is resolved again on the fresh one; a
// consent re-prompt for a marked key reuses the key already resolved.
TEST(RawCryptoFlow, ARecoveryRetryResolvesTheKeyAgain)
{
    Harness lost;
    lost.pinVerified = true;
    lost.channelVerified = true;
    lost.dropChannelOnNextNullPinOp = true;
    EXPECT_EQ(lost.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(lost.preflightCalls, 2);

    Harness marked;
    marked.pinVerified = true;
    marked.channelVerified = true;
    marked.keyAlwaysAuthenticates = true;
    EXPECT_EQ(marked.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(marked.preflightCalls, 1);
}

// The operation runs with exactly the key the preflight resolved -- on a
// recovery retry, the one resolved again on the fresh channel, not the first.
TEST(RawCryptoFlow, TheOperationUsesTheKeyThePreflightResolved)
{
    Harness h;
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(h.opKeyFIDs, (std::vector<std::uint16_t>{1}));

    Harness lost;
    lost.pinVerified = true;
    lost.channelVerified = true;
    lost.dropChannelOnNextNullPinOp = true;
    EXPECT_EQ(lost.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::Ok);
    EXPECT_EQ(lost.opKeyFIDs, (std::vector<std::uint16_t>{1, 2}));
}

// A flow handed no preflight refuses as a card error before any prompt and
// before the key is used.
TEST(RawCryptoFlow, AFlowHandedNoPreflightRefusesBeforeAnyPrompt)
{
    Harness h;
    h.wirePreflight = false;
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::CardError);
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_EQ(h.opCalls, 0);
}

// The operation's own InvalidInput (a mechanism the terminal cannot map) is
// surfaced, never read as a dropped channel.
TEST(RawCryptoFlow, AnInvalidInputFromTheOperationIsNotAChannelLoss)
{
    Harness h;
    h.pinVerified = true;
    h.channelVerified = true;
    h.opResult = RawCryptoResult{RawCryptoStatus::InvalidInput, {}};
    EXPECT_EQ(h.make().runSign(Mechanism::RsaPkcs1Sign, kInput).outcome, RawCryptoFlow::Outcome::InvalidInput);
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_TRUE(h.pinVerified);
}
