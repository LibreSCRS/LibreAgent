// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic test of CredentialCache::requestCredential using a Fake
// PrompterClient (the prompter interface is exercised by the existing
// PrompterIntegrationTest — here we focus on cache-vs-prompt routing).
//
// The cache routes off the AuthRequirement's paceKind(): the plugin's
// self-activation path hands the credential provider an EstablishPaceChannel
// requirement carrying the secret kind (CAN / MRZ) the card needs.

#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/operations/PromptPolicy.h> // kMaxPaceAttempts

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <gtest/gtest.h>
#include <atomic>
#include <optional>
#include <string_view>
#include <utility>

using LibreSCRS::Agent::CredentialCache;
using LibreSCRS::Agent::MrzChoiceSink;
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::Operations::kMaxPaceAttempts;
using LibreSCRS::Auth::AuthRequirement;
using LibreSCRS::Auth::CredentialResult;
using LibreSCRS::Auth::PaceSecretKind;
using LibreSCRS::Secure::String;

namespace {

// Test seam: the production PrompterClient is a concrete class. The
// CredentialCache helper takes a PrompterClient& by reference, so we
// derive a fake from a tiny duck-typed surface.

struct FakePrompter
{
    PromptResult canResult = PromptResult{PromptStatus::Error, std::nullopt, "uninitialised"};
    PromptResult mrzResult = PromptResult{PromptStatus::Error, std::nullopt, "uninitialised"};
    int canCalls = 0;
    int mrzCalls = 0;
    // The options CredentialCache actually handed to the most recent
    // requestCan/requestMrz call -- lets retry-context tests observe
    // attempt/lastError without a real D-Bus round trip.
    PromptOptions lastCanOptions;
    PromptOptions lastMrzOptions;

    PromptResult requestCan(const PromptOptions& options)
    {
        ++canCalls;
        lastCanOptions = options;
        return canResult;
    }
    PromptResult requestMrz(const PromptOptions& options)
    {
        ++mrzCalls;
        lastMrzOptions = options;
        return mrzResult;
    }
};

// Build an EstablishPaceChannel requirement for the given secret kind, the
// shape LM hands the credential provider during plugin self-activation.
AuthRequirement paceReq(PaceSecretKind kind)
{
    return AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{}, kind, std::nullopt,
                                          LibreSCRS::LocalizedText{});
}

} // namespace

TEST(CredentialCacheRequest, CanCacheHitDoesNotPrompt)
{
    CredentialCache cache;
    cache.putCan("card-A", String{"123456"});
    FakePrompter prompter;
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_NE(result.find("can"), nullptr);
    EXPECT_EQ(prompter.canCalls, 0) << "cache hit must not prompt";
}

TEST(CredentialCacheRequest, CanCacheMissPromptsAndStores)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_NE(result.find("can"), nullptr);
    EXPECT_EQ(prompter.canCalls, 1);
    EXPECT_TRUE(cache.hasCan("card-A")) << "prompt result must populate the cache";

    // Second call hits cache, does not re-prompt.
    auto again = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(again.status, CredentialResult::Status::Ok);
    EXPECT_EQ(prompter.canCalls, 1);
}

TEST(CredentialCacheRequest, MrzCacheMissPromptsAndStores)
{
    CredentialCache cache;
    FakePrompter prompter;
    // A conforming 3-line MRZ payload (the TD3 specimen): the adapter now
    // VERIFIES the payload, so this must be well-formed to store. The union
    // shape is asserted in MrzPromptYieldsUnionEntries; here we pin the
    // miss->prompt->store routing.
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{"L898902C36\n7408122\n1204159"}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_NE(result.find("mrz"), nullptr);
    EXPECT_EQ(prompter.mrzCalls, 1);
    EXPECT_TRUE(cache.hasMrz("card-A"));
}

TEST(CredentialCacheRequest, PrompterCancelledMapsToUserCancelled)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::UserCancelled);
    EXPECT_FALSE(cache.hasCan("card-A")) << "cancelled prompt must not populate the cache";
}

TEST(CredentialCacheRequest, PrompterErrorMapsToError)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Error, std::nullopt, "memfd read failed"};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_FALSE(cache.hasCan("card-A"));
}

// A cancelled CAN prompt must raise the userCancelled flag — and ONLY that
// flag: a cancel is not a prompter failure, so prompterFailed stays false. The
// flag is the list flow's only signal that an empty seam result was really a
// user-dismissed prompt (the LM seam swallows the candidate throw).
TEST(CredentialCacheRequest, CancelledCanPromptSetsUserCancelledFlagOnly)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          &userCancelled);
    EXPECT_EQ(result.status, CredentialResult::Status::UserCancelled);
    EXPECT_TRUE(userCancelled.load()) << "a cancelled prompt must raise the cancel signal";
    EXPECT_FALSE(prompterFailed.load()) << "a cancel is not a prompter failure";
}

TEST(CredentialCacheRequest, CancelledMrzPromptSetsUserCancelledFlagOnly)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts, &prompterFailed,
                                          &userCancelled);
    EXPECT_EQ(result.status, CredentialResult::Status::UserCancelled);
    EXPECT_TRUE(userCancelled.load());
    EXPECT_FALSE(prompterFailed.load());
}

// The complementary rule: a broken prompter raises prompterFailed and must NOT
// masquerade as a user cancel.
TEST(CredentialCacheRequest, PrompterErrorSetsPrompterFailedFlagOnly)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Error, std::nullopt, "prompter gone"};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          &userCancelled);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_TRUE(prompterFailed.load());
    EXPECT_FALSE(userCancelled.load()) << "a prompter failure is not a user cancel";
}

// The third signal, and the one this taxonomy was short of: the window closed
// because the holder's entry time ran out. Nobody cancelled and no prompter
// broke, so BOTH sibling flags must stay down — a test that only checked the
// new flag would pass with all three raised, which is the failure that would
// put "you cancelled" in front of someone who did not.
TEST(CredentialCacheRequest, ExpiredCanPromptSetsEntryExpiredFlagOnly)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, ""};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    std::atomic<bool> entryExpired{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          &userCancelled, /*mrzChoice=*/nullptr, &entryExpired);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_TRUE(entryExpired.load()) << "an expired entry window must raise the clock signal";
    EXPECT_FALSE(userCancelled.load()) << "the clock took it; the holder did not cancel";
    EXPECT_FALSE(prompterFailed.load()) << "the prompter answered; it did not break";
    EXPECT_FALSE(cache.hasCan("card-A")) << "an expired prompt must not populate the cache";
}

TEST(CredentialCacheRequest, ExpiredMrzPromptSetsEntryExpiredFlagOnly)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Timeout, std::nullopt, ""};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    std::atomic<bool> entryExpired{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts, &prompterFailed,
                                          &userCancelled, /*mrzChoice=*/nullptr, &entryExpired);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_TRUE(entryExpired.load());
    EXPECT_FALSE(userCancelled.load());
    EXPECT_FALSE(prompterFailed.load());
}

// The inverse, so the flag cannot be one that is simply always raised: a
// prompter that broke must NOT read as an expiry.
TEST(CredentialCacheRequest, PrompterErrorDoesNotRaiseEntryExpired)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Error, std::nullopt, "prompter gone"};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> entryExpired{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          /*userCancelled=*/nullptr, /*mrzChoice=*/nullptr, &entryExpired);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_TRUE(prompterFailed.load());
    EXPECT_FALSE(entryExpired.load()) << "a broken prompter is not an expired window";
}

// The fourth signal: the agent REFUSED to raise the prompt because the helper
// cannot be told which window to dismiss. Distinct from all three siblings —
// nothing was shown, so nothing was cancelled, nothing expired, and the helper
// did not break. Reporting it as a prompter failure would describe a broken
// helper when it is running fine, and would cost the holder the one remedy
// they can act on.
TEST(CredentialCacheRequest, RefusedPromptSetsHelperTooOldFlagOnly)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::HelperTooOld, std::nullopt, "helper out of date"};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    std::atomic<bool> entryExpired{false};
    std::atomic<bool> helperTooOld{false};
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          &userCancelled, /*mrzChoice=*/nullptr, &entryExpired, &helperTooOld);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_TRUE(helperTooOld.load()) << "a refusal must raise the capability signal";
    EXPECT_FALSE(prompterFailed.load()) << "the helper is running; it did not break";
    EXPECT_FALSE(entryExpired.load()) << "no window was shown, so no clock ran out";
    EXPECT_FALSE(userCancelled.load()) << "no window was shown, so nobody cancelled";
    EXPECT_FALSE(cache.hasCan("card-A"));
}

// The signal has to outlive the RUN that produced it. The first attempt raises
// a window, it expires, and that flow ends; the middleware's re-request arrives
// inside the NEXT flow, carrying the same rejection reason a genuinely wrong
// secret carries. A per-run flag reads false there and the caller marks a value
// nobody ever supplied -- which burns a PACE attempt and puts "the value you
// entered was not accepted" in front of a holder who entered nothing. Measured
// on a live agent: the first fix was per-run and the second dialog still said
// it.
TEST(CredentialCacheRequest, AnExpiryIsRememberedPerCardNotPerRun)
{
    CredentialCache cache;
    FakePrompter prompter;
    PromptOptions opts;

    EXPECT_FALSE(cache.lastPromptYieldedNothingFor("card-A")) << "a card with no history has nothing to remember";

    prompter.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, ""};
    EXPECT_EQ(cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts).status,
              CredentialResult::Status::Error);

    // The run is over; this is what the NEXT one must be able to see.
    EXPECT_TRUE(cache.lastPromptYieldedNothingFor("card-A"));
    EXPECT_FALSE(cache.lastPromptYieldedNothingFor("card-B")) << "remembered per card, not globally";

    // A prompt that answers clears it, so a wrong value entered after an expiry
    // is still marked wrong.
    prompter.canResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    EXPECT_EQ(cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts).status,
              CredentialResult::Status::Ok);
    EXPECT_FALSE(cache.lastPromptYieldedNothingFor("card-A"));
}

// An expiry must not cost a PACE attempt: three of them would otherwise leave
// the card unable to be asked at all, and the cap refuses to ASK, never to
// answer -- so the failure surfaces far from its cause.
TEST(CredentialCacheRequest, AnExpiryCostsNoAttempt)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, ""};
    PromptOptions opts;
    for (int i = 0; i < 3; ++i) {
        static_cast<void>(cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts));
    }
    // Asserted through behaviour rather than the private counter: the cap
    // refuses to ASK, so a card whose attempts were burned never reaches the
    // prompter again. This one still does.
    const int before = prompter.canCalls;
    prompter.canResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    EXPECT_EQ(cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts).status,
              CredentialResult::Status::Ok)
        << "three expiries must not exhaust the attempt cap";
    EXPECT_EQ(prompter.canCalls, before + 1) << "the fourth attempt was still allowed to ask";
}

TEST(CredentialCacheRequest, PinKindIsNeverCachedAndYieldsError)
{
    // PIN-as-PACE-password is never cached and never collected by the
    // pre-read flow: requestCredential routes it to an error without
    // touching the prompter.
    CredentialCache cache;
    FakePrompter prompter;
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Pin), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_EQ(prompter.canCalls, 0);
    EXPECT_EQ(prompter.mrzCalls, 0);
}

TEST(CredentialCacheRequest, AbsentPaceKindYieldsError)
{
    // A requirement without a paceKind (e.g. a signing requirement) is not a
    // pre-read secret request; the cache routes it to an error.
    CredentialCache cache;
    FakePrompter prompter;
    PromptOptions opts;
    auto signing = AuthRequirement::forSigning(LibreSCRS::LocalizedText{"", "PIN", {}}, std::nullopt);
    auto result = cache.requestCredential("card-A", signing, prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_EQ(prompter.canCalls, 0);
    EXPECT_EQ(prompter.mrzCalls, 0);
}

// -- Retry context (attempt / lastError) --------------------------------

TEST(CredentialCacheRequest, FirstEverCanPromptCarriesNoRetryContext)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 0u) << "the first-ever prompt for a card must carry no attempt count";
    EXPECT_TRUE(prompter.lastCanOptions.lastError.empty());
}

TEST(CredentialCacheRequest, CanRePromptAfterMarkCredentialWrongCarriesAttemptAndLastError)
{
    CredentialCache cache;
    cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");

    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);

    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 2u) << "one prior failure -> this is the second attempt";
    EXPECT_EQ(prompter.lastCanOptions.lastError, "librescrs.error.preRead.authFailed");
}

TEST(CredentialCacheRequest, MrzRePromptAfterMarkCredentialWrongCarriesAttemptAndLastError)
{
    CredentialCache cache;
    cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");

    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{"P<UTOERIKSSON<<ANNA<MARIA"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);

    ASSERT_EQ(prompter.mrzCalls, 1);
    EXPECT_EQ(prompter.lastMrzOptions.attempt, 2u);
    EXPECT_EQ(prompter.lastMrzOptions.lastError, "librescrs.error.preRead.authFailed");
}

TEST(CredentialCacheRequest, SecondConsecutiveFailureBumpsAttemptToThree)
{
    CredentialCache cache;
    cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");

    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);

    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 3u) << "two prior failures -> this is the third attempt";
}

TEST(CredentialCacheRequest, InvalidateAfterMarkCredentialWrongClearsRetryContext)
{
    // invalidate() (plain, full-entry erase) resets retry context too -- the
    // side-effect eviction path (a wrong signing PIN) must not leave a stale
    // "wrong CAN" claim attached to a later, unrelated prompt.
    CredentialCache cache;
    cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    cache.invalidate("card-A");

    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);

    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 0u)
        << "invalidate() must fully clear retry context, not just the secret";
    EXPECT_TRUE(prompter.lastCanOptions.lastError.empty());
}

TEST(CredentialCacheRequest, CacheHitAfterMarkCredentialWrongNeverReachesThePrompter)
{
    // A retry re-collecting a CORRECT secret is cached normally; a later,
    // unrelated cache HIT for the same card must not prompt at all (so no
    // question of retry context arises on that path).
    CredentialCache cache;
    cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    cache.putCan("card-A", String{"654321"}); // simulates a since-corrected, now-cached CAN

    FakePrompter prompter;
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    EXPECT_EQ(prompter.canCalls, 0) << "cache hit must not prompt regardless of recorded retry context";
}

// -- MRZ payload adaptation into the union credential entries (A1) -----------
//
// The prompter returns the canonical 3-line MRZ payload; requestCredential must
// deliver the UNION both LM activation branches consume: "mrz" (PACE) plus
// "documentNumber"/"dateOfBirth"/"dateOfExpiry" (BAC). The find() keys below
// are LITERALLY the LM consumption API (CardSession.cpp:876-886 / :779-781).

// The ICAO 9303 TD3 canonical specimen (UTO / ERIKSSON / L898902C3), the same
// MRZ the LM emrtd rig's DG1 fixture carries.
constexpr const char* kTd3MrzPayload = "L898902C36\n7408122\n1204159";

TEST(CredentialCacheRequest, MrzPromptYieldsUnionEntries)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);

    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    const auto* mrz = result.find("mrz");
    const auto* docNo = result.find("documentNumber");
    const auto* dob = result.find("dateOfBirth");
    const auto* doe = result.find("dateOfExpiry");
    ASSERT_NE(mrz, nullptr);
    ASSERT_NE(docNo, nullptr);
    ASSERT_NE(dob, nullptr);
    ASSERT_NE(doe, nullptr);
    EXPECT_EQ(mrz->view(), std::string_view{"L898902C3674081221204159"}); // MRZ_information (cds kept)
    EXPECT_EQ(docNo->view(), std::string_view{"L898902C3"});              // cd stripped
    EXPECT_EQ(dob->view(), std::string_view{"740812"});
    EXPECT_EQ(doe->view(), std::string_view{"120415"});
    EXPECT_TRUE(cache.hasMrz("card-A")) << "an accepted MRZ payload must populate the cache";
}

TEST(CredentialCacheRequest, MrzCacheHitYieldsSameUnionEntries)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);
    ASSERT_EQ(prompter.mrzCalls, 1);

    // Second call is a cache hit (no prompt) and must yield the identical union.
    auto again = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);
    EXPECT_EQ(prompter.mrzCalls, 1) << "cache hit must not re-prompt";
    EXPECT_EQ(again.status, CredentialResult::Status::Ok);
    ASSERT_NE(again.find("mrz"), nullptr);
    ASSERT_NE(again.find("documentNumber"), nullptr);
    ASSERT_NE(again.find("dateOfBirth"), nullptr);
    ASSERT_NE(again.find("dateOfExpiry"), nullptr);
    EXPECT_EQ(again.find("mrz")->view(), std::string_view{"L898902C3674081221204159"});
    EXPECT_EQ(again.find("documentNumber")->view(), std::string_view{"L898902C3"});
    EXPECT_EQ(again.find("dateOfBirth")->view(), std::string_view{"740812"});
    EXPECT_EQ(again.find("dateOfExpiry")->view(), std::string_view{"120415"});
}

TEST(CredentialCacheRequest, MalformedMrzPromptPayloadIsErrorAndNotCached)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{"garbage"}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);

    EXPECT_EQ(result.status, CredentialResult::Status::Error) << "a malformed MRZ payload is an error, not an Ok union";
    EXPECT_FALSE(cache.hasMrz("card-A")) << "a malformed payload must not be cached";

    // A following call prompts again (nothing was cached to hit).
    auto second = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    (void)second;
    EXPECT_EQ(prompter.mrzCalls, 2) << "a malformed prompt result must re-prompt on the next request";
}

TEST(CredentialCacheRequest, MalformedCachedMrzIsEvictedAndErrors)
{
    CredentialCache cache;
    cache.putMrz("card-A", String{"garbage"}); // a poisoned cache value (e.g. a stale deposit)
    FakePrompter prompter;
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);

    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_FALSE(cache.hasMrz("card-A")) << "a malformed cached value must be EVICTED so it cannot poison the next try";
    EXPECT_EQ(prompter.mrzCalls, 0) << "the hit path returns the error without prompting";
}

TEST(CredentialCacheRequest, CanPathUnchangedBySplitBuilders)
{
    // Regression pin: the split per-kind result builders must leave the Can
    // path returning exactly one "can" entry (never the MRZ union).
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_NE(result.find("can"), nullptr);
    EXPECT_EQ(result.values.size(), 1u) << "the Can builder must emit exactly one entry";
}

TEST(CredentialCacheRequest, CanPayloadWithNewlineRejectedNotCached)
{
    // Kind-confusion shape guard: a 3-line MRZ payload mis-delivered into the
    // CAN slot must never reach LM as a "CAN". A '\n' in a CAN payload is
    // malformed -> error, no cache write.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_FALSE(cache.hasCan("card-A")) << "a newline-bearing CAN payload must not be cached";
}

// -- The in-dialog CAN -> MRZ switch (the renegotiation hand-off) ------------
//
// A prompter that honoured the alternative-kind offer answers a CAN request
// with an MRZ payload and the kind it actually collected. requestCredential
// must NOT treat that as a CAN: it hands the payload to the caller's choice
// sink and unwinds the activation walk as a cancellation, so the flow one
// level up can renegotiate instead of feeding LM a "CAN" that is really an MRZ.

TEST(CredentialCacheRequest, ChosenMrzOnCanPromptFillsSinkAndCancelsWalk)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult =
        PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, "", LibreSCRS::Auth::PaceSecretKind::Mrz};
    PromptOptions opts;
    opts.altKinds = {"mrz"};
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};
    MrzChoiceSink sink;

    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          &userCancelled, &sink);

    EXPECT_EQ(result.status, CredentialResult::Status::UserCancelled)
        << "the walk unwinds as a cancellation so the flow can renegotiate";
    EXPECT_TRUE(sink.taken()) << "the user took the in-dialog switch";
    auto payload = sink.take();
    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(payload->view(), std::string_view{kTd3MrzPayload});
    EXPECT_FALSE(sink.taken()) << "one-shot: consuming disarms the sink";
    EXPECT_FALSE(sink.take().has_value()) << "a second take yields nothing";
    EXPECT_FALSE(userCancelled.load()) << "an in-dialog switch is NOT a user cancel";
    EXPECT_FALSE(prompterFailed.load()) << "an in-dialog switch is NOT a prompter failure";
    EXPECT_FALSE(cache.hasCan("card-A")) << "an MRZ payload must never land in the CAN slot";
    EXPECT_FALSE(cache.hasMrz("card-A")) << "the sink owns the payload; the cache write is the flow's call";
}

TEST(CredentialCacheRequest, ChosenMrzWithoutSinkIsPrompterError)
{
    // A caller that never advertised alt_kinds cannot receive a chosen-kind
    // reply: getting one means the prompter broke its side of the contract.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult =
        PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, "", LibreSCRS::Auth::PaceSecretKind::Mrz};
    PromptOptions opts;
    std::atomic<bool> prompterFailed{false};
    std::atomic<bool> userCancelled{false};

    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, &prompterFailed,
                                          &userCancelled);

    EXPECT_EQ(result.status, CredentialResult::Status::Error);
    EXPECT_TRUE(prompterFailed.load()) << "a chosen-kind reply to a non-opting caller is a broken prompter";
    EXPECT_FALSE(userCancelled.load());
    EXPECT_FALSE(cache.hasCan("card-A"));
    EXPECT_FALSE(cache.hasMrz("card-A"));
}

TEST(CredentialCacheRequest, ChosenKindEchoingTheRequestedKindIsAnOrdinaryReply)
{
    // A prompter MAY echo the kind it collected even when no switch happened;
    // that is an ordinary CAN reply, not a renegotiation.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, "", LibreSCRS::Auth::PaceSecretKind::Can};
    PromptOptions opts;
    MrzChoiceSink sink;

    auto result =
        cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, &sink);

    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_NE(result.find("can"), nullptr);
    EXPECT_FALSE(sink.taken());
    EXPECT_TRUE(cache.hasCan("card-A"));
}

TEST(CredentialCacheRequest, MrzChoiceSinkResetScrubsAnUnconsumedPayload)
{
    // The flow's teardown calls reset() so a payload nobody consumed never
    // outlives the run holding secret bytes.
    MrzChoiceSink sink;
    sink.offer(String{kTd3MrzPayload});
    ASSERT_TRUE(sink.taken());
    sink.reset();
    EXPECT_FALSE(sink.taken());
    EXPECT_FALSE(sink.take().has_value());
}

// --- The PACE attempt cap --------------------------------------------------
//
// The watchdog no longer bounds the consent -> PACE fails -> consent cycle, so
// the bound lives where the counter already does. A PIN cannot reach it: only
// Can and Mrz route through requestCredential, and the card owns that counter.

TEST(CredentialCacheAttemptCap, PromptsUpToTheCapAndThenStopsAsking)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
        EXPECT_EQ(result.status, CredentialResult::Status::Ok) << "attempt " << i << " should still be allowed to ask";
        cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    }
    EXPECT_EQ(prompter.canCalls, static_cast<int>(kMaxPaceAttempts));

    const auto capped = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(capped.status, CredentialResult::Status::Error);
    // Asserting only on the status would pass even if a dialog had been shown
    // to the holder and then discarded. The point of the cap is that nobody is
    // asked for a secret that can no longer be used.
    EXPECT_EQ(prompter.canCalls, static_cast<int>(kMaxPaceAttempts))
        << "the capped call raised a dialog the holder can never usefully answer";
}

TEST(CredentialCacheAttemptCap, TheCapAlsoCoversMrz)
{
    // The counter is shared between the two kinds because it bounds attempts on
    // THIS DOCUMENT's pre-read auth, not on a kind.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);
        EXPECT_EQ(result.status, CredentialResult::Status::Ok) << "attempt " << i;
        cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    }

    const auto capped = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts);
    EXPECT_EQ(capped.status, CredentialResult::Status::Error);
    EXPECT_EQ(prompter.mrzCalls, static_cast<int>(kMaxPaceAttempts));
}

TEST(CredentialCacheAttemptCap, ARemovedCardStartsOverBecauseItIsANewInsertion)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
        cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    }
    cache.invalidate("card-A"); // CardRemoved / ReaderRemoved erases the entry

    const auto afterReinsert = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(afterReinsert.status, CredentialResult::Status::Ok);
    EXPECT_EQ(prompter.canCalls, static_cast<int>(kMaxPaceAttempts) + 1);
}

TEST(CredentialCacheAttemptCap, TheCapIsPerCardNotGlobal)
{
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
        cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    }
    // A different card in a different reader must be unaffected -- otherwise one
    // holder's mistyping would lock out every other card in the machine, which
    // is the starvation this whole redesign exists to end.
    const auto other = cache.requestCredential("card-B", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(other.status, CredentialResult::Status::Ok);
}

TEST(CredentialCacheAttemptCap, ACachedSecretStillAnswersAfterTheCapIsReached)
{
    // The cap refuses to ASK, not to answer. A card whose secret is already
    // known must keep working -- the cap exists to stop pointless dialogs, not
    // to disable a card that has one.
    CredentialCache cache;
    FakePrompter prompter;
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        cache.markCredentialWrong("card-A", "librescrs.error.preRead.authFailed");
    }
    cache.putCan("card-A", String{"123456"});

    const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    EXPECT_EQ(prompter.canCalls, 0);
}

TEST(CredentialCacheAttemptCap, APinIsNeverCountedInSoftware)
{
    // The card owns the PIN retry counter. A software cap that disagreed with it
    // would tell the holder "too many attempts" while the card still had tries
    // left, or the reverse. The placement enforces this -- a PIN is refused at
    // the kind switch, before the cap or any prompt is reached -- and this pins
    // that routing so the cap can never migrate above it.
    CredentialCache cache;
    FakePrompter prompter;
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts + 2; ++i) {
        const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Pin), prompter, opts);
        EXPECT_EQ(result.status, CredentialResult::Status::Error);
    }
    EXPECT_EQ(prompter.canCalls, 0);
    EXPECT_EQ(prompter.mrzCalls, 0);
    // No PIN attempt was recorded against the card, so a later CAN is unaffected.
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const auto can = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts);
    EXPECT_EQ(can.status, CredentialResult::Status::Ok);
}
