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
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
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
