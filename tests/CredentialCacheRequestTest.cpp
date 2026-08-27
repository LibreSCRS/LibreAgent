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

#include <LibreSCRS/Agent/cache/AttemptContext.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/PromptPolicy.h> // kMaxPaceAttempts
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>

using LibreSCRS::Agent::AttemptContext;
using LibreSCRS::Agent::CredentialCache;
using LibreSCRS::Agent::MrzChoiceSink;
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::Operations::kMaxPaceAttempts;
using LibreSCRS::Agent::Operations::PrompterClientBase;
using LibreSCRS::Agent::Operations::PromptSerializer;
using LibreSCRS::Agent::Operations::SerializingPrompter;
using LibreSCRS::Auth::AuthRequirement;
using LibreSCRS::Auth::CredentialResult;
using LibreSCRS::Auth::PaceSecretKind;
using LibreSCRS::Secure::String;
using namespace std::chrono_literals;

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

// A REAL PrompterClientBase whose requestCan() blocks until the test
// releases it. FakePrompter above is duck-typed and cannot sit behind a
// SerializingPrompter (which needs a real PrompterClientBase&), and its calls
// return immediately, which cannot represent an operation genuinely PARKED in
// PromptSerializer's FIFO wait while a sibling's dialog is still live. This
// fake exists so a concurrency test can hold that shape open long enough for
// a second thread to queue behind it.
class BlockingCanPrompter final : public PrompterClientBase
{
public:
    std::atomic<int> canCalls{0};
    PromptResult canResult;
    std::mutex holdMutex;
    std::condition_variable holdCv;
    bool entered{false};
    bool release_{false};

    PromptResult requestCan(const PromptOptions&) override
    {
        canCalls.fetch_add(1);
        std::unique_lock lock(holdMutex);
        entered = true;
        holdCv.notify_all();
        holdCv.wait(lock, [&] { return release_; });
        return canResult;
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Error, std::nullopt, "not used by this fake"};
    }
    PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Error, std::nullopt, "not used by this fake"};
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

TEST(CredentialCacheRequest, CanRePromptAfterRecordedRejectionCarriesAttemptAndLastError)
{
    // Retry context now lives on the CALLER's own AttemptContext, not on the
    // cache: requestCredential populates opts.attempt / opts.lastError from
    // whatever AttemptContext the caller hands it.
    CredentialCache cache;
    AttemptContext attempts;
    attempts.recordRejection("librescrs.error.preRead.authFailed");

    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr,
                                          nullptr, nullptr, nullptr, &attempts);

    EXPECT_EQ(result.status, CredentialResult::Status::Ok);
    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 2u) << "one recorded rejection -> this is the second attempt";
    EXPECT_EQ(prompter.lastCanOptions.lastError, "librescrs.error.preRead.authFailed");
}

TEST(CredentialCacheRequest, MrzRePromptAfterRecordedRejectionCarriesAttemptAndLastError)
{
    CredentialCache cache;
    AttemptContext attempts;
    attempts.recordRejection("librescrs.error.preRead.authFailed");

    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{"P<UTOERIKSSON<<ANNA<MARIA"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, &attempts);

    ASSERT_EQ(prompter.mrzCalls, 1);
    EXPECT_EQ(prompter.lastMrzOptions.attempt, 2u);
    EXPECT_EQ(prompter.lastMrzOptions.lastError, "librescrs.error.preRead.authFailed");
}

TEST(CredentialCacheRequest, SecondConsecutiveRejectionBumpsAttemptToThree)
{
    CredentialCache cache;
    AttemptContext attempts;
    attempts.recordRejection("librescrs.error.preRead.authFailed");
    attempts.recordRejection("librescrs.error.preRead.authFailed");

    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, &attempts);

    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 3u) << "two prior rejections -> this is the third attempt";
}

TEST(CredentialCacheRequest, InvalidateDoesNotResetAnOperationsOwnRetryContext)
{
    // Retry context moved OFF the cache and onto the operation's own
    // AttemptContext -- so invalidate() (a cache-only eviction) has no bearing
    // on it. The old per-card design stored the count on the cache entry, so
    // invalidate() used to reset it; under per-operation ownership there is
    // nothing left on the cache side for invalidate() to reset. A fresh
    // operation starts cold not because the cache was cleared, but because
    // every real read flow constructs a brand-new AttemptContext at the top
    // of its own run() (see IdentityReadFlow / CertReadFlow).
    CredentialCache cache;
    AttemptContext attempts;
    attempts.recordRejection("librescrs.error.preRead.authFailed");
    cache.invalidate("card-A");

    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"654321"}, ""};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, &attempts);

    ASSERT_EQ(prompter.canCalls, 1);
    EXPECT_EQ(prompter.lastCanOptions.attempt, 2u)
        << "an operation's own retry context survives a cache-side invalidate";
}

TEST(CredentialCacheRequest, CacheHitAfterMarkCredentialWrongNeverReachesThePrompter)
{
    // A retry re-collecting a CORRECT secret is cached normally; a later,
    // unrelated cache HIT for the same card must not prompt at all (so no
    // question of retry context arises on that path).
    CredentialCache cache;
    cache.markCredentialWrong("card-A");
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

// -- The prompt gate: one declined window silences the operations queued
//    behind it ----------------------------------------------------------

TEST(CredentialCacheRequest, QueuedOperationsAreSilencedByAnExpiry)
{
    // Three verbs dispatched together (identity, token info, credentials) all
    // captured the same generation. The first window expires; the other two
    // were never the holder's second and third chance -- they were the same
    // chance, queued. Measured on hardware: three windows, 120 s apart.
    //
    // Beyond "no second window": the two silenced verbs must report the SAME
    // outcome (EntryExpired) the verb that actually raised the window
    // reported, not a generic communication failure -- a holder who let a
    // window expire must not be told two of the three reads failed for an
    // unrelated reason.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, "expired"};

    const std::uint64_t g = cache.refusalGenerationFor("card-A");
    AttemptContext first{g}, second{g}, third{g}; // all dispatched together

    PromptOptions opts;
    std::atomic<bool> expired1{false};
    std::atomic<bool> expired2{false};
    std::atomic<bool> expired3{false};
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                  &expired1, nullptr, &first);
    EXPECT_EQ(prompter.canCalls, 1);
    EXPECT_TRUE(expired1.load()) << "the verb that actually raised the window reports the expiry";

    // The MIDDLE one, not only the last: with two, "first" and "last" pass by
    // accident.
    auto r2 = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                      &expired2, nullptr, &second);
    auto r3 = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                      &expired3, nullptr, &third);
    EXPECT_EQ(prompter.canCalls, 1) << "a queued operation must not raise a second window";
    EXPECT_NE(r2.status, CredentialResult::Status::Ok);
    EXPECT_NE(r3.status, CredentialResult::Status::Ok);
    EXPECT_TRUE(expired2.load()) << "a silenced verb must report the SAME outcome the first one did";
    EXPECT_TRUE(expired3.load()) << "a silenced verb must report the SAME outcome the first one did";
}

TEST(CredentialCacheRequest, QueuedOperationsAreSilencedByACancel)
{
    // Cancel is the SAME shape as expiry and today leaves no trace at all, so
    // "Cancel" had to be clicked once per queued verb.
    //
    // The silenced verbs must report UserCancelled -- the SAME outcome the
    // verb that actually raised the window reported -- not a generic error
    // and not a fabricated expiry.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};

    const std::uint64_t g = cache.refusalGenerationFor("card-A");
    AttemptContext first{g}, second{g}, third{g}; // all dispatched together

    PromptOptions opts;
    std::atomic<bool> cancelled1{false};
    std::atomic<bool> cancelled2{false};
    std::atomic<bool> cancelled3{false};
    auto r1 = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, &cancelled1,
                                      nullptr, nullptr, nullptr, &first);
    auto r2 = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, &cancelled2,
                                      nullptr, nullptr, nullptr, &second);
    auto r3 = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, &cancelled3,
                                      nullptr, nullptr, nullptr, &third);
    EXPECT_EQ(prompter.canCalls, 1) << "one decline is a decline for everyone already queued";
    EXPECT_EQ(r1.status, CredentialResult::Status::UserCancelled);
    EXPECT_EQ(r2.status, CredentialResult::Status::UserCancelled)
        << "a silenced verb must report the SAME outcome the first one did";
    EXPECT_EQ(r3.status, CredentialResult::Status::UserCancelled)
        << "a silenced verb must report the SAME outcome the first one did";
    EXPECT_TRUE(cancelled1.load());
    EXPECT_TRUE(cancelled2.load());
    EXPECT_TRUE(cancelled3.load());
}

TEST(CredentialCacheRequest, ADismissedWindowIsRecordedAsHavingYieldedNothing)
{
    // To everything above this cache a dismissed window and an expired one are
    // the same fact: NOTHING was presented to the card. The activation fails
    // either way, and the card re-invokes carrying the very reason a genuinely
    // wrong value earns -- so the guard that decides whether that reason IS a
    // rejection reads exactly this flag (FlowPrelude::isCardRejectionSignal).
    // Recording it for the clock alone left one click on the dialog's dismiss
    // button evicting a value the holder never entered, spending one of the
    // three PACE attempts on it, and putting "the value entered was not
    // accepted" in front of someone who entered nothing.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};

    AttemptContext ctx{cache.refusalGenerationFor("card-A")};
    PromptOptions opts;
    const auto r = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr,
                                           nullptr, nullptr, nullptr, &ctx);
    ASSERT_EQ(r.status, CredentialResult::Status::UserCancelled);
    ASSERT_EQ(prompter.canCalls, 1) << "the window really was raised, and really was dismissed";
    EXPECT_TRUE(cache.lastPromptYieldedNothingFor("card-A"))
        << "a dismissal presents nothing to the card -- the identical fact an expiry records";
}

TEST(CredentialCacheRequest, AnAnsweredWindowClearsWhatADismissedOneRecorded)
{
    // The other half, and the reason the flag is not simply latched: a WRONG
    // value entered after a dismissal is a real rejection and must still be
    // charged. The flag names the LAST prompt, so a prompt that answered clears
    // it -- otherwise one dismissal would excuse every wrong value after it for
    // the rest of the insertion.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};

    AttemptContext dismissed{cache.refusalGenerationFor("card-A")};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, &dismissed);
    ASSERT_TRUE(cache.lastPromptYieldedNothingFor("card-A"));

    // A NEW operation (the retry affordance) whose window the holder answers.
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    AttemptContext answered{cache.refusalGenerationFor("card-A")};
    const auto r = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr,
                                           nullptr, nullptr, nullptr, &answered);
    ASSERT_EQ(r.status, CredentialResult::Status::Ok);
    EXPECT_FALSE(cache.lastPromptYieldedNothingFor("card-A"))
        << "this prompt DID yield a secret, so the next rejection signal describes a real rejection";
}

TEST(CredentialCacheRequest, AnOperationStartedAfterTheRefusalStillPrompts)
{
    // The retry button. It creates a NEW operation, which captures the
    // generation as it now stands -- so the gate must let it through. Without
    // this the fix kills the only affordance the holder has left.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, "expired"};

    AttemptContext queued{cache.refusalGenerationFor("card-A")};
    PromptOptions opts;
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, &queued);
    EXPECT_EQ(prompter.canCalls, 1);

    // Created AFTER the refusal, exactly as the retry button does.
    AttemptContext retried{cache.refusalGenerationFor("card-A")};
    (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, &retried);
    EXPECT_EQ(prompter.canCalls, 2) << "an operation the holder just asked for must still be able to ask";
}

TEST(CredentialCacheRequest, ACacheHitSurvivesTheGate)
{
    // REGRESSION GATE. The gate belongs AFTER the cache hit: it refuses to
    // ASK, never to ANSWER. Placed before the hit it breaks the SUCCESS path --
    // the holder types the CAN into the first window and the two queued verbs,
    // which should be served silently from cache, fail instead. No other test
    // here would catch that.
    CredentialCache cache;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, "expired"};

    AttemptContext queued{cache.refusalGenerationFor("card-A")};
    cache.noteRefusal("card-A");              // generation has moved past what `queued` captured
    cache.putCan("card-A", String{"123456"}); // ...but the secret is present

    PromptOptions opts;
    auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr,
                                          nullptr, nullptr, nullptr, &queued);
    EXPECT_EQ(result.status, CredentialResult::Status::Ok) << "a cached secret is an ANSWER, not an ASK";
    ASSERT_NE(result.find("can"), nullptr);
    EXPECT_EQ(prompter.canCalls, 0);
}

// The sequential tests above (QueuedOperationsAreSilencedBy*) prove the gate
// closes when a queued operation's check runs BEFORE it ever reaches the
// prompter -- each requestCredential call there returns before the next
// begins. Production does not dispatch that way: three verbs dispatched
// together all pass THAT check at the SAME generation, then queue behind
// PromptSerializer's per-card FIFO slot -- a shape no sequential test can
// represent, and the one a check made only at dispatch time cannot see,
// because the wait for the slot can itself outlast a sibling's whole prompt.
// This test drives two REAL concurrent operations through a REAL
// PromptSerializer + SerializingPrompter, wired exactly as
// FlowPrelude::makeReadCredentialProvider wires them in production, so the
// second is genuinely parked waiting for the slot while the first's window
// closes.
TEST(CredentialCacheRequest, AConcurrentlyQueuedOperationIsNeverPromptedAfterASiblingsRefusal)
{
    CredentialCache cache;
    PromptSerializer serializer;
    BlockingCanPrompter inner;
    inner.canResult = PromptResult{PromptStatus::Timeout, std::nullopt, "expired"};

    const std::uint64_t g = cache.refusalGenerationFor("card-A");
    AttemptContext first{g};
    AttemptContext second{g};

    LibreSCRS::CancelSource src1;
    LibreSCRS::CancelSource src2;
    std::atomic<bool> firstDone{false};
    // Calls the SAME cache.stillWantedFor production wires (see
    // FlowPrelude::makeReadCredentialProvider) -- not a hand-rolled
    // reimplementation of the comparison, so this test and production can
    // never silently drift apart.
    //
    // The wait-for-firstDone loop is a TEST-ONLY synchronization aid. It
    // pins down that, by the time second's predicate is consulted, first's
    // OWN requestCredential call -- noteRefusal included -- has FULLY
    // returned, sidestepping a separate and much narrower timing question:
    // PromptSerializer::release() (which wakes a queued waiter) runs, on the
    // releasing thread, strictly BEFORE that thread calls
    // CredentialCache::noteRefusal() -- release() is what the SlotGuard fires
    // as doPrompt() returns, before control unwinds back up to
    // requestCredential's post-prompt handling. A woken waiter could in
    // principle re-acquire the slot and evaluate ITS OWN predicate before the
    // releasing thread reaches noteRefusal(). That gap is a handful of
    // in-process function returns wide (nanoseconds-to-low-microseconds);
    // closing it would mean giving SerializingPrompter its own knowledge of
    // WHEN to bump a card's refusal generation, which is the opposite of
    // keeping it generic. That gap is a KNOWN, ACCEPTED residual: losing it
    // costs one extra dialog, never a fabricated silence. It is far narrower
    // than the FIFO-wait window this test exists to close, which is unbounded
    // -- bounded only by the dialog's own deadline.
    auto stillWantedSecond = [&] {
        for (int i = 0; i < 2000 && !firstDone.load(); ++i) {
            std::this_thread::sleep_for(1ms);
        }
        return cache.stillWantedFor("card-A", &second);
    };
    SerializingPrompter gated1{serializer, inner, src1.token(), "card-A"};
    SerializingPrompter gated2{serializer, inner, src2.token(), "card-A", stillWantedSecond};

    PromptOptions opts;
    std::thread t1([&] {
        auto r = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), gated1, opts, nullptr, nullptr,
                                         nullptr, nullptr, nullptr, &first);
        EXPECT_NE(r.status, CredentialResult::Status::Ok);
        firstDone = true;
    });

    // Wait until the first operation is actually inside the prompter (holding
    // the slot), so the second is guaranteed to queue behind it.
    {
        std::unique_lock lock(inner.holdMutex);
        ASSERT_TRUE(inner.holdCv.wait_for(lock, 2s, [&] { return inner.entered; }))
            << "the first operation must reach the prompter";
    }

    std::atomic<bool> secondDone{false};
    std::atomic<CredentialResult::Status> secondStatus{CredentialResult::Status::Ok};
    std::atomic<bool> secondEntryExpired{false};
    std::thread t2([&] {
        auto r = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), gated2, opts, nullptr, nullptr,
                                         nullptr, &secondEntryExpired, nullptr, &second);
        secondStatus = r.status;
        secondDone = true;
    });

    // Give the second thread time to genuinely reach the queued wait behind
    // the first -- the "parked in the serializer" shape a sequential test
    // cannot represent.
    std::this_thread::sleep_for(150ms);
    EXPECT_FALSE(secondDone.load()) << "second operation must still be queued, not yet returned";
    EXPECT_EQ(inner.canCalls.load(), 1) << "only the first operation has reached the prompter so far";

    // Release the first: its window "closes" (Timeout), bumping the card's
    // refusal generation. The second, still queued, wakes, is granted the
    // slot, and must find itself no longer wanted -- WITHOUT ever raising a
    // second window.
    {
        std::lock_guard lock(inner.holdMutex);
        inner.release_ = true;
        inner.holdCv.notify_all();
    }
    t1.join();
    t2.join();

    EXPECT_TRUE(firstDone.load());
    EXPECT_TRUE(secondDone.load());
    EXPECT_EQ(inner.canCalls.load(), 1)
        << "the second operation queued behind the FIFO wait and must be silenced there, not raise its own window";
    // Not just "not Ok": the refused-after-waiting outcome must be the SAME
    // one the operation that actually raised the window got (buildError(),
    // EntryExpired raised), not a generic status that happens to differ from
    // Ok. Deleting the post-acquire recheck entirely leaves the whole suite
    // green on a bare "!= Ok" check while the placeholder falls through to
    // the Cancelled branch and reports UserCancelled for what was really an
    // expiry. That perturbation was run against this suite: with the recheck
    // deleted, this equality is the ONLY assertion anywhere that reddens.
    EXPECT_EQ(secondStatus.load(), CredentialResult::Status::Error)
        << "the silenced operation must report the SAME outcome (buildError, mapped from EntryExpired) the "
           "operation that actually prompted did, not a different failure shape";
    EXPECT_TRUE(secondEntryExpired.load()) << "the silenced operation must raise the SAME entryExpired signal";
}

// The post-acquire recheck above exists to catch a sibling's window closing
// WHILE this operation waited its turn -- but "refuse to ASK, never to
// ANSWER" (the invariant ACacheHitSurvivesTheGate pins for the cache-hit
// path) applies here too. An operation that DID collect the right secret
// must never be discarded just because some OTHER, unrelated operation on
// the SAME card was refused at any point while this one's own dialog was
// still open. No race is needed to reach this: a sibling cancelled WHILE
// QUEUED -- or even before it ever reaches the queue at all (CancelCurrent,
// watchdog timeout, reader removal, shutdown drain all fire a CancelToken
// unconditionally) -- never touches the prompter, yet still bumps the
// card's refusal generation via the Cancelled branch, and that can happen
// at ANY moment during another operation's live, multi-second dialog.
TEST(CredentialCacheRequest, ACorrectlyAnsweredDialogSurvivesAnUnrelatedSiblingsRefusalRaisedWhileItWasLive)
{
    CredentialCache cache;
    PromptSerializer serializer;
    BlockingCanPrompter inner;
    inner.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};

    const std::uint64_t g = cache.refusalGenerationFor("card-A");
    AttemptContext first{g};

    LibreSCRS::CancelSource src1;
    // Wired exactly as production wires it (see FlowPrelude::makeReadCredentialProvider):
    // still consulted after this operation's OWN wait for the slot, which
    // happened long before the sibling below is even constructed.
    auto stillWantedFirst = [&] { return cache.stillWantedFor("card-A", &first); };
    SerializingPrompter gated1{serializer, inner, src1.token(), "card-A", stillWantedFirst};

    PromptOptions opts;
    std::atomic<bool> firstDone{false};
    std::atomic<CredentialResult::Status> firstStatus{CredentialResult::Status::Error};
    std::thread t1([&] {
        auto r = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), gated1, opts, nullptr, nullptr,
                                         nullptr, nullptr, nullptr, &first);
        firstStatus = r.status;
        firstDone = true;
    });

    // Wait until the first operation's dialog is genuinely live (already past
    // its own predicate check -- SerializingPrompter checks it exactly ONCE,
    // right after acquiring the slot, never again while doPrompt is parked).
    {
        std::unique_lock lock(inner.holdMutex);
        ASSERT_TRUE(inner.holdCv.wait_for(lock, 2s, [&] { return inner.entered; }))
            << "the first operation must reach the prompter";
    }

    // A second, UNRELATED operation for the SAME card is refused before it
    // ever reaches the prompter -- a pre-cancelled token reproduces exactly
    // what CancelCurrent / a watchdog timeout / reader removal produce
    // (PromptSerializer::acquire() handles an already-cancelled token and one
    // cancelled mid-wait identically -- see PromptSerializer.cpp). This never
    // touches the prompter (inner.canCalls must stay at 1) but still bumps
    // the card's refusal generation, WHILE the first's dialog is still open.
    LibreSCRS::CancelSource src2;
    src2.requestCancel();
    SerializingPrompter gated2{serializer, inner, src2.token(), "card-A"};
    AttemptContext second{g};
    auto r2 = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), gated2, opts, nullptr, nullptr, nullptr,
                                      nullptr, nullptr, &second);
    EXPECT_EQ(r2.status, CredentialResult::Status::UserCancelled) << "the cancelled sibling reports its own cancel";
    EXPECT_GT(cache.refusalGenerationFor("card-A"), g)
        << "the sibling's cancel must have bumped the generation while the first's dialog was still live";

    // Release the first's dialog with the CORRECT answer.
    {
        std::lock_guard lock(inner.holdMutex);
        inner.release_ = true;
        inner.holdCv.notify_all();
    }
    t1.join();

    EXPECT_EQ(firstStatus.load(), CredentialResult::Status::Ok)
        << "a correctly answered dialog must not be discarded because an unrelated sibling's refusal bumped the "
           "generation while it was still open";
    EXPECT_EQ(inner.canCalls.load(), 1) << "only the first operation ever reached the prompter";
    ASSERT_TRUE(cache.hasCan("card-A")) << "the correct secret must be CACHED, not discarded";
    ASSERT_TRUE(cache.getCan("card-A").has_value());
    EXPECT_EQ(cache.getCan("card-A")->view(), std::string_view{"123456"});
}

// --- The PACE attempt cap --------------------------------------------------
//
// The watchdog no longer bounds the consent -> PACE fails -> consent cycle, so
// the bound lives where the counter already does: the CALLING OPERATION's own
// AttemptContext (see AttemptContextTest and IdentityReadFlowTest for the
// full per-operation story). A PIN cannot reach it: only Can and Mrz route
// through requestCredential, and a null context (no AttemptContext passed)
// turns the cap off entirely -- see APinIsNeverCountedInSoftware below.

TEST(CredentialCacheAttemptCap, PromptsUpToTheCapAndThenStopsAsking)
{
    CredentialCache cache;
    AttemptContext attempts;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr,
                                                    nullptr, nullptr, nullptr, nullptr, &attempts);
        EXPECT_EQ(result.status, CredentialResult::Status::Ok) << "attempt " << i << " should still be allowed to ask";
        // Mirrors what production's credential provider does together: evict
        // the now-known-wrong cached value (so the NEXT iteration re-prompts
        // instead of hitting the still-cached secret from this one) AND
        // record the rejection on this operation's own context.
        cache.markCredentialWrong("card-A");
        attempts.recordRejection("librescrs.error.preRead.authFailed");
    }
    EXPECT_EQ(prompter.canCalls, static_cast<int>(kMaxPaceAttempts));

    const auto capped = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr,
                                                nullptr, nullptr, nullptr, nullptr, &attempts);
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
    // THIS OPERATION's pre-read auth, not on a kind.
    CredentialCache cache;
    AttemptContext attempts;
    FakePrompter prompter;
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{kTd3MrzPayload}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts, nullptr,
                                                    nullptr, nullptr, nullptr, nullptr, &attempts);
        EXPECT_EQ(result.status, CredentialResult::Status::Ok) << "attempt " << i;
        // See PromptsUpToTheCapAndThenStopsAsking: evict AND record together,
        // mirroring what production's credential provider does.
        cache.markCredentialWrong("card-A");
        attempts.recordRejection("librescrs.error.preRead.authFailed");
    }

    const auto capped = cache.requestCredential("card-A", paceReq(PaceSecretKind::Mrz), prompter, opts, nullptr,
                                                nullptr, nullptr, nullptr, nullptr, &attempts);
    EXPECT_EQ(capped.status, CredentialResult::Status::Error);
    EXPECT_EQ(prompter.mrzCalls, static_cast<int>(kMaxPaceAttempts));
}

TEST(CredentialCacheAttemptCap, ANewOperationStartsOverBecauseItIsANewAllowance)
{
    // A card re-insertion (or simply a second, unrelated read) is a NEW
    // operation: a fresh AttemptContext, not the exhausted one above. Under
    // the old per-card design the cache held the counter and invalidate()
    // reset it on CardRemoved; now the reset is simply "construct a new
    // context", which every real read flow does at the top of its own run().
    CredentialCache cache;
    AttemptContext attempts;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                      nullptr, nullptr, &attempts);
        // Evict AND record together (see PromptsUpToTheCapAndThenStopsAsking):
        // without the evict, iteration 2 onward would hit the CAN iteration 1
        // cached and never re-prompt, undercounting canCalls below.
        cache.markCredentialWrong("card-A");
        attempts.recordRejection("librescrs.error.preRead.authFailed");
    }
    cache.invalidate("card-A"); // CardRemoved / ReaderRemoved erases the cached secrets

    AttemptContext freshAttempts;
    const auto afterReinsert = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr,
                                                       nullptr, nullptr, nullptr, nullptr, &freshAttempts);
    EXPECT_EQ(afterReinsert.status, CredentialResult::Status::Ok);
    EXPECT_EQ(prompter.canCalls, static_cast<int>(kMaxPaceAttempts) + 1);
}

TEST(CredentialCacheAttemptCap, TheCapIsPerOperationNotGlobal)
{
    CredentialCache cache;
    AttemptContext attempts;
    FakePrompter prompter;
    prompter.canResult = PromptResult{PromptStatus::Ok, String{"123456"}, ""};
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        (void)cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr, nullptr,
                                      nullptr, nullptr, &attempts);
        cache.markCredentialWrong("card-A"); // evict AND record together, mirroring production
        attempts.recordRejection("librescrs.error.preRead.authFailed");
    }
    // A different card, driven through a DIFFERENT operation's own context,
    // must be unaffected -- otherwise one holder's mistyping would lock out
    // every other card in the machine, which is the starvation this whole
    // redesign exists to end.
    AttemptContext otherAttempts;
    const auto other = cache.requestCredential("card-B", paceReq(PaceSecretKind::Can), prompter, opts, nullptr, nullptr,
                                               nullptr, nullptr, nullptr, &otherAttempts);
    EXPECT_EQ(other.status, CredentialResult::Status::Ok);
}

TEST(CredentialCacheAttemptCap, ACachedSecretStillAnswersAfterTheCapIsReached)
{
    // The cap refuses to ASK, not to answer. A card whose secret is already
    // known must keep working -- the cap exists to stop pointless dialogs, not
    // to disable a card that has one.
    CredentialCache cache;
    AttemptContext attempts;
    FakePrompter prompter;
    const PromptOptions opts;

    for (std::uint32_t i = 0; i < kMaxPaceAttempts; ++i) {
        attempts.recordRejection("librescrs.error.preRead.authFailed");
    }
    cache.putCan("card-A", String{"123456"});

    const auto result = cache.requestCredential("card-A", paceReq(PaceSecretKind::Can), prompter, opts, nullptr,
                                                nullptr, nullptr, nullptr, nullptr, &attempts);
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
