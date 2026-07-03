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
#include <optional>
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

    PromptResult requestCan(const PromptOptions&)
    {
        ++canCalls;
        return canResult;
    }
    PromptResult requestMrz(const PromptOptions&)
    {
        ++mrzCalls;
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
    prompter.mrzResult = PromptResult{PromptStatus::Ok, String{"P<UTOERIKSSON<<ANNA<MARIA"}, ""};
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
