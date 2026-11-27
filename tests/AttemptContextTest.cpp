// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The per-operation attempt context, and the per-card refusal generation the
// prompt gate compares against. Attempts belong to ONE read attempt; the
// generation belongs to the card and outlives any single operation.

#include <LibreSCRS/Agent/cache/AttemptContext.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <type_traits>

using LibreSCRS::Agent::AttemptContext;
using LibreSCRS::Agent::CredentialCache;
using LibreSCRS::Agent::PublishedRefusalGeneration;

TEST(PublishedRefusalGeneration, HasNoDefaultSoNoOperationCanForgetIt)
{
    static_assert(!std::is_default_constructible_v<PublishedRefusalGeneration>);
    static_assert(!std::is_constructible_v<AttemptContext, std::uint64_t>);
    static_assert(!std::is_default_constructible_v<AttemptContext>);
    EXPECT_EQ(AttemptContext{PublishedRefusalGeneration{7}}.generationAtDispatch(), 7u);
}

TEST(AttemptContext, StartsCleanSoAFreshOperationPromptsCold)
{
    AttemptContext ctx{PublishedRefusalGeneration{0}};
    EXPECT_EQ(ctx.attempts(), 0U);
    EXPECT_TRUE(ctx.lastErrorKey().empty());
}

TEST(AttemptContext, RejectionRaisesTheCountAndRemembersWhy)
{
    AttemptContext ctx{PublishedRefusalGeneration{0}};
    ctx.recordRejection("librescrs.error.preRead.authFailed");
    EXPECT_EQ(ctx.attempts(), 1U);
    EXPECT_EQ(ctx.lastErrorKey(), "librescrs.error.preRead.authFailed");
    ctx.recordRejection("librescrs.error.preRead.authFailed");
    EXPECT_EQ(ctx.attempts(), 2U);
}

TEST(AttemptContext, TwoContextsDoNotShareACount)
{
    // The whole point of the per-operation split: three verbs dispatched
    // together must not spend each other's attempts, the way one per-card
    // counter made them.
    AttemptContext first{PublishedRefusalGeneration{0}};
    AttemptContext second{PublishedRefusalGeneration{0}};
    first.recordRejection("k");
    first.recordRejection("k");
    EXPECT_EQ(first.attempts(), 2U);
    EXPECT_EQ(second.attempts(), 0U) << "attempts belong to one operation, not to the card";
}

TEST(AttemptContext, GenerationAtDispatchIsFixedByConstruction)
{
    // No setter exists: the only way the value can differ from the default
    // is through the constructor argument, and it must still be readable
    // afterwards exactly as given.
    AttemptContext defaulted{PublishedRefusalGeneration{0}};
    EXPECT_EQ(defaulted.generationAtDispatch(), 0U);

    AttemptContext ctx{PublishedRefusalGeneration{7}};
    EXPECT_EQ(ctx.generationAtDispatch(), 7U);
}

TEST(CredentialCacheRefusal, GenerationStartsAtZeroAndRisesPerRefusal)
{
    CredentialCache cache;
    EXPECT_EQ(cache.refusalGenerationFor("card-A"), 0U);
    cache.noteRefusal("card-A");
    EXPECT_EQ(cache.refusalGenerationFor("card-A"), 1U);
    cache.noteRefusal("card-A");
    EXPECT_EQ(cache.refusalGenerationFor("card-A"), 2U);
}

TEST(CredentialCacheRefusal, GenerationIsPerCard)
{
    CredentialCache cache;
    cache.noteRefusal("card-A");
    EXPECT_EQ(cache.refusalGenerationFor("card-A"), 1U);
    EXPECT_EQ(cache.refusalGenerationFor("card-B"), 0U) << "one card's refusal must not silence another card's prompt";
}

TEST(CredentialCacheRefusal, EvictSecretsKeepsTheRefusalGeneration)
{
    // A rejected secret is dropped, but the card's own refusal history is not:
    // a holder who walked away from a window must not find the next operation
    // for the same card free to raise another one.
    CredentialCache cache;
    cache.noteRefusal("card-A", CredentialCache::RefusalKind::Cancelled);
    cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
    cache.evictSecrets("card-A");
    EXPECT_EQ(cache.refusalGenerationFor("card-A"), 1U);
    EXPECT_EQ(cache.lastRefusalKindFor("card-A"), CredentialCache::RefusalKind::Cancelled);
    EXPECT_FALSE(cache.getCan("card-A").has_value());
}

TEST(CredentialCacheRefusal, RemovalClearsTheGeneration)
{
    // invalidate() is the card-removal path. A re-presented card is a fresh
    // start: the holder who walked away from one insertion must not find the
    // next one already silenced.
    CredentialCache cache;
    cache.noteRefusal("card-A");
    cache.invalidate("card-A");
    EXPECT_EQ(cache.refusalGenerationFor("card-A"), 0U);
}
