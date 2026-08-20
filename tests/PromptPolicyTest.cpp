// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/PromptPolicy.h>
#include <gtest/gtest.h>

using namespace std::chrono_literals;
using LibreSCRS::Agent::Operations::deadlineFor;
using LibreSCRS::Agent::Operations::kLongestDeadline;
using LibreSCRS::Agent::Operations::kMaxPaceAttempts;
using LibreSCRS::Agent::Operations::PromptKind;

TEST(PromptPolicy, EachKindGetsTheDeadlineTheDesignChose)
{
    EXPECT_EQ(deadlineFor(PromptKind::Pin), 60'000ms);
    EXPECT_EQ(deadlineFor(PromptKind::Can), 120'000ms);
    EXPECT_EQ(deadlineFor(PromptKind::Mrz), 300'000ms);
    EXPECT_EQ(deadlineFor(PromptKind::ChangePin), 180'000ms);
}

TEST(PromptPolicy, MrzGetsTheMostTimeBecauseItIsEightyEightCharacters)
{
    EXPECT_GT(deadlineFor(PromptKind::Mrz), deadlineFor(PromptKind::Can));
    EXPECT_GT(deadlineFor(PromptKind::Can), deadlineFor(PromptKind::Pin));
}

TEST(PromptPolicy, TheLongestDeadlineConstantActuallyIsTheLongest)
{
    // Consumers (Phase 2) static_assert their transport budget against this.
    // If a kind ever outgrows it, that assertion must not silently pass.
    for (auto k : {PromptKind::Pin, PromptKind::Can, PromptKind::Mrz, PromptKind::ChangePin}) {
        EXPECT_LE(deadlineFor(k), kLongestDeadline);
    }
    EXPECT_EQ(kLongestDeadline, deadlineFor(PromptKind::Mrz));
}

TEST(PromptPolicy, ThePaceAttemptCapIsThree)
{
    EXPECT_EQ(kMaxPaceAttempts, 3u);
}
