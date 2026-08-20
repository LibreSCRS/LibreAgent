// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/PromptIdMinter.h>
#include <gtest/gtest.h>

#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using LibreSCRS::Agent::Operations::PromptIdMinter;

TEST(PromptIdMinter, IdsAreUniqueWithinOneRun)
{
    PromptIdMinter minter{"abc123"};
    EXPECT_EQ(minter.mint(), "abc123:1");
    EXPECT_EQ(minter.mint(), "abc123:2");
    EXPECT_EQ(minter.mint(), "abc123:3");
}

TEST(PromptIdMinter, TwoRunsNeverMintTheSameId)
{
    // The LK-3 shape: a per-process counter alone would make both runs emit
    // "1", so a stale prompter's window could be closed by the new agent.
    PromptIdMinter first;
    PromptIdMinter second;
    ASSERT_NE(first.runNonce(), second.runNonce());
    EXPECT_NE(first.mint(), second.mint());
}

TEST(PromptIdMinter, TheNonceIsNotEmptyAndCarriesNoSeparator)
{
    PromptIdMinter minter;
    EXPECT_FALSE(minter.runNonce().empty());
    // The id is split on ':' by nobody -- it is opaque -- but a nonce
    // containing the separator would make it ambiguous to a human reading logs.
    EXPECT_EQ(minter.runNonce().find(':'), std::string::npos);
}

TEST(PromptIdMinter, ConcurrentMintingProducesNoDuplicates)
{
    PromptIdMinter minter{"race"};
    std::vector<std::thread> threads;
    std::mutex mutex;
    std::set<std::string> seen;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 100; ++i) {
                auto id = minter.mint();
                std::lock_guard lock{mutex};
                seen.insert(std::move(id));
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(seen.size(), 800u);
}
