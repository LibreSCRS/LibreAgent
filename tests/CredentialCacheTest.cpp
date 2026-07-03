// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Type-system contract: this cache exposes NO putPin / getPin / hasPin method.
// PIN is never cached by construction; if a future change tries to add such a
// method, this test file (and every PIN-using call site) becomes the change's
// audit trail.

#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Secure/String.h>
#include <atomic>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using Secret = LibreSCRS::Secure::String;

namespace {
const std::string kCardA = "card-fp-A";
const std::string kCardB = "card-fp-B";
} // namespace

TEST(CredentialCache, EmptyByDefault)
{
    CredentialCache c;
    EXPECT_FALSE(c.hasCan(kCardA));
    EXPECT_FALSE(c.hasMrz(kCardA));
    EXPECT_FALSE(c.getCan(kCardA).has_value());
    EXPECT_FALSE(c.getMrz(kCardA).has_value());
}

TEST(CredentialCache, PutCanThenGetRoundTrips)
{
    CredentialCache c;
    c.putCan(kCardA, Secret{"123456"});

    EXPECT_TRUE(c.hasCan(kCardA));
    const auto got = c.getCan(kCardA);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->view(), "123456");
}

TEST(CredentialCache, PutMrzThenGetRoundTrips)
{
    CredentialCache c;
    c.putMrz(kCardA, Secret{"P<XXX..."});

    EXPECT_TRUE(c.hasMrz(kCardA));
    const auto got = c.getMrz(kCardA);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->view(), "P<XXX...");
}

TEST(CredentialCache, CanAndMrzCoexistForSameCard)
{
    CredentialCache c;
    c.putCan(kCardA, Secret{"123456"});
    c.putMrz(kCardA, Secret{"MRZ-DATA"});

    EXPECT_TRUE(c.hasCan(kCardA));
    EXPECT_TRUE(c.hasMrz(kCardA));
    EXPECT_EQ(c.getCan(kCardA)->view(), "123456");
    EXPECT_EQ(c.getMrz(kCardA)->view(), "MRZ-DATA");
}

TEST(CredentialCache, OverwriteReplacesPrevious)
{
    CredentialCache c;
    c.putCan(kCardA, Secret{"111111"});
    c.putCan(kCardA, Secret{"222222"});
    EXPECT_EQ(c.getCan(kCardA)->view(), "222222");
}

TEST(CredentialCache, InvalidateDropsBothCanAndMrz)
{
    CredentialCache c;
    c.putCan(kCardA, Secret{"123456"});
    c.putMrz(kCardA, Secret{"MRZ"});

    c.invalidate(kCardA);

    EXPECT_FALSE(c.hasCan(kCardA));
    EXPECT_FALSE(c.hasMrz(kCardA));
}

TEST(CredentialCache, InvalidateUnknownCardIsNoOp)
{
    CredentialCache c;
    c.invalidate(kCardA); // never set
    EXPECT_FALSE(c.hasCan(kCardA));
    EXPECT_FALSE(c.hasMrz(kCardA));
}

TEST(CredentialCache, InvalidateOneCardLeavesOthers)
{
    CredentialCache c;
    c.putCan(kCardA, Secret{"AAAAAA"});
    c.putCan(kCardB, Secret{"BBBBBB"});

    c.invalidate(kCardA);

    EXPECT_FALSE(c.hasCan(kCardA));
    EXPECT_TRUE(c.hasCan(kCardB));
    EXPECT_EQ(c.getCan(kCardB)->view(), "BBBBBB");
}

TEST(CredentialCache, ClearWipesEverything)
{
    CredentialCache c;
    c.putCan(kCardA, Secret{"AAAAAA"});
    c.putMrz(kCardA, Secret{"AMRZ"});
    c.putCan(kCardB, Secret{"BBBBBB"});

    c.clear();

    EXPECT_FALSE(c.hasCan(kCardA));
    EXPECT_FALSE(c.hasMrz(kCardA));
    EXPECT_FALSE(c.hasCan(kCardB));
}

TEST(CredentialCache, EmptyKeyIsValidKey)
{
    // Empty string is a degenerate but valid std::map key — no card has
    // this fingerprint in practice, but the cache should not crash on it.
    CredentialCache c;
    c.putCan("", Secret{"x"});
    EXPECT_TRUE(c.hasCan(""));
    c.invalidate("");
    EXPECT_FALSE(c.hasCan(""));
}

// Concurrency stress: in production the accessors run BOTH from the monitor
// thread (under the agent state mutex) AND from per-reader worker jthreads
// (which do not hold it). Without the cache's internal mutex this is a data
// race on a std::map holding Secure::String secrets (UB). This test pounds
// the same keys from many threads doing get/put/has/invalidate concurrently;
// it must complete without crashing/hanging and leave the map in a coherent
// state. Run under TSan (if a sanitizer config is configured) it also flags
// the underlying read/write race directly.
TEST(CredentialCache, ConcurrentGetPutInvalidateStress)
{
    CredentialCache c;
    constexpr int kThreads = 8;
    constexpr int kIters = 20000;

    // A small fixed key space so threads genuinely contend on the same
    // std::map nodes rather than each owning a disjoint key.
    const std::string keys[] = {"k0", "k1", "k2", "k3"};
    constexpr int kKeyCount = 4;

    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < kIters; ++i) {
                const auto& key = keys[(t + i) % kKeyCount];
                switch ((t + i) % 5) {
                case 0:
                    c.putCan(key, Secret{"123456"});
                    break;
                case 1:
                    c.putMrz(key, Secret{"MRZ-DATA"});
                    break;
                case 2:
                    (void)c.getCan(key);
                    break;
                case 3:
                    (void)c.hasMrz(key);
                    break;
                case 4:
                    c.invalidate(key);
                    break;
                }
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (auto& th : threads) {
        th.join();
    }

    // Surviving entries (if any) must be internally coherent: a present
    // CAN/MRZ round-trips to the value the writers stored. No torn reads.
    for (const auto& key : keys) {
        if (auto can = c.getCan(key)) {
            EXPECT_EQ(can->view(), "123456");
        }
        if (auto mrz = c.getMrz(key)) {
            EXPECT_EQ(mrz->view(), "MRZ-DATA");
        }
    }

    // The cache is still fully functional after the storm.
    c.clear();
    c.putCan("after", Secret{"999999"});
    ASSERT_TRUE(c.hasCan("after"));
    EXPECT_EQ(c.getCan("after")->view(), "999999");
}
