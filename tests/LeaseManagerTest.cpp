// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <LibreSCRS/Agent/Identity.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>

using namespace LibreSCRS::Agent::Pkcs11;
using LibreSCRS::Agent::CallerToken;
using LibreSCRS::Agent::ObjectId;
using namespace std::chrono;

namespace {
LeaseConfig cfg()
{
    return LeaseConfig{.idleTimeout = minutes(10), .maxLifetime = hours(8)};
}
// (caller, card) key helpers — caller is an opaque CallerToken, card an opaque
// per-insertion ObjectId (distinct integers stand in for distinct cards).
LeaseKey k(const char* caller, std::uint64_t card)
{
    return LeaseKey{CallerToken{caller}, ObjectId{card}};
}
} // namespace

TEST(LeaseManager, GrantThenActiveWithinIdleWindow)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    EXPECT_TRUE(m.isActive(k("app", 1), now + minutes(5)));
}

TEST(LeaseManager, IdleTimeoutExpires)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    EXPECT_FALSE(m.isActive(k("app", 1), now + minutes(11)));
}

TEST(LeaseManager, TouchResetsIdleClock)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    EXPECT_TRUE(m.touch(k("app", 1), now + minutes(9)));     // still active → bumps last-use
    EXPECT_TRUE(m.isActive(k("app", 1), now + minutes(18))); // 9+9 < idle from last touch
}

TEST(LeaseManager, MaxLifetimeCapsEvenWhenBusy)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    // Kept busy every 5 min, but max-lifetime 8h still caps it.
    for (int i = 1; i <= 96; ++i) {
        // touch() is [[nodiscard]]; the keep-busy intent discards the result.
        static_cast<void>(m.touch(k("app", 1), now + minutes(5 * i)));
    }
    EXPECT_FALSE(m.isActive(k("app", 1), now + hours(8) + minutes(1)));
}

TEST(LeaseManager, ScopedToCallerAndCard)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    EXPECT_FALSE(m.isActive(k("other", 1), now));
    EXPECT_FALSE(m.isActive(k("app", 2), now));
}

TEST(LeaseManager, RevokeOnLogout)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.revoke(k("app", 1));
    EXPECT_FALSE(m.isActive(k("app", 1), now));
}

TEST(LeaseManager, RevokeCardDropsAllCallers)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("appA", 1), now);
    m.grant(k("appB", 1), now);
    m.revokeCard(ObjectId{1});
    EXPECT_FALSE(m.isActive(k("appA", 1), now));
    EXPECT_FALSE(m.isActive(k("appB", 1), now));
}

TEST(LeaseManager, RevokeCallerDropsAllCards)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.grant(k("app", 2), now);
    m.revokeCaller(CallerToken{"app"});
    EXPECT_FALSE(m.isActive(k("app", 1), now));
    EXPECT_FALSE(m.isActive(k("app", 2), now));
}

// --- PIN-as-consent verified state ------------------------------------

TEST(LeaseManager, PinVerifiedStartsFalseAndAbsentLeaseIsFalse)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    EXPECT_FALSE(m.isPinVerified(k("app", 1))) << "no lease => not verified";
    m.grant(k("app", 1), now);
    EXPECT_FALSE(m.isPinVerified(k("app", 1))) << "a fresh grant is unverified";
}

TEST(LeaseManager, MarkThenIsPinVerified)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.markPinVerified(k("app", 1));
    EXPECT_TRUE(m.isPinVerified(k("app", 1)));
}

TEST(LeaseManager, MarkPinVerifiedOnAbsentLeaseIsNoOp)
{
    LeaseManager m{cfg()};
    m.markPinVerified(k("app", 1)); // no lease exists
    EXPECT_FALSE(m.isPinVerified(k("app", 1)));
}

TEST(LeaseManager, ReGrantResetsPinVerified)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.markPinVerified(k("app", 1));
    EXPECT_TRUE(m.isPinVerified(k("app", 1)));
    // A fresh Login (re-grant of an existing lease) is fresh consent.
    m.grant(k("app", 1), now + minutes(1));
    EXPECT_FALSE(m.isPinVerified(k("app", 1))) << "re-grant re-arms the verify";
}

TEST(LeaseManager, ClearPinVerifiedKeepsTheLease)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.markPinVerified(k("app", 1));
    m.clearPinVerified(k("app", 1));
    EXPECT_FALSE(m.isPinVerified(k("app", 1))) << "cleared => re-verify next op";
    EXPECT_TRUE(m.isActive(k("app", 1), now)) << "the lease itself survives the clear";
}

TEST(LeaseManager, ClearPinVerifiedOnAbsentLeaseIsNoOp)
{
    LeaseManager m{cfg()};
    m.clearPinVerified(k("app", 1)); // must not crash / create a lease
    EXPECT_FALSE(m.isPinVerified(k("app", 1)));
}

TEST(LeaseManager, IdleReapClearsPinVerified)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.markPinVerified(k("app", 1));
    // isActive past the idle window reaps the lease (erases the entry).
    EXPECT_FALSE(m.isActive(k("app", 1), now + minutes(11)));
    // A new grant after the reap is unverified (the old verified flag is gone).
    m.grant(k("app", 1), now + minutes(11));
    EXPECT_FALSE(m.isPinVerified(k("app", 1)));
}

TEST(LeaseManager, RevokeClearsPinVerified)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.markPinVerified(k("app", 1));
    m.revoke(k("app", 1));
    EXPECT_FALSE(m.isPinVerified(k("app", 1)));
    m.grant(k("app", 1), now);
    EXPECT_FALSE(m.isPinVerified(k("app", 1))) << "post-revoke grant is unverified";
}

TEST(LeaseManager, RevokeCardClearsPinVerified)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("appA", 1), now);
    m.markPinVerified(k("appA", 1));
    m.revokeCard(ObjectId{1});
    EXPECT_FALSE(m.isPinVerified(k("appA", 1)));
}

TEST(LeaseManager, RevokeCallerClearsPinVerified)
{
    steady_clock::time_point now{};
    LeaseManager m{cfg()};
    m.grant(k("app", 1), now);
    m.markPinVerified(k("app", 1));
    m.revokeCaller(CallerToken{"app"});
    EXPECT_FALSE(m.isPinVerified(k("app", 1)));
}
