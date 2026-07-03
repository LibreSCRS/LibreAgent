// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure-logic exercise of the per-level expired-cert gate. LmSigner computes
// `expired` from the cert's notAfter on hardware; this pins the policy decision
// itself (the part that decides block vs proceed vs proceed-allowing-expired).
#include <LibreSCRS/Agent/operations/SignGate.h>
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <gtest/gtest.h>

using LibreSCRS::Agent::Operations::evaluateExpiredGate;
using LibreSCRS::Agent::Operations::ExpiredGate;
namespace sp = LibreSCRS::Agent::Operations::SignatureParams;

TEST(SignExpiredGate, NotExpiredAlwaysProceeds)
{
    EXPECT_EQ(evaluateExpiredGate(false, false, false), ExpiredGate::Proceed);
    EXPECT_EQ(evaluateExpiredGate(false, false, true), ExpiredGate::Proceed);
    EXPECT_EQ(evaluateExpiredGate(false, true, false), ExpiredGate::Proceed);
    EXPECT_EQ(evaluateExpiredGate(false, true, true), ExpiredGate::Proceed);
}

TEST(SignExpiredGate, BbExpiredNeedsExplicitConsent)
{
    EXPECT_EQ(evaluateExpiredGate(true, /*qualifiedFamily=*/false, /*allowExpired=*/false), ExpiredGate::Blocked);
    EXPECT_EQ(evaluateExpiredGate(true, /*qualifiedFamily=*/false, /*allowExpired=*/true),
              ExpiredGate::ProceedAllowingExpired);
}

TEST(SignExpiredGate, QualifiedFamilyExpiredAlwaysBlockedNeverHonoursAllowExpired)
{
    // A timestamp/LTV over an expired cert is internally inconsistent: the
    // qualified family must NEVER forward allowExpired, even when the client set it.
    EXPECT_EQ(evaluateExpiredGate(true, /*qualifiedFamily=*/true, /*allowExpired=*/false), ExpiredGate::Blocked);
    EXPECT_EQ(evaluateExpiredGate(true, /*qualifiedFamily=*/true, /*allowExpired=*/true), ExpiredGate::Blocked);
}

TEST(SignExpiredGate, BtComposesWithTheQualifiedClassifierToHardBlockExpired)
{
    // Pin the wiring the production LmSigner uses: the qualifiedFamily input is
    // derived from isQualifiedSignLevel(level). For b-t an expired cert is a
    // hard block even when the client set allowExpired.
    EXPECT_EQ(evaluateExpiredGate(/*expired=*/true, sp::isQualifiedSignLevel("b-t"), /*allowExpired=*/true),
              ExpiredGate::Blocked);
    EXPECT_EQ(evaluateExpiredGate(/*expired=*/true, sp::isQualifiedSignLevel("b-t"), /*allowExpired=*/false),
              ExpiredGate::Blocked);
    // The same classifier keeps b-b on the consent-honouring path.
    EXPECT_EQ(evaluateExpiredGate(/*expired=*/true, sp::isQualifiedSignLevel("b-b"), /*allowExpired=*/true),
              ExpiredGate::ProceedAllowingExpired);
}
