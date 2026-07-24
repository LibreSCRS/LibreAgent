// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// DerListenerRegistry is the extracted, transport-neutral fix for a real
// hang found in DBusTransport's certificateDer plumbing: a DER op cancelled
// mid-flight, followed by a second op whose AgentOperation::Private happens
// to reuse the SAME heap address (hence the SAME DerListener* identity) as
// the cancelled one, used to let the first op's late/stale reply silently
// steal-and-drop the second op's registration — the second op's finished()
// then never fired (permanent hang for its consumer). This suite drives the
// registry directly (no D-Bus, no event loop, no QCoreApplication needed):
// the cheapest layer where "remove-by-identity" vs "remove-by-token" is
// directly assertable. Forcing the actual heap-reuse condition deterministic
// enough for a CI test isn't feasible (malloc reuse is not part of any
// contract); this instead pins the OBSERVABLE contract the fix guarantees —
// a registration surviving cancel+reuse is looked up and removed strictly by
// its own token, so an unrelated registration sharing the same listener
// pointer is never touched.

#include "DerListenerRegistry.h"

#include <gtest/gtest.h>

#include <QSet>

using namespace LibreSCRS::AgentClient;

namespace {

/// A minimal DerListener double — only identity matters to this suite; no
/// test here ever calls onCertificateDer.
class DummyDerListener : public TransportSeam::DerListener
{
public:
    void onCertificateDer(quint64 /*token*/, DerOutcome /*outcome*/) override {}
};

} // namespace

TEST(DerListenerRegistry, AddReturnsDistinctIncreasingTokens)
{
    DerListenerRegistry registry;
    DummyDerListener listener;
    const quint64 tokenA = registry.add(&listener);
    const quint64 tokenB = registry.add(&listener);
    EXPECT_NE(tokenA, tokenB);
    EXPECT_GT(tokenB, tokenA);
}

TEST(DerListenerRegistry, TakeIfPresentDeliversOnceThenIsEmpty)
{
    DerListenerRegistry registry;
    DummyDerListener listener;
    const quint64 token = registry.add(&listener);

    EXPECT_EQ(registry.takeIfPresent(token), &listener);
    // Consumed: a duplicate/second reply for the same token is a no-op.
    EXPECT_EQ(registry.takeIfPresent(token), nullptr);
}

TEST(DerListenerRegistry, UnknownTokenYieldsNullptr)
{
    DerListenerRegistry registry;
    EXPECT_EQ(registry.takeIfPresent(12345), nullptr);
}

TEST(DerListenerRegistry, CancelRemovesOnlyItsOwnTokenNeverASiblingWithTheSamePointer)
{
    DerListenerRegistry registry;
    DummyDerListener listener; // deliberately the SAME pointer for both registrations
    const quint64 tokenA = registry.add(&listener);
    const quint64 tokenB = registry.add(&listener);

    registry.cancel(tokenA);

    EXPECT_EQ(registry.takeIfPresent(tokenA), nullptr);   // cancelled: gone
    EXPECT_EQ(registry.takeIfPresent(tokenB), &listener); // sibling, untouched
}

// ---- the regression case: cancel + pointer reuse must never lose the second delivery ----

TEST(DerListenerRegistry, CancelledOpsStaleReplyNeverStealsAReusedPointersSecondRegistration)
{
    // Simulates the exact reported race, without needing real heap-address
    // recycling: op A is registered, cancelled BEFORE its reply lands, and op
    // B is then minted reusing the identical listener pointer (standing in
    // for a Private object freed and immediately reallocated at the same
    // address) — the scenario a plain pointer-keyed set cannot disambiguate.
    DerListenerRegistry registry;
    DummyDerListener sharedPointer;

    const quint64 tokenA = registry.add(&sharedPointer); // op A starts
    registry.cancel(tokenA);                             // op A cancelled mid-flight
    const quint64 tokenB = registry.add(&sharedPointer); // op B reuses the SAME pointer

    // Op A's reply lambda fires late (captured tokenA): must be a no-op, and
    // — the crux of the bug — must NOT touch op B's registration.
    EXPECT_EQ(registry.takeIfPresent(tokenA), nullptr);

    // Op B's own reply must still be delivered.
    EXPECT_EQ(registry.takeIfPresent(tokenB), &sharedPointer);
    EXPECT_EQ(registry.takeIfPresent(tokenB), nullptr); // consumed, idempotent
}

// ---- documents the bug this registry replaces: the pre-fix mechanism ----

namespace {

/// A byte-for-byte structural mirror of DBusTransport's PRE-FIX bookkeeping
/// (`QSet<DerListener*> m_derListeners`, reply lambda: `if
/// (!m_derListeners.remove(listener)) return; ... listener->onCertificateDer(...)`,
/// cancel: `m_derListeners.remove(listener)`). Not production code — kept
/// here ONLY to demonstrate, under the exact same call sequence as the
/// regression test above, that the identity-keyed design actually drops the
/// second delivery. This is the "prove it fails" side of the fix: run this
/// mechanism through the scenario and it fails the assertion the new
/// registry passes.
class LegacyPointerKeyedDerListeners
{
public:
    void add(TransportSeam::DerListener* listener)
    {
        m_listeners.insert(listener);
    }
    void cancel(TransportSeam::DerListener* listener)
    {
        m_listeners.remove(listener);
    }
    /// Mirrors the old reply lambda: true if this reply's listener was still
    /// registered (and is now consumed) — false ("cancelled, the operation is
    /// gone") otherwise.
    [[nodiscard]] bool tryDeliver(TransportSeam::DerListener* listener)
    {
        return m_listeners.remove(listener);
    }

private:
    QSet<TransportSeam::DerListener*> m_listeners;
};

} // namespace

TEST(LegacyPointerKeyedDerListenersDemo, DropsTheSecondDeliveryAfterCancelAndPointerReuse)
{
    LegacyPointerKeyedDerListeners legacy;
    DummyDerListener sharedPointer;

    legacy.add(&sharedPointer);    // op A starts
    legacy.cancel(&sharedPointer); // op A cancelled mid-flight
    legacy.add(&sharedPointer);    // op B reuses the SAME pointer

    // Op A's stale reply lambda fires late: WRONGLY reports success (it finds
    // the pointer — now actually op B's registration — still present) and
    // would incorrectly deliver op B's outcome under op A's token.
    EXPECT_TRUE(legacy.tryDeliver(&sharedPointer)); // <- the bug: "succeeds", but steals op B's slot

    // Op B's OWN reply then finds nothing left to deliver: this is the
    // reported permanent hang (finished() never fires for op B).
    EXPECT_FALSE(legacy.tryDeliver(&sharedPointer));
}
