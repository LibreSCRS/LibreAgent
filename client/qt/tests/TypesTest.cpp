// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// FdHandle's move-only RAII contract (close-on-destroy, move transfer,
// release-without-closing) plus lightweight construction/default-value
// checks for the plain aggregates in Types.h/SignOptions.h/CallError.h.
// Token<->enum round-trips live in TokenMapTest.cpp -- TokenMap is an
// internal TU, not part of the public value-type API this file covers.
#include <LibreSCRS/AgentClient/CallError.h>
#include <LibreSCRS/AgentClient/ClientTimeouts.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <utility>

using namespace LibreSCRS::AgentClient;

namespace {

// Returns the read end of a fresh pipe (closing the write end immediately --
// these tests only need one live fd whose closedness is independently
// checkable via fcntl(F_GETFD)). -1 on failure.
int makeTestFd()
{
    int fds[2];
    if (::pipe(fds) != 0) {
        return -1;
    }
    ::close(fds[1]);
    return fds[0];
}

// True iff `fd` is currently an open descriptor in this process, checked via
// fcntl(F_GETFD) -- succeeds for any open fd, fails with EBADF for a closed
// or never-opened one. This is the proof a FdHandle's destructor/move-assign
// genuinely called close(2) on the OS descriptor, not merely forgot its own
// copy of the integer.
bool fdIsOpen(int fd)
{
    return ::fcntl(fd, F_GETFD) != -1;
}

} // namespace

// ---- FdHandle ---------------------------------------------------------

TEST(FdHandle, DefaultConstructedIsInvalid)
{
    FdHandle h;
    EXPECT_FALSE(h.valid());
    EXPECT_EQ(h.get(), -1);
}

TEST(FdHandle, ExplicitFromIntIsValidAndReturnsTheSameFd)
{
    const int fd = makeTestFd();
    ASSERT_GE(fd, 0);
    FdHandle h(fd);
    EXPECT_TRUE(h.valid());
    EXPECT_EQ(h.get(), fd);
    ::close(h.release()); // this test, not FdHandle, owns fd from here on
}

TEST(FdHandle, DestructorClosesTheUnderlyingFd)
{
    const int fd = makeTestFd();
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(fdIsOpen(fd));
    {
        FdHandle h(fd);
    } // h destructs here
    EXPECT_FALSE(fdIsOpen(fd));
    EXPECT_EQ(errno, EBADF);
}

TEST(FdHandle, MoveConstructionTransfersOwnershipAndInvalidatesTheSource)
{
    const int fd = makeTestFd();
    ASSERT_GE(fd, 0);
    FdHandle a(fd);
    FdHandle b(std::move(a));

    EXPECT_FALSE(a.valid());
    EXPECT_EQ(a.get(), -1);
    EXPECT_TRUE(b.valid());
    EXPECT_EQ(b.get(), fd);
    // Ownership moved, not duplicated: the fd must still be open (b owns
    // it now -- a's destructor, having been left invalid, must not close it).
    EXPECT_TRUE(fdIsOpen(fd));
}

TEST(FdHandle, MoveConstructionFromAnInvalidHandleLeavesBothInvalid)
{
    FdHandle a;
    FdHandle b(std::move(a));
    EXPECT_FALSE(a.valid());
    EXPECT_FALSE(b.valid());
}

TEST(FdHandle, MoveAssignmentClosesThePriorFdAndTransfersOwnership)
{
    const int fdA = makeTestFd();
    const int fdB = makeTestFd();
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    FdHandle a(fdA);
    FdHandle b(fdB);

    a = std::move(b);

    EXPECT_EQ(a.get(), fdB);
    EXPECT_FALSE(b.valid());
    // a's ORIGINAL fd (fdA) must have been closed by the move-assignment,
    // not merely overwritten/leaked.
    EXPECT_FALSE(fdIsOpen(fdA));
    // a's new fd (fdB, taken over from b) must still be open.
    EXPECT_TRUE(fdIsOpen(fdB));
}

TEST(FdHandle, SelfMoveAssignmentIsANoOpAndDoesNotCloseTheFd)
{
    const int fd = makeTestFd();
    ASSERT_GE(fd, 0);
    FdHandle a(fd);

    FdHandle& aRef = a; // avoids a `-Wself-move` diagnostic on `a = std::move(a)`
    a = std::move(aRef);

    EXPECT_TRUE(a.valid());
    EXPECT_EQ(a.get(), fd);
    EXPECT_TRUE(fdIsOpen(fd));
}

TEST(FdHandle, ReleaseRelinquishesOwnershipWithoutClosingTheFd)
{
    const int fd = makeTestFd();
    ASSERT_GE(fd, 0);
    FdHandle h(fd);

    const int released = h.release();

    EXPECT_EQ(released, fd);
    EXPECT_FALSE(h.valid());
    // release() must NOT close the fd -- the caller now owns it.
    EXPECT_TRUE(fdIsOpen(fd));
    ::close(fd); // this test, not FdHandle, now owns it
}

TEST(FdHandle, ReleaseOnAnInvalidHandleReturnsMinusOne)
{
    FdHandle h;
    EXPECT_EQ(h.release(), -1);
    EXPECT_FALSE(h.valid());
}

// ---- plain value-type aggregates --------------------------------------

TEST(SignOptionsValueType, DefaultsMatchTheAgentsInvisibleEnvelopedDefaultAndDeferTheLevel)
{
    SignOptions opts;
    EXPECT_EQ(opts.format, SignatureFormat::PAdES);
    // The level is the ONE default that is not a value of its own: it defers to
    // whatever the agent is configured for. A client that wants the baseline
    // has to say so.
    EXPECT_EQ(opts.level, SignatureLevel::Auto);
    EXPECT_EQ(opts.packaging, Packaging::Enveloped);
    EXPECT_TRUE(opts.visualSignature.isEmpty());
    EXPECT_TRUE(opts.tsaUrl.isEmpty());
    EXPECT_TRUE(opts.displayName.isEmpty());
    EXPECT_TRUE(opts.extra.isEmpty());
}

TEST(PhotoItemValueType, IsMoveOnlyAndCarriesItsKeyAndFdTogether)
{
    const int fd = makeTestFd();
    ASSERT_GE(fd, 0);
    PhotoItem item{QStringLiteral("face"), FdHandle(fd)};
    EXPECT_EQ(item.key, QStringLiteral("face"));
    EXPECT_TRUE(item.fd.valid());
    EXPECT_TRUE(item.extra.isEmpty());

    PhotoItem moved(std::move(item));
    EXPECT_EQ(moved.key, QStringLiteral("face"));
    EXPECT_TRUE(moved.fd.valid());
    EXPECT_FALSE(item.fd.valid()); // moved-from
}

TEST(CertificateInfoValueType, DefaultsAreUnknownTrustAndNotSigningCapable)
{
    CertificateInfo info;
    EXPECT_FALSE(info.signingCapable);
    EXPECT_EQ(info.trust, TrustStatus::Unknown);
    EXPECT_TRUE(info.securityStatus.isEmpty());
    EXPECT_TRUE(info.extra.isEmpty());
}

TEST(FieldValueType, DefaultConstructionLeavesExtraEmpty)
{
    Field f;
    EXPECT_TRUE(f.extra.isEmpty());
    EXPECT_TRUE(f.detail.isNull());
}

TEST(FieldGroupValueType, DefaultConstructionLeavesFieldsAndExtraEmpty)
{
    FieldGroup g;
    EXPECT_TRUE(g.fields.isEmpty());
    EXPECT_TRUE(g.extra.isEmpty());
}

TEST(CallErrorValueType, HasTheDocumentedSevenEnumerators)
{
    // Not a wire-frozen value set (CallError is local/client-side, never
    // serialized) -- this just pins the documented shape so an accidental
    // reorder/removal is caught here rather than downstream.
    EXPECT_EQ(static_cast<int>(CallError::None), 0);
    EXPECT_EQ(static_cast<int>(CallError::AgentUnavailable), 1);
    EXPECT_EQ(static_cast<int>(CallError::Timeout), 2);
    EXPECT_EQ(static_cast<int>(CallError::AccessDenied), 3);
    EXPECT_EQ(static_cast<int>(CallError::InvalidArguments), 4);
    EXPECT_EQ(static_cast<int>(CallError::TransportFailure), 5);
    EXPECT_EQ(static_cast<int>(CallError::ProtocolError), 6);
}

TEST(ClientTimeoutsValueType, HasTheDocumentedMillisecondBudgets)
{
    EXPECT_EQ(kHandshakeTimeoutMs, 1000);
    EXPECT_EQ(kDefaultCallTimeoutMs, 3000);
    EXPECT_EQ(kLongOperationTimeoutMs, 35000);
    // Handshake budget must never exceed the ordinary call budget, which
    // must never exceed the long-operation budget -- catches the three
    // constants being edited out of their intended relative order.
    EXPECT_LT(kHandshakeTimeoutMs, kDefaultCallTimeoutMs);
    EXPECT_LT(kDefaultCallTimeoutMs, kLongOperationTimeoutMs);
}
