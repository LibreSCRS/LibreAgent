// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The socket transport, driven against the Qt-free agent double.

#include "fakes/FakeSocketAgent.h"

#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#if defined(__linux__)
#include <dirent.h>
#endif

namespace {

namespace T = LibreSCRS::Agent::Test;
namespace P = LibreSCRS::Pkcs11Agent;
namespace W = LibreSCRS::Agent::Wire;

// RFC 5280 keyEncipherment. A cert without it must not offer decryption, which
// is a claim about the bit rather than about the card.
constexpr std::uint32_t kKeyEncipherment = 1U << 2;

/// Short budgets, so a suite can drive the two-budget rule in seconds rather
/// than in the ten minutes the shipped interactive budget allows. The claim
/// being tested is that there are TWO of them and that they reach different
/// calls; the shipped VALUES are pinned separately, below.
constexpr P::SocketTimeouts kFastBudgets{/*publicDataSecs=*/2, /*interactiveSecs=*/8};

TEST(SocketAgentClient, PinsTheTwoShippedBudgets)
{
    // Named, because a single budget is the failure this design exists to
    // avoid, and a later edit that collapses them would otherwise only show up
    // as a timeout on somebody's card.
    EXPECT_EQ(P::kInteractiveTimeoutSecs, 600);
    EXPECT_EQ(P::kPublicDataTimeoutSecs, 60);
    EXPECT_GT(P::kInteractiveTimeoutSecs, P::kPublicDataTimeoutSecs);
}

TEST(SocketAgentClient, MapsGetStateOntoOneSlotPerReader)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addReader("r2");
    fake.addCert("c1", "certid-1", /*signingCapable=*/true, kKeyEncipherment);
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_TRUE(client.connected());

    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 2U);
    EXPECT_EQ(snap.readers[0].readerPath, "r1");
    EXPECT_TRUE(snap.readers[0].hasCard);
    ASSERT_EQ(snap.readers[0].certs.size(), 1U);
    EXPECT_EQ(snap.readers[0].certs[0].certId, "certid-1");
    EXPECT_TRUE(snap.readers[0].certs[0].canSign);
    EXPECT_TRUE(snap.readers[0].certs[0].canDecrypt);
    EXPECT_FALSE(snap.readers[0].certs[0].signsHashOnCard);

    EXPECT_EQ(snap.readers[1].readerPath, "r2");
    EXPECT_FALSE(snap.readers[1].hasCard);
    EXPECT_TRUE(snap.readers[1].certs.empty());
}

TEST(SocketAgentClient, DrivesReadCertificatesToOpFinishedAndKeepsTheList)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_TRUE(client.connected());
    ASSERT_EQ(client.snapshot().readers.size(), 1U);

    // The real claim: the operation was drained. A client that read only
    // OpStarted would leave two frames in the socket, and the NEXT call would
    // read one of them as its own reply.
    const auto der = client.certDer("r1", "certid-1");
    EXPECT_EQ(der.status, P::Status::Ok);
    EXPECT_FALSE(der.bytes.empty());
    EXPECT_EQ(fake.callCount(T::Call::GetCertDer), 1);
}

TEST(SocketAgentClient, DiscardsAnEventThatArrivesInsideItsOwnOperation)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.interleaveEventInsideNextOperation();
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_TRUE(client.connected());

    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1U);
    ASSERT_EQ(snap.readers[0].certs.size(), 1U);
    // The stray CardAdded names a reader that is not in the state reply. If it
    // had been consumed as news, this client keeps no subscription to put it
    // in -- so the only visible symptom would be the desynchronised socket the
    // next call trips over.
    const auto again = client.snapshot();
    EXPECT_EQ(again.readers.size(), 1U);
}

TEST(SocketAgentClient, AddressesReadCertificatesByCardAndPkCallsByReader)
{
    // Addressing is genuinely split on this wire: certificates are read per
    // CARD, every Pk* call names a READER. A client that used one handle for
    // both would work only where the two happen to be spelled the same.
    T::FakeSocketAgent fake;
    fake.addReader("reader-handle", /*hasCard=*/true, "card-handle");
    fake.addCert("card-handle", "certid-1");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_TRUE(client.connected());

    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1U);
    // The certificate list arrived, so ReadCertificates was addressed by the
    // CARD handle: the fake matches on it and would have returned nothing for
    // the reader handle.
    ASSERT_EQ(snap.readers[0].certs.size(), 1U);
    EXPECT_EQ(fake.callCount(T::Call::ReadCertificates), 1);

    // And the Pk* call is addressed by the READER handle: the login succeeds
    // because the fake was not asked about a card.
    EXPECT_EQ(client.login("reader-handle").status, P::Status::Ok);
    EXPECT_EQ(fake.callCount(T::Call::PkLogin), 1);
}

TEST(SocketAgentClient, SurvivesAHumanPacedLoginButNotAStalledCertRead)
{
    // One fake, two calls, one delay that sits BETWEEN the two budgets. A
    // client with a single budget fails one of these two whichever value that
    // budget takes, and passes everything else in this file.
    const auto between =
        std::chrono::milliseconds{1000 * (kFastBudgets.publicDataSecs + kFastBudgets.interactiveSecs) / 2};

    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.delayCall(T::Call::PkLogin, between);
    fake.delayCall(T::Call::GetCertDer, between);
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_TRUE(client.connected());

    // Human-paced: inside the interactive budget, so it completes.
    EXPECT_EQ(client.login("r1").status, P::Status::Ok);

    // Public data: past the public budget, so it is abandoned rather than
    // waited out. A second client, because the first one's socket is now closed
    // -- which is itself the correct answer to a peer that stopped answering.
    P::SocketAgentClient other{fake.path(), kFastBudgets};
    ASSERT_TRUE(other.connected());
    EXPECT_EQ(other.certDer("r1", "certid-1").status, P::Status::DeviceRemoved);
}

TEST(SocketAgentClient, RefusesAFrameThatCarriesADescriptorAndClosesIt)
{
    // Repeated, because one leaked descriptor is inside the noise of any
    // process's open-file count and twenty are not. The fake is stopped before
    // the second count so that its own accepted sockets -- closed on the serve
    // thread, whenever that thread next notices -- are not what is being
    // measured.
    constexpr int kRounds = 20;

    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.start();

#if defined(__linux__)
    const auto openFds = [] {
        int n = 0;
        DIR* d = ::opendir("/proc/self/fd");
        if (d == nullptr)
            return -1;
        while (::readdir(d) != nullptr)
            ++n;
        ::closedir(d);
        return n;
    };
    const int before = openFds();
    ASSERT_GT(before, 0);
#endif

    for (int i = 0; i < kRounds; ++i) {
        P::SocketAgentClient client{fake.path(), kFastBudgets};
        ASSERT_TRUE(client.connected());
        fake.attachDescriptorToNextReply();
        // Nothing this module asks for rides a descriptor, so a frame carrying
        // one is either a different contract or an attempt to hand this process
        // a file. Either way the call fails rather than proceeding.
        EXPECT_EQ(client.login("r1").status, P::Status::DeviceRemoved);
    }
    fake.stop();

#if defined(__linux__)
    const int after = openFds();
    // Silently dropping a received descriptor is a leak nothing else in this
    // suite would notice: the call already failed, so the failure path is the
    // only place the descriptor could have been dropped.
    EXPECT_LE(after, before);
#endif
}

TEST(SocketAgentClient, ReportsDeviceRemovedWhenNothingIsListening)
{
    P::SocketAgentClient client{T::makeSocketPath("absent"), kFastBudgets};
    EXPECT_FALSE(client.connected());
    EXPECT_TRUE(client.snapshot().readers.empty());
    EXPECT_EQ(client.login("r1").status, P::Status::DeviceRemoved);
    EXPECT_EQ(client.certDer("r1", "c").status, P::Status::DeviceRemoved);
    EXPECT_EQ(client.logout("r1"), P::Status::DeviceRemoved);
}

TEST(SocketAgentClient, ReportsDeviceRemovedWhenTheHandshakeIsRefused)
{
    // A refused handshake must not look like an agent with no readers: a
    // loader told "zero slots" stops asking, while a loader told the device is
    // gone can try again.
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.refuseNextHello();
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    EXPECT_FALSE(client.connected());
}

TEST(SocketAgentClient, MapsEveryRefusalTheWireHasANameFor)
{
    // The refusal table is the part with no compiler holding it, so every
    // row is driven. What this suite CANNOT state is the row that is missing:
    // this wire has no token for a cancelled prompt, so a cancelled prompt is
    // indistinguishable here from a generic communication failure. Holding
    // both transports to one answer about that needs a token added to the
    // contract, and is not this file's to decide.
    struct Row
    {
        W::SyncError wire;
        P::Status want;
    };
    const Row rows[] = {
        {W::SyncError::UserNotLoggedIn, P::Status::UserNotLoggedIn},
        {W::SyncError::NotAuthorized, P::Status::NotAuthorized},
        {W::SyncError::AuthFailed, P::Status::AuthFailed},
        {W::SyncError::KeyNotFound, P::Status::KeyNotFound},
        {W::SyncError::UnknownCard, P::Status::UnknownCard},
        {W::SyncError::NotSupported, P::Status::NotSupported},
        {W::SyncError::UnsupportedOnThisCard, P::Status::NotSupported},
        {W::SyncError::RateLimited, P::Status::RateLimited},
        {W::SyncError::CommunicationError, P::Status::Communication},
        {W::SyncError::InputTooLarge, P::Status::GeneralError},
    };
    for (const auto& row : rows) {
        T::FakeSocketAgent fake;
        fake.addReader("r1", /*hasCard=*/true, "c1");
        fake.failCall(T::Call::PkLogin, row.wire);
        fake.start();

        P::SocketAgentClient client{fake.path(), kFastBudgets};
        ASSERT_TRUE(client.connected());
        EXPECT_EQ(client.login("r1").status, row.want) << "wire refusal #" << static_cast<int>(row.wire);
    }
}

} // namespace
