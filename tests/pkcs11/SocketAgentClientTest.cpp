// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The socket transport, driven against the Qt-free agent double.

#include "fakes/FakeSocketAgent.h"

#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>

#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

#include <fcntl.h>

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

// Two cards in two readers must read as two tokens: a loader keys a token on
// its label and serial, and two tokens that agree on both are one token to it.
// The label is the holder the signing certificate names, or the reader's name
// for a card with none; the serial is the card handle's tail.
TEST(SocketAgentClient, NamesEachSeatedCardsTokenApart)
{
    T::FakeSocketAgent fake;
    fake.addReader("obj/1", /*hasCard=*/true, "obj/3");
    fake.addReader("obj/2", /*hasCard=*/true, "obj/4");
    fake.addReader("obj/6", /*hasCard=*/true, "obj/7");
    fake.addReader("obj/5");
    fake.setReaderName("obj/6", "Reader Three");
    fake.addCert("obj/3", "cert-1", /*signingCapable=*/true, kKeyEncipherment, "Holder One");
    fake.addCert("obj/4", "cert-2", /*signingCapable=*/true, kKeyEncipherment, "Holder Two");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 4U);

    EXPECT_EQ(snap.readers[0].tokenLabel, "Holder One");
    EXPECT_EQ(snap.readers[0].tokenSerial, "3");
    EXPECT_EQ(snap.readers[1].tokenLabel, "Holder Two");
    EXPECT_EQ(snap.readers[1].tokenSerial, "4");
    EXPECT_EQ(snap.readers[2].tokenLabel, "Reader Three") << "no certificate: the reader names the token";
    EXPECT_EQ(snap.readers[2].tokenSerial, "7");

    EXPECT_TRUE(snap.readers[3].tokenSerial.empty()) << "an empty reader has no token to name";
}

// Every reader, seated or not, carries the name the agent reports for it, and
// keeps the handle as the key calls are addressed by.
TEST(SocketAgentClient, CarriesEachReadersName)
{
    T::FakeSocketAgent fake;
    fake.addReader("obj/1", /*hasCard=*/true, "obj/3");
    fake.addReader("obj/2", "Empty Reader");
    fake.setReaderName("obj/1", "Seated Reader");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 2U);
    EXPECT_EQ(snap.readers[0].readerName, "Seated Reader");
    EXPECT_EQ(snap.readers[0].readerPath, "obj/1");
    EXPECT_EQ(snap.readers[1].readerName, "Empty Reader");
    EXPECT_EQ(snap.readers[1].readerPath, "obj/2");
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

// An unknown request tag makes an agent drop the connection, so a question an
// agent's Hello does not offer is never sent at all.
TEST(SocketAgentClient, ALoginStateIsNotAskedOfAnAgentThatDoesNotOfferIt)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.setFeatures({"credentials"});
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_EQ(client.login("r1").status, P::Status::Ok);
    EXPECT_EQ(client.loginActive("r1"), std::nullopt);
    EXPECT_EQ(fake.callCount(T::Call::PkLoginState), 0);
}

// NSS asks about its login from any thread, also while a PIN prompt holds the
// one connection. The answer then is "no answer", at once -- never a wait for
// the human.
TEST(SocketAgentClient, ALoginStateNeverWaitsForABusyTransport)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.delayCall(T::Call::PkLogin, std::chrono::seconds{2});
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_TRUE(client.connected());
    std::thread prompt([&client] { (void)client.login("r1"); });
    std::this_thread::sleep_for(std::chrono::milliseconds{200});
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(client.loginActive("r1"), std::nullopt);
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::milliseconds{200});
    prompt.join();
    EXPECT_EQ(client.loginActive("r1"), std::optional<bool>{true}) << "asked again once the socket is free";
}

// An agent that takes the question but does not answer holds the loader for the
// login-state budget only -- seconds, not the minute public data may take.
TEST(SocketAgentClient, ALoginStateIsGivenUpAfterItsOwnBudget)
{
    EXPECT_EQ(P::SocketTimeouts{}.loginStateSecs, 2);

    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.delayCall(T::Call::PkLoginState, std::chrono::seconds{4});
    fake.start();

    P::SocketAgentClient client{fake.path(), P::SocketTimeouts{/*publicDataSecs=*/30, /*interactiveSecs=*/30,
                                                               /*loginStateSecs=*/1}};
    ASSERT_EQ(client.login("r1").status, P::Status::Ok);
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(client.loginActive("r1"), std::nullopt);
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds{3});
}

// The agent drops a login on its own (idle, lifetime, the card left); the
// answer follows the agent, not what this client last did.
TEST(SocketAgentClient, ALoginTheAgentEndedReadsAsEnded)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_EQ(client.login("r1").status, P::Status::Ok);
    fake.expireLogin("r1");
    EXPECT_EQ(client.loginActive("r1"), std::optional<bool>{false});
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

TEST(SocketAgentClient, ARefusedHandshakeIsRetriedOnTheNextCall)
{
    // A refusal is an answer about that connection, not about the agent: the
    // loader keeps the module for the life of the process, and an agent that
    // restarted must be reachable again without the application restarting.
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.refuseNextHello();
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    EXPECT_FALSE(client.connected());

    EXPECT_EQ(client.snapshot().readers.size(), 1U);
    EXPECT_TRUE(client.connected());
}

TEST(SocketAgentClient, APeerCheckThatRefusesSendsNothingAndReportsDeviceRemoved)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.start();

    int seenFd = -1;
    P::SocketAgentClient client{fake.path(), kFastBudgets, [&seenFd](int fd) {
                                    seenFd = fd;
                                    return false;
                                }};
    EXPECT_FALSE(client.connected());
    EXPECT_GE(seenFd, 0);
    EXPECT_TRUE(client.snapshot().readers.empty());
    EXPECT_EQ(client.login("r1").status, P::Status::DeviceRemoved);
    EXPECT_EQ(
        client.signRaw("r1", "certid-1", LibreSCRS::Agent::Mechanism::RsaPkcs1Sign, std::vector<std::uint8_t>{1, 2, 3})
            .status,
        P::Status::DeviceRemoved);
    // Refused before the handshake: the peer never saw a request.
    EXPECT_EQ(fake.callCount(T::Call::Hello), 0);
    EXPECT_EQ(fake.callCount(T::Call::PkSignRaw), 0);
}

TEST(SocketAgentClient, APeerCheckThatThrowsIsARefusal)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets,
                                [](int) -> bool { throw std::runtime_error{"peer lookup failed"}; }};
    EXPECT_FALSE(client.connected());
    EXPECT_EQ(client.login("r1").status, P::Status::DeviceRemoved);
    EXPECT_EQ(fake.callCount(T::Call::Hello), 0);
}

TEST(SocketAgentClient, TheAgentSocketIsNotInheritedByAChildProcess)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.start();

    // The peer check is handed the connected descriptor, which is the one
    // place a test can see it.
    int fdFlags = -1;
    P::SocketAgentClient client{fake.path(), kFastBudgets, [&fdFlags](int fd) {
                                    fdFlags = ::fcntl(fd, F_GETFD);
                                    return true;
                                }};
    ASSERT_TRUE(client.connected());
    ASSERT_GE(fdFlags, 0);
    EXPECT_NE(fdFlags & FD_CLOEXEC, 0);
}

TEST(SocketAgentClient, APeerCheckRunsOnEveryConnectAndARefusalDoesNotStick)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.start();

    int calls = 0;
    bool allow = false;
    P::SocketAgentClient client{fake.path(), kFastBudgets, [&](int) {
                                    ++calls;
                                    return allow;
                                }};
    EXPECT_FALSE(client.connected());
    EXPECT_EQ(calls, 1);

    allow = true;
    EXPECT_EQ(client.snapshot().readers.size(), 1U);
    EXPECT_EQ(calls, 2);
    EXPECT_TRUE(client.connected());
}

TEST(SocketAgentClient, APeerCheckThatAcceptsLeavesTheCallsAsTheyWere)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "certid-1");
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets, [](int) { return true; }};
    ASSERT_TRUE(client.connected());
    EXPECT_EQ(client.snapshot().readers.size(), 1U);
    EXPECT_EQ(fake.callCount(T::Call::Hello), 1);
}

TEST(SocketAgentClient, MapsEveryRefusalTheWireHasANameFor)
{
    // The refusal table is the part with no compiler holding it, so every
    // row is driven, including the one this wire used to have no token for: a
    // dismissed prompt is its own answer here now rather than a generic
    // communication failure. That the OTHER transport agrees about it is not
    // asserted here -- that claim belongs to the suite both transports
    // instantiate, not to this transport's own file.
    struct Row
    {
        W::SyncError wire;
        P::Status want;
    };
    const Row rows[] = {
        {W::SyncError::UserNotLoggedIn, P::Status::UserNotLoggedIn},
        {W::SyncError::NotAuthorized, P::Status::NotAuthorized},
        {W::SyncError::AuthFailed, P::Status::AuthFailed},
        {W::SyncError::Cancelled, P::Status::Cancelled},
        {W::SyncError::KeyNotFound, P::Status::KeyNotFound},
        {W::SyncError::UnknownCard, P::Status::UnknownCard},
        {W::SyncError::NotSupported, P::Status::NotSupported},
        {W::SyncError::UnsupportedOnThisCard, P::Status::NotSupported},
        {W::SyncError::RateLimited, P::Status::RateLimited},
        {W::SyncError::CommunicationError, P::Status::Communication},
        {W::SyncError::InvalidRequest, P::Status::InvalidInput},
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

// The entry a key object is built from carries the agent's key facts: the
// card's CKA_ID (no more counter), the key's family and size, and no decrypt
// for an EC key whatever its keyUsage says.
TEST(SocketAgentClient, CarriesTheKeyFactsOfEachCertificate)
{
    namespace T = LibreSCRS::Agent::Test;
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1", LibreSCRS::Agent::Wire::PreReadAuth::Can);
    fake.addCert("c1", "lk", /*signingCapable=*/true, /*keyUsageBits=*/0x05);
    fake.setKeyFacts("lk", {0xF7, 0x13}, LibreSCRS::Agent::KeyType::Ec, 384, /*canDerive=*/true);
    fake.start();
    P::SocketAgentClient client{fake.path(), kFastBudgets};
    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    const auto& e = snap.readers[0].certs[0];
    EXPECT_EQ(e.ckaId, (std::vector<std::uint8_t>{0xF7, 0x13}));
    EXPECT_EQ(e.keyType, LibreSCRS::Agent::KeyType::Ec);
    EXPECT_EQ(e.keyBits, 384u);
    EXPECT_TRUE(e.canDerive);
    EXPECT_FALSE(e.canDecrypt) << "keyEncipherment on an EC key is not an RSA decryption";
    EXPECT_FALSE(e.signsHashOnCard) << "the hash-on-card family is an RSA choice";
}

// A raw signature names its mechanism on the wire, as the module asked.
TEST(SocketAgentClient, ARawSignatureCarriesTheMechanismToken)
{
    namespace T = LibreSCRS::Agent::Test;
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "lk");
    fake.start();
    P::SocketAgentClient client{fake.path(), kFastBudgets};
    const std::vector<std::uint8_t> digest(48, 0xAB);
    EXPECT_EQ(client.signRaw("r1", "lk", LibreSCRS::Agent::Mechanism::EcdsaSign, digest).status, P::Status::Ok);
    EXPECT_EQ(fake.lastSignMechanism(), "ecdsa");
    EXPECT_EQ(client.signRaw("r1", "lk", LibreSCRS::Agent::Mechanism::Sha256RsaPkcs1Sign, digest).status,
              P::Status::Ok);
    EXPECT_EQ(fake.lastSignMechanism(), "sha256-rsa-pkcs");
    // A decryption mechanism shares its token with a signing one; it is still
    // not a signature, and nothing reaches the agent for it.
    const int signsBefore = fake.callCount(T::Call::PkSignRaw);
    EXPECT_EQ(client.signRaw("r1", "lk", LibreSCRS::Agent::Mechanism::RsaPkcs1Decrypt, digest).status,
              P::Status::NotSupported);
    EXPECT_EQ(fake.callCount(T::Call::PkSignRaw), signsBefore);
}

// The module serves only a NIST curve at that curve's width. A point of
// another curve or width is a reply the wire decoder refuses, so the client
// treats the agent as one that no longer speaks the contract (DeviceRemoved,
// as for any malformed reply): never a point handed to a loader, never cached.
TEST(SocketAgentClient, AnEcPointOffItsCurvesWidthIsNotServed)
{
    namespace T = LibreSCRS::Agent::Test;
    using LibreSCRS::Agent::KeyType;
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "no-point");
    fake.setKeyFacts("no-point", {0x01}, KeyType::Ec, 384, /*canDerive=*/false);
    fake.setEcPoint("no-point", "P-384", {}, {});
    fake.addCert("c1", "short");
    fake.setKeyFacts("short", {0x02}, KeyType::Ec, 384, /*canDerive=*/false);
    fake.setEcPoint("short", "P-384", std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 0x22));
    fake.addCert("c1", "uneven");
    fake.setKeyFacts("uneven", {0x03}, KeyType::Ec, 384, /*canDerive=*/false);
    fake.setEcPoint("uneven", "P-384", std::vector<std::uint8_t>(48, 0x11), std::vector<std::uint8_t>(47, 0x22));
    fake.addCert("c1", "p192");
    fake.setKeyFacts("p192", {0x04}, KeyType::Ec, 192, /*canDerive=*/false);
    fake.setEcPoint("p192", "P-192", std::vector<std::uint8_t>(24, 0x11), std::vector<std::uint8_t>(24, 0x22));
    fake.addCert("c1", "p521");
    fake.setKeyFacts("p521", {0x05}, KeyType::Ec, 521, /*canDerive=*/false);
    fake.setEcPoint("p521", "P-521", std::vector<std::uint8_t>(66, 0x11), std::vector<std::uint8_t>(66, 0x22));
    fake.start();
    P::SocketAgentClient client{fake.path(), kFastBudgets};

    for (const char* certId : {"no-point", "short", "uneven", "p192"}) {
        const auto first = client.publicKey("r1", certId, KeyType::Ec);
        EXPECT_EQ(first.status, P::Status::DeviceRemoved) << certId;
        EXPECT_TRUE(first.x.empty() && first.y.empty() && first.crv.empty()) << certId;
        const int asked = fake.callCount(T::Call::PkPublicKey);
        EXPECT_EQ(client.publicKey("r1", certId, KeyType::Ec).status, P::Status::DeviceRemoved) << certId;
        EXPECT_EQ(fake.callCount(T::Call::PkPublicKey), asked + 1) << certId << ": a malformed answer was cached";
    }
    // The control: a well-formed point on the widest curve is served.
    const auto ok = client.publicKey("r1", "p521", KeyType::Ec);
    EXPECT_EQ(ok.status, P::Status::Ok);
    EXPECT_EQ(ok.crv, "P-521");
    EXPECT_EQ(ok.x.size(), 66u);
    EXPECT_EQ(ok.y.size(), 66u);
}

// A cached key answers only for its own family: once the RSA key is cached, a
// request for an EC key under the same id is NotSupported, as an uncached one
// would be -- not the cached RSA key.
TEST(SocketAgentClient, ACachedKeyAnswersOnlyForItsFamily)
{
    namespace T = LibreSCRS::Agent::Test;
    using LibreSCRS::Agent::KeyType;
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "rsa");
    fake.start();
    P::SocketAgentClient client{fake.path(), kFastBudgets};
    ASSERT_EQ(client.publicKey("r1", "rsa", KeyType::Rsa).status, P::Status::Ok);
    const auto ec = client.publicKey("r1", "rsa", KeyType::Ec);
    EXPECT_EQ(ec.status, P::Status::NotSupported);
    EXPECT_TRUE(ec.modulus.empty());
    EXPECT_EQ(client.publicKey("r1", "rsa", KeyType::Other).status, P::Status::NotSupported);
    EXPECT_EQ(client.publicKey("r1", "rsa", KeyType::Rsa).status, P::Status::Ok) << "the cached key is still served";
}

// Derive admits an entry only for an EC key, as the entry's own canDerive
// does: an RSA key the agent marks as deriving and not signing is left out,
// as the other transport leaves it out.
TEST(SocketAgentClient, AnRsaKeyMarkedDerivingIsNotAnEntry)
{
    namespace T = LibreSCRS::Agent::Test;
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1");
    fake.addCert("c1", "rsa-derive", /*signingCapable=*/false);
    fake.setKeyFacts("rsa-derive", {0x01}, LibreSCRS::Agent::KeyType::Rsa, 2048, /*canDerive=*/true);
    fake.addCert("c1", "ec-derive", /*signingCapable=*/false);
    fake.setKeyFacts("ec-derive", {0x02}, LibreSCRS::Agent::KeyType::Ec, 384, /*canDerive=*/true);
    fake.start();
    P::SocketAgentClient client{fake.path(), kFastBudgets};
    const auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    EXPECT_EQ(snap.readers[0].certs[0].certId, "ec-derive");
}

} // namespace
