// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// One slot model, two transports.
//
// The mapping from what the agent reports to what a loader sees is a pure
// function, and both transports feed it. Which mechanism a token advertises,
// and whether its key offers decryption at all, are derived from a capability
// flag rather than from a card name -- so a transport that read that flag
// differently would publish a different token and its own suite would stay
// green throughout.
//
// Every case builds the bus transport's snapshot the way that client builds
// it, from the same card facts, and drives the real socket client against the
// double scripted with those facts, because a hand-built snapshot cannot show
// that the socket client fills one in the same way. The two are compared as
// the model a loader would see.

#include "fakes/FakeSocketAgent.h"

#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>
#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

namespace T = LibreSCRS::Agent::Test;
namespace P = LibreSCRS::Pkcs11Agent;
namespace W = LibreSCRS::Agent::Wire;

constexpr std::uint32_t kKeyEncipherment = 1U << 2;
constexpr P::SocketTimeouts kFastBudgets{/*publicDataSecs=*/2, /*interactiveSecs=*/8};

/// The card facts both transports start from. Deliberately not a snapshot:
/// each side has to derive one, which is where they could disagree.
struct CardFacts
{
    W::PreReadAuth preAuth = W::PreReadAuth::None;
    std::uint32_t keyUsageBits = 0;
    LibreSCRS::Agent::KeyType keyType = LibreSCRS::Agent::KeyType::Rsa;
    std::uint32_t keyBits = 2048;
    /// The agent's keyId. The socket double names a certificate's key by the
    /// certId's bytes unless told otherwise; the same bytes here.
    std::vector<std::uint8_t> keyId{'c', 'e', 'r', 't', 'i', 'd', '-', '1'};
    bool signingCapable = true;
    bool canDerive = false;
};

/// Assemble the snapshot the way the BUS client assembles it -- the same
/// derivations, spelled out here rather than called, because that client lives
/// in the other repository and links a bus this tree does not have.
P::AgentSnapshot busSnapshot(const CardFacts& facts)
{
    const bool canDriveSigning = (facts.preAuth == W::PreReadAuth::None || facts.preAuth == W::PreReadAuth::Can);
    const bool canDriveDecrypt = (facts.preAuth == W::PreReadAuth::None);
    const bool hashesOnCard = (facts.preAuth == W::PreReadAuth::Can);
    const bool keyUsagePermitsDecrypt = (facts.keyUsageBits & ((1U << 2) | (1U << 3))) != 0;
    const bool isRsa = facts.keyType == LibreSCRS::Agent::KeyType::Rsa;

    P::ReaderState reader;
    reader.readerPath = "r1";
    reader.hasCard = true;

    P::CertEntry ce;
    ce.certId = "certid-1";
    ce.signingCapable = facts.signingCapable;
    ce.keyType = facts.keyType;
    ce.canDerive = facts.canDerive && facts.keyType == LibreSCRS::Agent::KeyType::Ec;
    if (ce.signingCapable || ce.canDerive) {
        ce.label = "certid-1";
        ce.ckaId = facts.keyId;
        ce.keyBits = facts.keyBits;
        ce.canSign = ce.signingCapable && canDriveSigning;
        ce.canDecrypt = isRsa && canDriveDecrypt && keyUsagePermitsDecrypt;
        ce.signsHashOnCard = isRsa && hashesOnCard;
        reader.certs.push_back(std::move(ce));
    }

    P::AgentSnapshot snap;
    snap.readers.push_back(std::move(reader));
    return snap;
}

/// Drive the real socket client against a double scripted with the same facts.
P::AgentSnapshot socketSnapshot(const CardFacts& facts)
{
    T::FakeSocketAgent fake;
    fake.addReader("r1", /*hasCard=*/true, "c1", facts.preAuth);
    fake.addCert("c1", "certid-1", facts.signingCapable, facts.keyUsageBits);
    fake.setKeyFacts("certid-1", facts.keyId, facts.keyType, facts.keyBits, facts.canDerive);
    fake.start();

    P::SocketAgentClient client{fake.path(), kFastBudgets};
    EXPECT_TRUE(client.connected());
    return client.snapshot();
}

/// Compare what a loader would see, not what the two structs happen to hold.
void expectSameModel(const P::AgentSnapshot& a, const P::AgentSnapshot& b)
{
    const auto ma = P::ObjectModel::build(a);
    const auto mb = P::ObjectModel::build(b);
    ASSERT_EQ(ma.slots.size(), mb.slots.size());
    for (std::size_t i = 0; i < ma.slots.size(); ++i) {
        EXPECT_EQ(ma.slots[i].tokenPresent, mb.slots[i].tokenPresent);
        EXPECT_EQ(ma.slots[i].protectedAuthPath, mb.slots[i].protectedAuthPath);
        EXPECT_EQ(ma.slots[i].mechanisms, mb.slots[i].mechanisms);
        ASSERT_EQ(ma.slots[i].objects.size(), mb.slots[i].objects.size());
        for (std::size_t j = 0; j < ma.slots[i].objects.size(); ++j) {
            EXPECT_EQ(ma.slots[i].objects[j].cls, mb.slots[i].objects[j].cls);
            EXPECT_EQ(ma.slots[i].objects[j].ckaId, mb.slots[i].objects[j].ckaId);
            EXPECT_EQ(ma.slots[i].objects[j].sign, mb.slots[i].objects[j].sign);
            EXPECT_EQ(ma.slots[i].objects[j].decrypt, mb.slots[i].objects[j].decrypt);
            EXPECT_EQ(ma.slots[i].objects[j].keyType, mb.slots[i].objects[j].keyType);
            EXPECT_EQ(ma.slots[i].objects[j].keyBits, mb.slots[i].objects[j].keyBits);
        }
    }
}

TEST(SnapshotParity, TheSameCardFactsProduceTheSameSlotsAndMechanisms)
{
    const CardFacts facts{W::PreReadAuth::None, kKeyEncipherment};
    expectSameModel(busSnapshot(facts), socketSnapshot(facts));
}

TEST(SnapshotParity, ACardTheAgentCannotDriveAdvertisesNoMechanismOnEitherPath)
{
    // Mrz is the family neither transport can drive a signing credential for.
    // The claim is about the flag, not the card: a token whose key can do
    // nothing must advertise nothing, or a loader offers an operation that
    // always fails.
    const CardFacts facts{W::PreReadAuth::Mrz, kKeyEncipherment};
    const auto bus = busSnapshot(facts);
    const auto sock = socketSnapshot(facts);
    expectSameModel(bus, sock);
    const auto model = P::ObjectModel::build(sock);
    ASSERT_EQ(model.slots.size(), 1U);
    EXPECT_TRUE(model.slots[0].mechanisms.empty());
}

TEST(SnapshotParity, HashOnCardAdvertisesSha256RsaPkcsOnEitherPath)
{
    const CardFacts facts{W::PreReadAuth::Can, kKeyEncipherment};
    const auto sock = socketSnapshot(facts);
    expectSameModel(busSnapshot(facts), sock);
    const auto model = P::ObjectModel::build(sock);
    ASSERT_EQ(model.slots.size(), 1U);
    EXPECT_NE(std::find(model.slots[0].mechanisms.begin(), model.slots[0].mechanisms.end(),
                        static_cast<CK_MECHANISM_TYPE>(CKM_SHA256_RSA_PKCS)),
              model.slots[0].mechanisms.end());
}

TEST(SnapshotParity, DecryptStaysGatedToPreAuthNoneOnEitherPath)
{
    // Two halves of one gate: the credential family AND the key-usage bit.
    // Either alone would let a token offer decryption it cannot perform.
    const CardFacts noBit{W::PreReadAuth::None, 0};
    expectSameModel(busSnapshot(noBit), socketSnapshot(noBit));
    {
        const auto model = P::ObjectModel::build(socketSnapshot(noBit));
        ASSERT_EQ(model.slots.size(), 1U);
        for (const auto& o : model.slots[0].objects)
            EXPECT_FALSE(o.decrypt);
    }

    const CardFacts hashOnCard{W::PreReadAuth::Can, kKeyEncipherment};
    expectSameModel(busSnapshot(hashOnCard), socketSnapshot(hashOnCard));
    {
        const auto model = P::ObjectModel::build(socketSnapshot(hashOnCard));
        ASSERT_EQ(model.slots.size(), 1U);
        for (const auto& o : model.slots[0].objects)
            EXPECT_FALSE(o.decrypt);
    }
}

TEST(SnapshotParity, AnEcKeyProducesTheSameModelOnEitherPath)
{
    CardFacts facts{W::PreReadAuth::Can, kKeyEncipherment};
    facts.keyType = LibreSCRS::Agent::KeyType::Ec;
    facts.keyBits = 384;
    facts.keyId = {0xF7, 0x13, 0x4B, 0x02};
    facts.canDerive = true;
    const auto sock = socketSnapshot(facts);
    expectSameModel(busSnapshot(facts), sock);
    const auto model = P::ObjectModel::build(sock);
    ASSERT_EQ(model.slots.size(), 1U);
    const auto& mechs = model.slots[0].mechanisms;
    EXPECT_NE(std::find(mechs.begin(), mechs.end(), static_cast<CK_MECHANISM_TYPE>(CKM_ECDSA)), mechs.end());
    EXPECT_EQ(std::find(mechs.begin(), mechs.end(), static_cast<CK_MECHANISM_TYPE>(CKM_SHA256_RSA_PKCS)), mechs.end())
        << "hash-on-card is an RSA family choice";
    for (const auto& o : model.slots[0].objects)
        EXPECT_FALSE(o.decrypt) << "an EC key never decrypts";
}

} // namespace
