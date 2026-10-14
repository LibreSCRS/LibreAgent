// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure mapping tests: an agent snapshot (readers/cards/certs + per-cert
// capability flags) -> PKCS#11 slots/tokens/objects/mechanisms. No D-Bus.
//
// The mechanism table is CAPABILITY-ADVERTISED, never card-type-hardcoded:
//  - a PKS-style token (certs with signingCapable + canDecrypt) advertises
//    ONLY raw CKM_RSA_PKCS (covering both sign and decrypt) — the combined
//    CKM_SHAxxx_RSA_PKCS mechanisms are NOT advertised because the
//    libcrypto-free module cannot compute the digest they require;
//  - a NAM-style hash-on-card token (canSign + signsHashOnCard, decrypt off)
//    advertises ONLY the combined CKM_SHA256_RSA_PKCS sign mechanism (the card
//    computes the digest from the raw message) and its key carries CKA_SIGN but
//    not CKA_DECRYPT;
//  - a fully capability-gated token (canSign == canDecrypt == false) advertises
//    NO mechanisms and its key carries neither CKA_SIGN nor CKA_DECRYPT.
// PSS is never advertised. CKM_ECDSA is advertised for an EC key only, and the
// hash-on-card choice is an RSA family's alone.

#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>
#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <algorithm>
#include <string>
#include <vector>
#include <gtest/gtest.h>

using namespace LibreSCRS::Pkcs11Agent;

namespace {

AgentSnapshot oneCardOneCert()
{
    ReaderState r;
    r.readerPath = "/org/librescrs/Agent/reader/0";
    r.hasCard = true;
    r.tokenLabel = "LibreSCRS PKS";
    CertEntry c;
    c.certId = "abc123";
    c.label = "Sign";
    c.ckaId = {0x01};
    c.signingCapable = true;
    c.canSign = true;    // PKS: CardPlugin::sign works
    c.canDecrypt = true; // PKS: CardPlugin::decipher works (keyUsage permits)
    c.keyType = LibreSCRS::Agent::KeyType::Rsa;
    c.keyBits = 2048;
    r.certs.push_back(c);
    return AgentSnapshot{.readers = {r}};
}

// NAM-style hash-on-card SSCD (IAS-ECC): the agent drives on-card SHA-256 RSA
// signing (canSign + signsHashOnCard) but decrypt is not supported (no on-card
// MSE-CT/PSO-DECIPHER). The card computes the digest, so the proxy advertises
// CKM_SHA256_RSA_PKCS (sign-only), not the DigestInfo CKM_RSA_PKCS.
AgentSnapshot namCard()
{
    ReaderState r;
    r.readerPath = "/org/librescrs/Agent/reader/1";
    r.hasCard = true;
    r.tokenLabel = "LibreSCRS NAM";
    CertEntry c;
    c.certId = "nam999";
    c.label = "Qualified Signature";
    c.ckaId = {0x02};
    c.signingCapable = true;
    c.canSign = true;         // the agent supplies the eSign PIN + drives on-card sign
    c.signsHashOnCard = true; // IAS-ECC hashes the raw message on-card
    c.canDecrypt = false;     // decrypt is not supported on this card
    c.keyType = LibreSCRS::Agent::KeyType::Rsa;
    c.keyBits = 3072;
    r.certs.push_back(c);
    return AgentSnapshot{.readers = {r}};
}

// A capability-gated card: a signing cert is present, but the agent can drive
// NEITHER on-card sign nor decrypt (canSign == canDecrypt == false). Fail-closed:
// no mechanisms, and a key with neither CKA_SIGN nor CKA_DECRYPT.
AgentSnapshot gatedCard()
{
    AgentSnapshot s = namCard();
    s.readers[0].certs[0].canSign = false;
    s.readers[0].certs[0].signsHashOnCard = false;
    s.readers[0].certs[0].canDecrypt = false;
    return s;
}

bool hasMech(const std::vector<CK_MECHANISM_TYPE>& mechs, CK_MECHANISM_TYPE t)
{
    return std::find(mechs.begin(), mechs.end(), t) != mechs.end();
}

} // namespace

TEST(ObjectModel, SlotPerReaderTokenPresentWhenCard)
{
    auto m = ObjectModel::build(oneCardOneCert());
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_TRUE(m.slots[0].tokenPresent);
    EXPECT_TRUE(m.slots[0].protectedAuthPath); // CKF_PROTECTED_AUTHENTICATION_PATH
    EXPECT_EQ(m.slots[0].readerPath, "/org/librescrs/Agent/reader/0");
}

TEST(ObjectModel, ThreeObjectsPerSigningCert)
{
    auto m = ObjectModel::build(oneCardOneCert());
    ASSERT_EQ(m.slots.size(), 1u);
    const auto& objs = m.slots[0].objects;
    int cert = 0, pub = 0, priv = 0;
    for (const auto& o : objs) {
        if (o.cls == CKO_CERTIFICATE) {
            ++cert;
            EXPECT_EQ(o.ckaId, std::vector<std::uint8_t>{0x01});
        }
        if (o.cls == CKO_PUBLIC_KEY)
            ++pub;
        if (o.cls == CKO_PRIVATE_KEY) {
            ++priv;
            EXPECT_TRUE(o.sign);
            EXPECT_TRUE(o.decrypt);
            EXPECT_EQ(o.ckaId, std::vector<std::uint8_t>{0x01});
            EXPECT_EQ(o.certId, "abc123");
        }
    }
    EXPECT_EQ(cert, 1);
    EXPECT_EQ(pub, 1);
    EXPECT_EQ(priv, 1);
}

TEST(ObjectModel, MechanismsAreRawRsaPkcsOnly_NoHashCombosNoPssNoEcdsa)
{
    auto m = ObjectModel::build(oneCardOneCert());
    const auto& mechs = m.slots[0].mechanisms;
    EXPECT_TRUE(hasMech(mechs, CKM_RSA_PKCS));
    // The combined hash-RSA mechanisms are NOT advertised: the libcrypto-free
    // module cannot hash, so it would sign a never-hashed message no verifier
    // accepts. Callers supply a complete DigestInfo to CKM_RSA_PKCS instead.
    EXPECT_FALSE(hasMech(mechs, CKM_SHA256_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_SHA384_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_SHA512_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_RSA_PKCS_PSS)); // SR cards do not advertise PSS
    EXPECT_FALSE(hasMech(mechs, CKM_ECDSA));        // an RSA-only card
    // Exactly one advertised mechanism.
    EXPECT_EQ(mechs.size(), 1u);
}

TEST(ObjectModel, NoTokenWhenNoCard)
{
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].hasCard = false;
    s.readers[0].certs.clear();
    auto m = ObjectModel::build(s);
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_FALSE(m.slots[0].tokenPresent);
    EXPECT_TRUE(m.slots[0].objects.empty());
    EXPECT_TRUE(m.slots[0].mechanisms.empty());
}

// ---- NAM: hash-on-card sign-only (decrypt gated) ---------------------------

TEST(ObjectModel, NamHashOnCardTokenAdvertisesSha256RsaPkcsSignOnly)
{
    auto m = ObjectModel::build(namCard());
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_TRUE(m.slots[0].tokenPresent);
    const auto& mechs = m.slots[0].mechanisms;
    // The card hashes on-card, so the proxy offers the combined
    // CKM_SHA256_RSA_PKCS (sign-only) and NOT the DigestInfo CKM_RSA_PKCS.
    EXPECT_EQ(mechs.size(), 1u);
    EXPECT_TRUE(hasMech(mechs, CKM_SHA256_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_RSA_PKCS));
}

TEST(ObjectModel, NamPrivateKeyObjectSignsButDoesNotDecrypt)
{
    auto m = ObjectModel::build(namCard());
    ASSERT_EQ(m.slots.size(), 1u);
    bool sawPriv = false;
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            sawPriv = true;
            EXPECT_TRUE(o.sign) << "NAM key signs on-card";
            EXPECT_FALSE(o.decrypt) << "NAM key does not decrypt";
        }
    }
    EXPECT_TRUE(sawPriv);
}

TEST(ObjectModel, FullyGatedTokenAdvertisesNoMechanismsNorKeyFlags)
{
    auto m = ObjectModel::build(gatedCard());
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_TRUE(m.slots[0].tokenPresent);
    EXPECT_TRUE(m.slots[0].mechanisms.empty()) << "a card the agent cannot drive advertises nothing";
    bool sawPriv = false;
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            sawPriv = true;
            EXPECT_FALSE(o.sign);
            EXPECT_FALSE(o.decrypt);
        }
    }
    // The cert + public key + a capability-less private key are still present.
    EXPECT_TRUE(sawPriv);
}

TEST(ObjectModel, SignOnlyCardOmitsDecryptMechanism)
{
    // A card whose key signs but cannot decrypt (keyUsage without
    // dataEncipherment) advertises CKM_RSA_PKCS sign but the key has no
    // CKA_DECRYPT. The mechanism CKM_RSA_PKCS still appears (it covers sign);
    // CKA_DECRYPT on the key is what gates decrypt per-object.
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].certs[0].canDecrypt = false;
    auto m = ObjectModel::build(s);
    const auto& mechs = m.slots[0].mechanisms;
    EXPECT_TRUE(hasMech(mechs, CKM_RSA_PKCS));
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            EXPECT_TRUE(o.sign);
            EXPECT_FALSE(o.decrypt);
        }
    }
}

TEST(ObjectModel, NonSigningCertProducesNoKeyObjects)
{
    // A cert without a usable signing key (signingCapable=false) yields no
    // PKCS#11 objects (the proxy only surfaces signing certs).
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].certs[0].signingCapable = false;
    auto m = ObjectModel::build(s);
    EXPECT_TRUE(m.slots[0].objects.empty());
}

// A loader shows the user the token label, so it names the holder the card's
// signing certificate names, and the reader the card sits in when there is no
// such certificate. A certificate that cannot sign does not name the token.
TEST(ObjectModel, TokenLabelIsTheSigningCertHolderElseTheReaderName)
{
    CertEntry auth;
    auth.label = auth.holderName = "Auth Only";
    auth.signingCapable = false;
    CertEntry holder;
    holder.label = holder.holderName = "Petar Petrović";
    holder.signingCapable = true;
    CertEntry second;
    second.label = second.holderName = "Second Holder";
    second.signingCapable = true;
    // A signing cert whose subject has no CN: its CKA_LABEL falls back to the
    // hex cert id, which must never become the token's name.
    CertEntry noCn;
    noCn.label = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    noCn.signingCapable = true;

    EXPECT_EQ(tokenLabelFor({auth, holder, second}, "ACS ACR39U ICC Reader"), "Petar Petrović");
    EXPECT_EQ(tokenLabelFor({noCn, holder}, "ACS ACR39U ICC Reader"), "Petar Petrović");
    EXPECT_EQ(tokenLabelFor({noCn}, "ACS ACR39U ICC Reader"), "ACS ACR39U ICC Reader");
    EXPECT_EQ(tokenLabelFor({auth}, "ACS ACR39U ICC Reader"), "ACS ACR39U ICC Reader");
    EXPECT_EQ(tokenLabelFor({}, "ACS ACR39U ICC Reader"), "ACS ACR39U ICC Reader");
    EXPECT_EQ(tokenLabelFor({}, ""), "");
}

// The serial is what tells two seated cards apart. It is the counter at the end
// of the agent's handle, on either transport, and when it has to be shortened
// to the field's 16 bytes it keeps the END, where two counters differ.
TEST(ObjectModel, TokenSerialIsTheHandleTailAndFitsTheField)
{
    EXPECT_EQ(tokenSerialFor("/org/librescrs/Agent/card/7"), "7");
    EXPECT_EQ(tokenSerialFor("obj/12"), "12");
    EXPECT_EQ(tokenSerialFor("c1"), "c1");

    const std::string a = tokenSerialFor("obj/1234567890123456781");
    const std::string b = tokenSerialFor("obj/1234567890123456782");
    EXPECT_EQ(a.size(), kTokenSerialMaxBytes);
    EXPECT_EQ(a, "4567890123456781");
    EXPECT_NE(a, b) << "two cards whose counters differ at the end collided";
}

// The serial the transport filled reaches the slot unchanged, and two readers'
// cards reach two different slots with two different serials.
TEST(ObjectModel, EachSlotCarriesItsOwnTokenSerial)
{
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].tokenSerial = "3";
    ReaderState second = namCard().readers[0];
    second.tokenSerial = "5";
    s.readers.push_back(second);

    const auto m = ObjectModel::build(s);
    ASSERT_EQ(m.slots.size(), 2u);
    EXPECT_EQ(m.slots[0].tokenSerial, "3");
    EXPECT_EQ(m.slots[1].tokenSerial, "5");
    EXPECT_EQ(m.slots[0].tokenLabel, "LibreSCRS PKS");
    EXPECT_EQ(m.slots[1].tokenLabel, "LibreSCRS NAM");
}

// The reader's name rides to the slot for display; the handle stays the key.
TEST(ObjectModel, EachSlotCarriesItsReaderName)
{
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].readerName = "ACS ACR39U ICC Reader";
    const auto m = ObjectModel::build(s);
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_EQ(m.slots[0].readerName, "ACS ACR39U ICC Reader");
    EXPECT_EQ(m.slots[0].readerPath, "/org/librescrs/Agent/reader/0");
}

// The card's per-operation consent rule for a key lands on that key's private
// object, and only where the card set it.
TEST(ObjectModel, PrivateKeyCarriesTheCardsConsentRule)
{
    auto snap = oneCardOneCert();
    snap.readers[0].certs[0].alwaysAuthenticate = true;
    const auto m = ObjectModel::build(snap);
    ASSERT_EQ(m.slots.size(), 1u);
    int seen = 0;
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            EXPECT_TRUE(o.alwaysAuthenticate);
            ++seen;
        }
    }
    EXPECT_EQ(seen, 1);

    const auto plain = ObjectModel::build(oneCardOneCert());
    ASSERT_EQ(plain.slots.size(), 1u);
    for (const auto& o : plain.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY)
            EXPECT_FALSE(o.alwaysAuthenticate) << "an unmarked key's private object stays unmarked";
    }
}

namespace {

// The new Serbian ID card: one EC P-384 key, the card's own 16-byte iD, a PACE
// card (the agent reports it as hash-on-card for RSA keys, which must not
// matter for an EC key).
CertEntry lkEntry()
{
    CertEntry c;
    c.certId = "lk";
    c.label = "LK";
    c.ckaId = {0xF7, 0x13, 0x4B, 0x02, 0x7C, 0xD6, 0x45, 0x57, 0x86, 0x0A, 0xF5, 0x4E, 0xB9, 0xCD, 0x1D, 0x41};
    c.signingCapable = true;
    c.canSign = true;
    c.canDecrypt = false;
    c.signsHashOnCard = true;
    c.keyType = LibreSCRS::Agent::KeyType::Ec;
    c.keyBits = 384;
    return c;
}

AgentSnapshot cardWith(std::vector<CertEntry> certs)
{
    ReaderState r;
    r.readerPath = "/org/librescrs/Agent/reader/9";
    r.hasCard = true;
    r.certs = std::move(certs);
    return AgentSnapshot{.readers = {r}};
}

} // namespace

TEST(ObjectModel, AnEcKeyAdvertisesEcdsaNotTheRsaMechanisms)
{
    const auto m = ObjectModel::build(cardWith({lkEntry()}));
    const auto& mechs = m.slots[0].mechanisms;
    EXPECT_TRUE(hasMech(mechs, CKM_ECDSA));
    EXPECT_FALSE(hasMech(mechs, CKM_SHA256_RSA_PKCS)) << "hash-on-card is an RSA family choice";
    EXPECT_FALSE(hasMech(mechs, CKM_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_ECDH1_DERIVE)) << "a key the agent does not derive with";
}

TEST(ObjectModel, AMixedCardAdvertisesTheUnion)
{
    auto rsa = oneCardOneCert().readers[0].certs[0];
    const auto m = ObjectModel::build(cardWith({rsa, lkEntry()}));
    EXPECT_TRUE(hasMech(m.slots[0].mechanisms, CKM_RSA_PKCS));
    EXPECT_TRUE(hasMech(m.slots[0].mechanisms, CKM_ECDSA));
}

TEST(ObjectModel, KeyObjectsCarryTheirTypeSizeAndTheCardsId)
{
    const auto m = ObjectModel::build(cardWith({lkEntry()}));
    for (const auto& o : m.slots[0].objects) {
        EXPECT_EQ(o.ckaId, lkEntry().ckaId) << "CKA_ID is the card's own iD on every object";
        if (o.cls == CKO_PUBLIC_KEY || o.cls == CKO_PRIVATE_KEY) {
            EXPECT_EQ(o.keyType, LibreSCRS::Agent::KeyType::Ec);
            EXPECT_EQ(o.keyBits, 384u);
        }
    }
}

TEST(ObjectModel, AnEcPrivateKeyNeverDecrypts)
{
    auto lk = lkEntry();
    lk.canDecrypt = true; // a transport bug must not turn into CKA_DECRYPT on an EC key
    const auto m = ObjectModel::build(cardWith({lk}));
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            EXPECT_FALSE(o.decrypt);
            EXPECT_TRUE(o.sign);
        }
    }
}

TEST(ObjectModel, AnOtherKeyProducesNoObjects)
{
    auto other = lkEntry();
    other.keyType = LibreSCRS::Agent::KeyType::Other;
    other.keyBits = 0;
    const auto m = ObjectModel::build(cardWith({other}));
    EXPECT_TRUE(m.slots[0].objects.empty());
    EXPECT_TRUE(m.slots[0].mechanisms.empty());
}

TEST(ObjectModel, ADeriveOnlyKeyIsAKeyThatDerives)
{
    auto deriveOnly = lkEntry();
    deriveOnly.signingCapable = false;
    deriveOnly.canSign = false;
    deriveOnly.canDerive = true;
    const auto m = ObjectModel::build(cardWith({deriveOnly}));
    ASSERT_EQ(m.slots[0].objects.size(), 3u);
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            EXPECT_TRUE(o.derive);
            EXPECT_FALSE(o.sign);
        }
    }
    EXPECT_TRUE(hasMech(m.slots[0].mechanisms, CKM_ECDH1_DERIVE));
    EXPECT_FALSE(hasMech(m.slots[0].mechanisms, CKM_ECDSA));
}

TEST(ObjectModel, AnRsaKeyNeverDerives)
{
    auto rsa = oneCardOneCert().readers[0].certs[0];
    rsa.canDerive = true; // a transport bug must not turn into CKA_DERIVE on an RSA key
    const auto m = ObjectModel::build(cardWith({rsa}));
    for (const auto& o : m.slots[0].objects) {
        EXPECT_FALSE(o.derive);
    }
    EXPECT_FALSE(hasMech(m.slots[0].mechanisms, CKM_ECDH1_DERIVE));

    // Nor does it make a non-signing RSA key an object of its own.
    rsa.signingCapable = false;
    const auto none = ObjectModel::build(cardWith({rsa}));
    EXPECT_TRUE(none.slots[0].objects.empty());
}

// CKA_SIGN is the agent's signingCapable AND the transport's canSign: a key
// the certificate does not sign with (a key-agreement key) never signs, even
// if a transport sets canSign for it.
TEST(ObjectModel, AKeyItsCertificateDoesNotSignWithNeverSigns)
{
    auto deriveOnly = lkEntry();
    deriveOnly.signingCapable = false;
    deriveOnly.canSign = true; // a transport that did not AND signingCapable in
    deriveOnly.canDerive = true;
    const auto m = ObjectModel::build(cardWith({deriveOnly}));
    for (const auto& o : m.slots[0].objects) {
        EXPECT_FALSE(o.sign);
    }
    EXPECT_FALSE(hasMech(m.slots[0].mechanisms, CKM_ECDSA));
    EXPECT_TRUE(hasMech(m.slots[0].mechanisms, CKM_ECDH1_DERIVE));
}

// A key whose size names no curve (EC) or no modulus (RSA) cannot be served:
// it would have no CKA_EC_PARAMS, and every length question about it would go
// to the card. It produces no objects, as an Other key does.
TEST(ObjectModel, AKeyOfNoKnownSizeProducesNoObjects)
{
    for (const std::uint32_t bits : {0U, 255U, 192U}) {
        auto ec = lkEntry();
        ec.keyBits = bits;
        const auto m = ObjectModel::build(cardWith({ec}));
        EXPECT_TRUE(m.slots[0].objects.empty()) << "EC " << bits;
        EXPECT_TRUE(m.slots[0].mechanisms.empty()) << "EC " << bits;
    }
    auto rsa = oneCardOneCert().readers[0].certs[0];
    rsa.keyBits = 0;
    const auto m = ObjectModel::build(cardWith({rsa}));
    EXPECT_TRUE(m.slots[0].objects.empty());
    EXPECT_TRUE(m.slots[0].mechanisms.empty());
}
