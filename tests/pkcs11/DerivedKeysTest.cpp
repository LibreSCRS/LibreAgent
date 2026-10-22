// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The secret keys C_DeriveKey makes: what a template may ask for, which bytes
// of Z the key holds, and what it serves.
#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Agent/pkcs11/DerivedKeys.h>
#include <LibreSCRS/Agent/pkcs11/SessionState.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace LibreSCRS::Pkcs11Agent;

namespace {

CK_BBOOL kTrue = CK_TRUE;
CK_BBOOL kFalse = CK_FALSE;

} // namespace

TEST(DerivedKeys, AnEmptyTemplateIsASensitiveGenericSecret)
{
    const auto t = parseDerivedKeyTemplate(nullptr, 0);
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->keyType, CKK_GENERIC_SECRET);
    EXPECT_TRUE(t->sensitive);
    EXPECT_FALSE(t->extractable);
    EXPECT_FALSE(t->valueLen.has_value());
}

// pkcs11-tool --derive's own template is accepted as it is sent: nine fixed
// attributes, plus CKA_VALUE_LEN = BYTES4BITS(degree) that it always appends
// for an EC peer (OpenSC src/tools/pkcs11-tool.c, derive_ec_key).
TEST(DerivedKeys, ThePkcs11ToolTemplateIsAccepted)
{
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
    CK_ULONG keyLen = 48; // P-384
    CK_ATTRIBUTE tmpl[] = {
        {CKA_TOKEN, &kFalse, sizeof(kFalse)},     {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},          {CKA_SENSITIVE, &kFalse, sizeof(kFalse)},
        {CKA_EXTRACTABLE, &kTrue, sizeof(kTrue)}, {CKA_ENCRYPT, &kTrue, sizeof(kTrue)},
        {CKA_DECRYPT, &kTrue, sizeof(kTrue)},     {CKA_WRAP, &kTrue, sizeof(kTrue)},
        {CKA_UNWRAP, &kTrue, sizeof(kTrue)},      {CKA_VALUE_LEN, &keyLen, sizeof(keyLen)},
    };
    const auto t = parseDerivedKeyTemplate(tmpl, 10);
    ASSERT_TRUE(t.has_value());
    EXPECT_FALSE(t->sensitive);
    EXPECT_TRUE(t->extractable);
    EXPECT_EQ(t->usage.size(), 4u);
    EXPECT_EQ(t->valueLen, std::optional<CK_ULONG>{48});
}

TEST(DerivedKeys, WhatTheModuleCannotMakeIsRefused)
{
    CK_OBJECT_CLASS pubCls = CKO_PUBLIC_KEY;
    CK_KEY_TYPE des = CKK_DES3;
    CK_ULONG zero = 0;
    CK_BBOOL unknownValue = CK_TRUE;
    const auto rv = [](std::vector<CK_ATTRIBUTE> tmpl) {
        const auto t = parseDerivedKeyTemplate(tmpl.data(), static_cast<CK_ULONG>(tmpl.size()));
        return t.has_value() ? CKR_OK : t.error();
    };
    EXPECT_EQ(rv({{CKA_TOKEN, &kTrue, sizeof(kTrue)}}), CKR_TEMPLATE_INCONSISTENT) << "no token storage";
    EXPECT_EQ(rv({{CKA_PRIVATE, &kFalse, sizeof(kFalse)}}), CKR_TEMPLATE_INCONSISTENT);
    EXPECT_EQ(rv({{CKA_CLASS, &pubCls, sizeof(pubCls)}}), CKR_TEMPLATE_INCONSISTENT);
    EXPECT_EQ(rv({{CKA_KEY_TYPE, &des, sizeof(des)}}), CKR_TEMPLATE_INCONSISTENT);
    EXPECT_EQ(rv({{CKA_VALUE_LEN, &zero, sizeof(zero)}}), CKR_ATTRIBUTE_VALUE_INVALID);
    EXPECT_EQ(rv({{CKA_MODIFIABLE, &unknownValue, sizeof(unknownValue)}}), CKR_ATTRIBUTE_TYPE_INVALID);
}

// What the module alone decides about a key it makes is not the template's to
// set (PKCS#11 v2.40 section 5.1: CKR_ATTRIBUTE_READ_ONLY).
TEST(DerivedKeys, WhatOnlyTheModuleSetsIsReadOnly)
{
    CK_MECHANISM_TYPE ecdh = CKM_ECDH1_DERIVE;
    CK_BYTE value[16]{};
    std::vector<CK_ATTRIBUTE> readOnly{{CKA_LOCAL, &kFalse, sizeof(kFalse)},
                                       {CKA_ALWAYS_SENSITIVE, &kTrue, sizeof(kTrue)},
                                       {CKA_NEVER_EXTRACTABLE, &kTrue, sizeof(kTrue)},
                                       {CKA_KEY_GEN_MECHANISM, &ecdh, sizeof(ecdh)},
                                       {CKA_VALUE, value, sizeof(value)}};
    for (auto& a : readOnly) {
        const auto t = parseDerivedKeyTemplate(&a, 1);
        ASSERT_FALSE(t.has_value()) << "attribute 0x" << std::hex << a.type;
        EXPECT_EQ(t.error(), CKR_ATTRIBUTE_READ_ONLY) << "attribute 0x" << std::hex << a.type;
    }
}

TEST(DerivedKeys, AnAesKeyNamesItsLength)
{
    CK_KEY_TYPE aes = CKK_AES;
    CK_ATTRIBUTE noLen[] = {{CKA_KEY_TYPE, &aes, sizeof(aes)}};
    EXPECT_EQ(parseDerivedKeyTemplate(noLen, 1).error(), CKR_TEMPLATE_INCOMPLETE);
    for (CK_ULONG len : {CK_ULONG{16}, CK_ULONG{24}, CK_ULONG{32}}) {
        CK_ATTRIBUTE ok[] = {{CKA_KEY_TYPE, &aes, sizeof(aes)}, {CKA_VALUE_LEN, &len, sizeof(len)}};
        EXPECT_TRUE(parseDerivedKeyTemplate(ok, 2).has_value()) << len;
    }
    CK_ULONG twenty = 20;
    CK_ATTRIBUTE bad[] = {{CKA_KEY_TYPE, &aes, sizeof(aes)}, {CKA_VALUE_LEN, &twenty, sizeof(twenty)}};
    EXPECT_EQ(parseDerivedKeyTemplate(bad, 2).error(), CKR_ATTRIBUTE_VALUE_INVALID);
}

// A shorter CKA_VALUE_LEN keeps the LAST bytes of Z, as SoftHSM 2.7.0 does
// (P-256, CKD_NULL, CKK_GENERIC_SECRET, measured: VALUE_LEN=16 gave
// a85db699f0024c80f9668ece94650fe0, the last 16 of a Z that starts
// f5c8a3ff). The middle of the first half was not recorded and does not enter
// the result; it is zero here.
TEST(DerivedKeys, AShorterValueKeepsTheLastBytesOfTheSecret)
{
    std::vector<std::uint8_t> z(32, 0x00);
    z[0] = 0xF5;
    z[1] = 0xC8;
    z[2] = 0xA3;
    z[3] = 0xFF;
    const std::vector<std::uint8_t> last16{0xA8, 0x5D, 0xB6, 0x99, 0xF0, 0x02, 0x4C, 0x80,
                                           0xF9, 0x66, 0x8E, 0xCE, 0x94, 0x65, 0x0F, 0xE0};
    std::copy(last16.begin(), last16.end(), z.begin() + 16);
    DerivedKeyTemplate t;
    t.valueLen = 16;
    EXPECT_EQ(derivedKeyValue(z, t).value(), last16);
    t.valueLen = 32;
    EXPECT_EQ(derivedKeyValue(z, t).value(), z);
    t.valueLen.reset();
    EXPECT_EQ(derivedKeyValue(z, t).value(), z);
}

// A longer one is the template's fault, said as such.
TEST(DerivedKeys, ALongerValueThanTheSecretIsTheTemplatesFault)
{
    const std::vector<std::uint8_t> z(32, 0x01);
    DerivedKeyTemplate t;
    t.valueLen = 40;
    EXPECT_EQ(derivedKeyValue(z, t).error(), CKR_TEMPLATE_INCONSISTENT);
}

// Sensitive by default: the value is not served, and the key says why.
TEST(DerivedKeys, ASensitiveKeyKeepsItsValue)
{
    DerivedKey key;
    key.value.assign(32, 0x5A);
    CK_BYTE buf[64];
    CK_ATTRIBUTE value{CKA_VALUE, buf, sizeof(buf)};
    EXPECT_EQ(serveDerivedKeyAttribute(key, value), CKR_ATTRIBUTE_SENSITIVE);
    EXPECT_EQ(value.ulValueLen, CK_UNAVAILABLE_INFORMATION);
    CK_ULONG len = 0;
    CK_ATTRIBUTE valueLen{CKA_VALUE_LEN, &len, sizeof(len)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, valueLen), CKR_OK);
    EXPECT_EQ(len, 32u);
    CK_BBOOL never = CK_FALSE;
    CK_ATTRIBUTE neverExtractable{CKA_NEVER_EXTRACTABLE, &never, sizeof(never)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, neverExtractable), CKR_OK);
    EXPECT_EQ(never, CK_TRUE);
    CK_BBOOL always = CK_FALSE;
    CK_ATTRIBUTE alwaysSensitive{CKA_ALWAYS_SENSITIVE, &always, sizeof(always)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, alwaysSensitive), CKR_OK);
    EXPECT_EQ(always, CK_TRUE);
}

// Either half alone keeps the value: a sensitive key that may be extracted
// (wrapped) and an unsensitive key that may not are both unreadable.
TEST(DerivedKeys, OnlyAnUnsensitiveExtractableKeyServesItsValue)
{
    for (const auto& [sensitive, extractable] : {std::pair{false, false}, std::pair{true, true}}) {
        DerivedKey key;
        key.attributes.sensitive = sensitive;
        key.attributes.extractable = extractable;
        key.value.assign(16, 0x5A);
        CK_BYTE buf[16]{};
        CK_ATTRIBUTE value{CKA_VALUE, buf, sizeof(buf)};
        EXPECT_EQ(serveDerivedKeyAttribute(key, value), CKR_ATTRIBUTE_SENSITIVE)
            << "sensitive=" << sensitive << " extractable=" << extractable;
        EXPECT_EQ(value.ulValueLen, CK_UNAVAILABLE_INFORMATION);
        EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + 16), std::vector<std::uint8_t>(16, 0x00));
    }
}

TEST(DerivedKeys, AReadableKeyServesItsValue)
{
    DerivedKey key;
    key.attributes.sensitive = false;
    key.attributes.extractable = true;
    key.value.assign(16, 0x5A);
    CK_BYTE buf[16];
    CK_ATTRIBUTE value{CKA_VALUE, buf, sizeof(buf)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, value), CKR_OK);
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + 16), key.value);
    CK_BBOOL token = CK_TRUE;
    CK_ATTRIBUTE tokenAttr{CKA_TOKEN, &token, sizeof(token)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, tokenAttr), CKR_OK);
    EXPECT_EQ(token, CK_FALSE);
    CK_BBOOL always = CK_TRUE;
    CK_ATTRIBUTE alwaysSensitive{CKA_ALWAYS_SENSITIVE, &always, sizeof(always)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, alwaysSensitive), CKR_OK);
    EXPECT_EQ(always, CK_FALSE);
    CK_BBOOL never = CK_TRUE;
    CK_ATTRIBUTE neverExtractable{CKA_NEVER_EXTRACTABLE, &never, sizeof(never)};
    ASSERT_EQ(serveDerivedKeyAttribute(key, neverExtractable), CKR_OK);
    EXPECT_EQ(never, CK_FALSE);
}

TEST(DerivedKeys, ASearchMatchesClassTypeTokenAndPrivate)
{
    DerivedKey key;
    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_OBJECT_CLASS priv = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE bySecret[] = {{CKA_CLASS, &secret, sizeof(secret)}, {CKA_TOKEN, &kFalse, sizeof(kFalse)}};
    EXPECT_TRUE(derivedKeyMatches(key, bySecret, 2));
    CK_ATTRIBUTE byPrivateKey[] = {{CKA_CLASS, &priv, sizeof(priv)}};
    EXPECT_FALSE(derivedKeyMatches(key, byPrivateKey, 1));
    CK_ATTRIBUTE byToken[] = {{CKA_TOKEN, &kTrue, sizeof(kTrue)}};
    EXPECT_FALSE(derivedKeyMatches(key, byToken, 1));
}

// --- the store: who sees a derived key, and what destroys it ---------------

namespace {

Slot presentSlot(std::string reader, std::string serial)
{
    Slot s;
    s.readerPath = std::move(reader);
    s.tokenPresent = true;
    s.tokenSerial = std::move(serial);
    return s;
}

ObjectModel modelOf(std::vector<Slot> slots)
{
    ObjectModel m;
    m.slots = std::move(slots);
    return m;
}

// A store with readers "a" (slot 0) and "b" (slot 1), each with a card.
SessionState twoCards()
{
    SessionState st;
    st.setModel(modelOf({presentSlot("a", "card-a"), presentSlot("b", "card-b")}));
    return st;
}

CK_SESSION_HANDLE loggedInSession(SessionState& st, CK_SLOT_ID slot)
{
    const CK_SESSION_HANDLE h = st.openSession(slot, CKF_SERIAL_SESSION);
    st.setLoggedIn(slot, std::chrono::steady_clock::now());
    return h;
}

CK_OBJECT_HANDLE keep(SessionState& st, CK_SLOT_ID slot, CK_SESSION_HANDLE creator)
{
    DerivedKey key;
    key.slot = slot;
    key.creator = creator;
    key.value.assign(4, 0x5A);
    return st.addDerivedKey(std::move(key));
}

std::vector<CK_OBJECT_HANDLE> secretsSeenBy(const SessionState& st, CK_SESSION_HANDLE session, CK_SLOT_ID slot)
{
    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_ATTRIBUTE bySecret[] = {{CKA_CLASS, &secret, sizeof(secret)}};
    return st.findMatches(session, slot, bySecret, 1);
}

} // namespace

// A derived key is a private object of its slot: every session there finds it
// while the token is logged in -- the login is the token's, so a session opened
// later does too -- and a session of another slot does not.
TEST(DerivedKeyStore, OnlyALoggedInSessionOfItsSlotSeesAKey)
{
    SessionState st = twoCards();
    const CK_SESSION_HANDLE creator = loggedInSession(st, 0);
    const CK_SESSION_HANDLE later = st.openSession(0, CKF_SERIAL_SESSION);
    const CK_SESSION_HANDLE elsewhere = loggedInSession(st, 1);
    const CK_OBJECT_HANDLE h = keep(st, 0, creator);
    EXPECT_TRUE(SessionState::isDerivedHandle(h));

    EXPECT_NE(st.derivedKey(creator, h), nullptr);
    EXPECT_NE(st.derivedKey(later, h), nullptr) << "a session opened after the login";
    EXPECT_EQ(st.derivedKey(elsewhere, h), nullptr) << "a session of another slot";
    EXPECT_EQ(secretsSeenBy(st, later, 0), std::vector<CK_OBJECT_HANDLE>{h});
    EXPECT_TRUE(secretsSeenBy(st, elsewhere, 1).empty());

    EXPECT_TRUE(st.destroyDerivedKey(h));
    EXPECT_EQ(st.derivedKey(creator, h), nullptr);
    EXPECT_FALSE(st.destroyDerivedKey(h));
}

// Closing a session takes the keys it made and no other; closing every
// session of a slot takes that slot's keys and no other slot's.
TEST(DerivedKeyStore, ClosingSessionsTakesTheirKeysOnly)
{
    SessionState st = twoCards();
    const CK_SESSION_HANDLE first = loggedInSession(st, 0);
    const CK_SESSION_HANDLE second = loggedInSession(st, 0);
    const CK_SESSION_HANDLE onB = loggedInSession(st, 1);
    const CK_OBJECT_HANDLE ofFirst = keep(st, 0, first);
    const CK_OBJECT_HANDLE ofSecond = keep(st, 0, second);
    const CK_OBJECT_HANDLE ofB = keep(st, 1, onB);

    ASSERT_TRUE(st.closeSession(first));
    EXPECT_EQ(st.derivedKey(second, ofFirst), nullptr) << "the closed session's key";
    EXPECT_NE(st.derivedKey(second, ofSecond), nullptr) << "another session's key survives";

    const CK_SESSION_HANDLE third = loggedInSession(st, 0);
    st.closeAllSessions(0);
    const CK_SESSION_HANDLE again = loggedInSession(st, 0);
    EXPECT_EQ(st.derivedKey(again, ofSecond), nullptr);
    EXPECT_EQ(st.session(third), nullptr);
    EXPECT_NE(st.derivedKey(onB, ofB), nullptr) << "another slot's key survives";
}

// A key belongs to the card it was derived with: a refresh that shows the same
// card keeps it, one that shows another card, no card, or no reader does not.
TEST(DerivedKeyStore, AKeyGoesWithItsCard)
{
    SessionState st = twoCards();
    const CK_SESSION_HANDLE a = loggedInSession(st, 0);
    const CK_SESSION_HANDLE b = loggedInSession(st, 1);
    CK_OBJECT_HANDLE onA = keep(st, 0, a);
    const CK_OBJECT_HANDLE onB = keep(st, 1, b);

    st.setModel(modelOf({presentSlot("a", "card-a"), presentSlot("b", "card-b")}));
    EXPECT_NE(st.derivedKey(a, onA), nullptr) << "the same card";

    st.setModel(modelOf({presentSlot("a", "card-a2"), presentSlot("b", "card-b")}));
    EXPECT_EQ(st.derivedKey(a, onA), nullptr) << "another card in the reader";
    EXPECT_NE(st.derivedKey(b, onB), nullptr) << "the other reader's card stayed";

    onA = keep(st, 0, a);
    Slot empty = presentSlot("a", "");
    empty.tokenPresent = false;
    st.setModel(modelOf({empty, presentSlot("b", "card-b")}));
    st.setModel(modelOf({presentSlot("a", "card-a2"), presentSlot("b", "card-b")}));
    EXPECT_EQ(st.derivedKey(a, onA), nullptr) << "the card left and came back";

    onA = keep(st, 0, a);
    st.setModel(modelOf({presentSlot("b", "card-b")}));
    st.setModel(modelOf({presentSlot("a", "card-a2"), presentSlot("b", "card-b")}));
    EXPECT_EQ(st.derivedKey(a, onA), nullptr) << "the reader left";
    EXPECT_NE(st.derivedKey(b, onB), nullptr);
}

// A token that names no serial cannot be told from the next one, so its keys
// do not survive a refresh even when the next one names none either.
TEST(DerivedKeyStore, ATokenWithoutASerialKeepsNoKeyAcrossARefresh)
{
    SessionState st;
    st.setModel(modelOf({presentSlot("a", "")}));
    const CK_SESSION_HANDLE s = loggedInSession(st, 0);
    const CK_OBJECT_HANDLE h = keep(st, 0, s);
    ASSERT_NE(st.derivedKey(s, h), nullptr);
    st.setModel(modelOf({presentSlot("a", "")}));
    EXPECT_EQ(st.derivedKey(s, h), nullptr);
}

// The scope form of secureZero wipes the buffer as it is when the scope ends,
// on a normal exit and on an exception, so a secret copy cannot outlive it.
TEST(SecureZeroOnExit, WipesTheBufferOnEveryWayOut)
{
    std::vector<std::uint8_t> normal{0x11, 0x22};
    {
        const LibreSCRS::Agent::SecureZeroOnExit wipe{normal};
        normal.push_back(0x33); // grown after the guard took it
    }
    EXPECT_EQ(normal, (std::vector<std::uint8_t>{0, 0, 0}));

    std::vector<std::uint8_t> thrown{0x44, 0x55};
    try {
        const LibreSCRS::Agent::SecureZeroOnExit wipe{thrown};
        throw std::runtime_error{"leave"};
    } catch (const std::runtime_error&) {
    }
    EXPECT_EQ(thrown, (std::vector<std::uint8_t>{0, 0}));
}
