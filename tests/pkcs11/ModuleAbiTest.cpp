// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Drive the full C_* ABI of the built module against the socket agent double.
// The module connects to the path the double is listening on, so dlopen +
// C_Initialize wires them together.

#include "SocketFixture.h"
#include "TestCertificates.h"

#include <LibreSCRS/Agent/wire/SyncError.h>
#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <dlfcn.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent::Test;
namespace W = LibreSCRS::Agent::Wire;

namespace {

struct LoadedModule
{
    void* handle = nullptr;
    CK_FUNCTION_LIST_PTR fn = nullptr;

    LoadedModule()
    {
        handle = dlopen(LIBRESCRS_PKCS11_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
        if (!handle)
            return;
        auto getList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(handle, "C_GetFunctionList"));
        if (getList)
            getList(&fn);
    }
    ~LoadedModule()
    {
        if (fn)
            fn->C_Finalize(nullptr);
        if (handle)
            dlclose(handle);
    }
};

// Find the single private-key object on the slot's first session.
CK_OBJECT_HANDLE findPrivateKey(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    EXPECT_EQ(fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[8];
    CK_ULONG n = 0;
    EXPECT_EQ(fn->C_FindObjects(session, objs, 8, &n), CKR_OK);
    EXPECT_EQ(fn->C_FindObjectsFinal(session), CKR_OK);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

CK_SLOT_ID firstPresentSlot(CK_FUNCTION_LIST_PTR fn)
{
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    EXPECT_EQ(fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_GE(n, 1u);
    return slots[0];
}

CK_OBJECT_HANDLE findOne(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls)
{
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    EXPECT_EQ(fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[8];
    CK_ULONG n = 0;
    EXPECT_EQ(fn->C_FindObjects(session, objs, 8, &n), CKR_OK);
    EXPECT_EQ(fn->C_FindObjectsFinal(session), CKR_OK);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

// The new Serbian ID card's single key: EC P-384, the card's own 16-byte iD.
const std::vector<std::uint8_t> kLkKeyId{0xF7, 0x13, 0x4B, 0x02, 0x7C, 0xD6, 0x45, 0x57,
                                         0x86, 0x0A, 0xF5, 0x4E, 0xB9, 0xCD, 0x1D, 0x41};

void seatEcKey(FakeSocketAgent& f, const std::string& certId, bool canDerive = false)
{
    f.setKeyFacts(certId, kLkKeyId, LibreSCRS::Agent::KeyType::Ec, 384, canDerive);
    f.setEcPoint(certId, "P-384", std::vector<std::uint8_t>(48, 0x11), std::vector<std::uint8_t>(48, 0x22));
    // What the agent answers for ECDSA on P-384: r||s, 2 * 48 bytes.
    f.setSignResponder([](const W::PkSignRaw&) { return std::vector<std::uint8_t>(96, 0x5A); });
}

CK_OBJECT_HANDLE findKeyOfType(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls, CK_KEY_TYPE kt)
{
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}, {CKA_KEY_TYPE, &kt, sizeof(kt)}};
    EXPECT_EQ(fn->C_FindObjectsInit(session, tmpl, 2), CKR_OK);
    CK_OBJECT_HANDLE objs[8];
    CK_ULONG n = 0;
    EXPECT_EQ(fn->C_FindObjects(session, objs, 8, &n), CKR_OK);
    EXPECT_EQ(fn->C_FindObjectsFinal(session), CKR_OK);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

std::vector<std::uint8_t> attrBytes(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                                    CK_ATTRIBUTE_TYPE t, CK_RV* rvOut = nullptr)
{
    CK_ATTRIBUTE a{t, nullptr, 0};
    CK_RV rv = fn->C_GetAttributeValue(s, o, &a, 1);
    std::vector<std::uint8_t> out;
    if (rv == CKR_OK) {
        out.resize(a.ulValueLen);
        a.pValue = out.data();
        rv = fn->C_GetAttributeValue(s, o, &a, 1);
    }
    if (rvOut != nullptr)
        *rvOut = rv;
    return out;
}

} // namespace

TEST(ModuleAbi, GetTokenInfoReportsProtectedAuthPathAndPresent)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_TOKEN_INFO ti{};
    ASSERT_EQ(m.fn->C_GetTokenInfo(slot, &ti), CKR_OK);
    EXPECT_TRUE(ti.flags & CKF_PROTECTED_AUTHENTICATION_PATH);
    EXPECT_TRUE(ti.flags & CKF_LOGIN_REQUIRED);
    EXPECT_TRUE(ti.flags & CKF_USER_PIN_INITIALIZED); // NSS offers only "set password" without it

    CK_SLOT_INFO si{};
    ASSERT_EQ(m.fn->C_GetSlotInfo(slot, &si), CKR_OK);
    EXPECT_TRUE(si.flags & CKF_TOKEN_PRESENT);
}

namespace {

// The space-padded field as the string a loader would display.
std::string trimmedField(const CK_UTF8CHAR* field, std::size_t len)
{
    std::string out(reinterpret_cast<const char*>(field), len);
    out.erase(out.find_last_not_of(' ') + 1);
    return out;
}

} // namespace

// Two cards seated at once are two tokens to a loader only if their label or
// serial differ; NSS in particular shows one when both agree. Each token is
// named after the holder its signing certificate names, or after its reader
// when it has none, and carries the card handle's tail as its serial.
TEST(ModuleAbi, SeatedCardsReadAsDistinctTokens)
{
    constexpr const char* kReader1 = "/org/librescrs/Agent/reader/1";
    constexpr const char* kCard1 = "/org/librescrs/Agent/card/1";
    constexpr const char* kReader2 = "/org/librescrs/Agent/reader/2";
    constexpr const char* kCard2 = "/org/librescrs/Agent/card/2";
    // The fixture seats kCard0 with a cert under the default CN; the other two
    // are a second holder and a card with no certificate at all.
    SocketFixture agent(/*hasCard=*/true, "None", [&](FakeSocketAgent& fake) {
        fake.addReader(kReader1, /*hasCard=*/true, kCard1);
        fake.addCert(kCard1, "cert-def", /*signingCapable=*/true, kDecryptableKeyUsage, "Second Holder");
        fake.addReader(kReader2, /*hasCard=*/true, kCard2);
        fake.setReaderName(kReader2, "Reader Two");
    });
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    ASSERT_EQ(n, 3u);

    CK_TOKEN_INFO ti[3]{};
    for (CK_ULONG i = 0; i < 3; ++i)
        ASSERT_EQ(m.fn->C_GetTokenInfo(slots[i], &ti[i]), CKR_OK);

    EXPECT_EQ(trimmedField(ti[0].label, sizeof(ti[0].label)), "Fake Subject");
    EXPECT_EQ(trimmedField(ti[0].serialNumber, sizeof(ti[0].serialNumber)), "0");
    EXPECT_EQ(trimmedField(ti[1].label, sizeof(ti[1].label)), "Second Holder");
    EXPECT_EQ(trimmedField(ti[1].serialNumber, sizeof(ti[1].serialNumber)), "1");
    EXPECT_EQ(trimmedField(ti[2].label, sizeof(ti[2].label)), "Reader Two");
    EXPECT_EQ(trimmedField(ti[2].serialNumber, sizeof(ti[2].serialNumber)), "2");
}

// The label field is 32 bytes of UTF-8. A holder's name longer than that is cut
// where a character starts, never inside one: a loader handed half a character
// shows a replacement glyph or rejects the string.
TEST(ModuleAbi, ALongHolderNameIsCutOnACharacterBoundary)
{
    const std::string name = "Јовановић-Петровић, Александра";
    SocketFixture agent(/*hasCard=*/false, "None", [&](FakeSocketAgent& fake) {
        fake.addReader("/org/librescrs/Agent/reader/9", /*hasCard=*/true, "/org/librescrs/Agent/card/9");
        fake.addCert("/org/librescrs/Agent/card/9", kCertId, /*signingCapable=*/true, kDecryptableKeyUsage, name);
    });
    // The name is chosen so byte 32 falls inside a two-byte character; a name
    // that happened to break cleanly would prove nothing.
    ASSERT_GT(name.size(), 32u);
    ASSERT_EQ(static_cast<unsigned char>(name[32]) & 0xC0, 0x80);

    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_TOKEN_INFO ti{};
    ASSERT_EQ(m.fn->C_GetTokenInfo(firstPresentSlot(m.fn), &ti), CKR_OK);
    EXPECT_EQ(trimmedField(ti.label, sizeof(ti.label)), name.substr(0, 31));
    EXPECT_EQ(ti.label[31], ' ') << "the byte the split character would have taken is padding";
}

// A loader shows the slot description next to the token, so it is the reader's
// own name rather than the agent's handle for it. The two interfaces of one
// dual-interface reader have names that differ only at the end, and the
// 64-byte field keeps that end. A reader the agent names nothing is still
// described, by its handle.
TEST(ModuleAbi, SlotDescriptionIsTheReaderName)
{
    constexpr const char* kReader1 = "/org/librescrs/Agent/reader/1";
    constexpr const char* kReader2 = "/org/librescrs/Agent/reader/2";
    const std::string contact = "HID Global OMNIKEY 5422 Smartcard Reader";
    const std::string contactless = "HID Global OMNIKEY 5422CL Smartcard Reader";
    SocketFixture agent(/*hasCard=*/true, "None", [&](FakeSocketAgent& fake) {
        fake.setReaderName(kReader0, contact);
        fake.addReader(kReader1, contactless);
        fake.addReader(kReader2, "");
    });
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_FALSE, slots, &n), CKR_OK);
    ASSERT_EQ(n, 3u);

    CK_SLOT_INFO si[3]{};
    for (CK_ULONG i = 0; i < 3; ++i)
        ASSERT_EQ(m.fn->C_GetSlotInfo(slots[i], &si[i]), CKR_OK);

    EXPECT_EQ(trimmedField(si[0].slotDescription, sizeof(si[0].slotDescription)), contact);
    EXPECT_EQ(trimmedField(si[1].slotDescription, sizeof(si[1].slotDescription)), contactless);
    EXPECT_EQ(trimmedField(si[2].slotDescription, sizeof(si[2].slotDescription)), kReader2);
}

TEST(ModuleAbi, MechanismListHasRawRsaPkcsOnly_NoHashCombosNoPss)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    CK_MECHANISM_TYPE mechs[16];
    CK_ULONG n = 16;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &n), CKR_OK);
    bool rsa = false, sha256 = false, pss = false;
    for (CK_ULONG i = 0; i < n; ++i) {
        if (mechs[i] == CKM_RSA_PKCS)
            rsa = true;
        if (mechs[i] == CKM_SHA256_RSA_PKCS)
            sha256 = true;
        if (mechs[i] == CKM_RSA_PKCS_PSS)
            pss = true;
    }
    EXPECT_TRUE(rsa);
    EXPECT_FALSE(sha256) << "the libcrypto-free module must not advertise hash-RSA combos";
    EXPECT_FALSE(pss);
    EXPECT_EQ(n, 1u) << "only raw CKM_RSA_PKCS is advertised";

    // The withdrawn combos report CKR_MECHANISM_INVALID from C_GetMechanismInfo.
    CK_MECHANISM_INFO info{};
    EXPECT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_SHA256_RSA_PKCS, &info), CKR_MECHANISM_INVALID);
    ASSERT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_RSA_PKCS, &info), CKR_OK);
    EXPECT_TRUE(info.flags & CKF_SIGN);
    EXPECT_TRUE(info.flags & CKF_DECRYPT);
}

TEST(ModuleAbi, FindAttributesLoginSignDecryptFlow)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // CKA_CLASS + CKA_ID + CKA_SIGN.
    CK_OBJECT_CLASS cls = 0;
    CK_BBOOL canSign = CK_FALSE;
    CK_ATTRIBUTE attrs[] = {{CKA_CLASS, &cls, sizeof(cls)}, {CKA_SIGN, &canSign, sizeof(canSign)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attrs, 2), CKR_OK);
    EXPECT_EQ(cls, CKO_PRIVATE_KEY);
    EXPECT_EQ(canSign, CK_TRUE);

    // C_Login(CKU_USER, NULL, 0): pPin ignored, agent prompter is the auth path.
    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // Sign with raw CKM_RSA_PKCS: the caller supplies a COMPLETE DigestInfo
    // block; the module passes it through VERBATIM (no hashing, no prefix added).
    const std::vector<std::uint8_t> digestInfo = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                                  0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                                                  // 32-byte digest payload:
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                                                  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    ASSERT_EQ(m.fn->C_Sign(session, const_cast<CK_BYTE*>(digestInfo.data()), static_cast<CK_ULONG>(digestInfo.size()),
                           sig, &sigLen),
              CKR_OK);
    std::vector<std::uint8_t> got(sig, sig + sigLen);
    EXPECT_EQ(got, kCannedSig);
    // The agent received the block VERBATIM — the module added no prefix.
    EXPECT_EQ(agent.fake->lastSignInput(), digestInfo);

    // Decrypt (single-part) with CKM_RSA_PKCS.
    CK_MECHANISM dmech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_DecryptInit(session, &dmech, key), CKR_OK);
    std::vector<CK_BYTE> ct(256, 0x01);
    CK_BYTE plain[512];
    CK_ULONG plainLen = sizeof(plain);
    ASSERT_EQ(m.fn->C_Decrypt(session, ct.data(), ct.size(), plain, &plainLen), CKR_OK);
    std::vector<std::uint8_t> gotPlain(plain, plain + plainLen);
    EXPECT_EQ(gotPlain, kCannedPlain);

    // Decrypt (multi-part) with CKM_RSA_PKCS: C_DecryptUpdate buffers, the one
    // on-card decrypt runs at C_DecryptFinal. Update yields no intermediate
    // plaintext (RSA is single-block); Final returns the canned plaintext.
    ASSERT_EQ(m.fn->C_DecryptInit(session, &dmech, key), CKR_OK);
    CK_BYTE upd[512];
    CK_ULONG updLen = sizeof(upd);
    ASSERT_EQ(m.fn->C_DecryptUpdate(session, ct.data(), 128, upd, &updLen), CKR_OK);
    EXPECT_EQ(updLen, 0u);
    updLen = sizeof(upd);
    ASSERT_EQ(m.fn->C_DecryptUpdate(session, ct.data() + 128, 128, upd, &updLen), CKR_OK);
    EXPECT_EQ(updLen, 0u);
    CK_BYTE last[512];
    CK_ULONG lastLen = sizeof(last);
    ASSERT_EQ(m.fn->C_DecryptFinal(session, last, &lastLen), CKR_OK);
    std::vector<std::uint8_t> gotMulti(last, last + lastLen);
    EXPECT_EQ(gotMulti, kCannedPlain);

    EXPECT_EQ(m.fn->C_CloseSession(session), CKR_OK);
}

TEST(ModuleAbi, SignInitRejectsPss)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS_PSS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_MECHANISM_INVALID);
}

TEST(ModuleAbi, SignSizeQueryReturnsModulusBytes)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // The model carries the key's size (the double reports 2048 bits), so the
    // length is answered without the card. A NULL-buffer size query must not error.
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_ULONG sigLen = 0;
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), nullptr, &sigLen), CKR_OK);
    EXPECT_GT(sigLen, 0u);
}

TEST(ModuleAbi, NotLoggedInSurfacedFromSign)
{
    SocketFixture agent(true, "None",
                        [](FakeSocketAgent& f) { f.failCall(Call::PkSignRaw, W::SyncError::UserNotLoggedIn); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    // The agent reports the lease expired -> NSS will transparently re-C_Login.
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen), CKR_USER_NOT_LOGGED_IN);
}

TEST(ModuleAbi, RateLimitedSurfacedFromSign)
{
    SocketFixture agent(true, "None",
                        [](FakeSocketAgent& f) { f.failCall(Call::PkSignRaw, W::SyncError::RateLimited); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    // The agent's PIN-prompt / sign throttle tripped -> the consent-surface
    // rejection surfaces as CKR_FUNCTION_REJECTED, never a generic error.
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen), CKR_FUNCTION_REJECTED);
}

TEST(ModuleAbi, NamHashOnCardOffersSha256RsaPkcsSignOnly)
{
    // Can (hash-on-card / IAS-ECC SSCD) card: it hashes the RAW message
    // on-card, so the proxy advertises CKM_SHA256_RSA_PKCS (sign-only) and NOT
    // CKM_RSA_PKCS (the card rejects a caller-built DigestInfo). Decrypt stays
    // gated (the pkcs15 plugin has no decipher primitive).
    SocketFixture agent(true, "Can");
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    // Mechanism list: exactly {CKM_SHA256_RSA_PKCS}.
    CK_MECHANISM_TYPE mechs[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &n), CKR_OK);
    ASSERT_EQ(n, 1u) << "hash-on-card token advertises exactly one sign mechanism";
    EXPECT_EQ(mechs[0], CKM_SHA256_RSA_PKCS);

    // C_GetMechanismInfo: SIGN only, never DECRYPT; CKM_RSA_PKCS not advertised.
    CK_MECHANISM_INFO info{};
    ASSERT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_SHA256_RSA_PKCS, &info), CKR_OK);
    EXPECT_TRUE((info.flags & CKF_SIGN) != 0);
    EXPECT_TRUE((info.flags & CKF_DECRYPT) == 0) << "hash-on-card sign is sign-only";
    EXPECT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_RSA_PKCS, &info), CKR_MECHANISM_INVALID);

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // C_SignInit rejects the DigestInfo mechanism (the card cannot sign a
    // caller-supplied DigestInfo). A failed init leaves no active operation, so
    // assert the rejection FIRST, then the acceptance of the hash-on-card one.
    CK_MECHANISM raw{CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &raw, key), CKR_MECHANISM_INVALID);
    CK_MECHANISM sha{CKM_SHA256_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &sha, key), CKR_OK);
}

TEST(ModuleAbi, CertValueFetchedLazily)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    ASSERT_EQ(m.fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[4];
    CK_ULONG n = 0;
    ASSERT_EQ(m.fn->C_FindObjects(session, objs, 4, &n), CKR_OK);
    ASSERT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
    ASSERT_EQ(n, 1u);

    CK_ATTRIBUTE val[] = {{CKA_VALUE, nullptr, 0}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, objs[0], val, 1), CKR_OK);
    EXPECT_EQ(val[0].ulValueLen, kCannedDer.size());
}

// ssh-pkcs11 builds the RSA public key from CKA_MODULUS + CKA_PUBLIC_EXPONENT
// on the key objects; if these are absent it skips the key. The crypto-free
// module serves them from the agent's Pkcs11_1.PublicKey bytes.
TEST(ModuleAbi, PublicKeyServesModulusAndExponent)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    const auto expectMod = cannedModulus();

    for (CK_OBJECT_CLASS cls : {CKO_PUBLIC_KEY, CKO_PRIVATE_KEY}) {
        CK_OBJECT_HANDLE key = findOne(m.fn, session, cls);
        ASSERT_NE(key, CK_INVALID_HANDLE);

        // Size query first (pValue==NULL must return the lengths).
        CK_ATTRIBUTE sizeq[] = {{CKA_MODULUS, nullptr, 0}, {CKA_PUBLIC_EXPONENT, nullptr, 0}};
        ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, sizeq, 2), CKR_OK);
        EXPECT_EQ(sizeq[0].ulValueLen, expectMod.size());
        EXPECT_EQ(sizeq[1].ulValueLen, kCannedExponent.size());

        std::vector<CK_BYTE> mod(sizeq[0].ulValueLen);
        std::vector<CK_BYTE> exp(sizeq[1].ulValueLen);
        CK_ATTRIBUTE get[] = {{CKA_MODULUS, mod.data(), (CK_ULONG)mod.size()},
                              {CKA_PUBLIC_EXPONENT, exp.data(), (CK_ULONG)exp.size()}};
        ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, get, 2), CKR_OK);
        std::vector<std::uint8_t> gotMod(mod.begin(), mod.end());
        std::vector<std::uint8_t> gotExp(exp.begin(), exp.end());
        EXPECT_EQ(gotMod, expectMod) << "class " << cls;
        EXPECT_EQ(gotExp, kCannedExponent) << "class " << cls;
    }

    // CKA_MODULUS_BITS belongs to the public key and is derived from the fetched
    // modulus length (256 B -> 2048).
    CK_OBJECT_HANDLE pub = findOne(m.fn, session, CKO_PUBLIC_KEY);
    ASSERT_NE(pub, CK_INVALID_HANDLE);
    CK_ULONG bits = 0;
    CK_ATTRIBUTE bitsAttr[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, pub, bitsAttr, 1), CKR_OK);
    EXPECT_EQ(bits, 2048u);

    EXPECT_EQ(m.fn->C_CloseSession(session), CKR_OK);
}

// A loader re-authenticates before an operation only for a key whose
// CKA_ALWAYS_AUTHENTICATE is TRUE, and that attribute is the card's own rule
// for the key: unmarked reads FALSE, marked reads TRUE.
TEST(ModuleAbi, AnOrdinaryKeyIsNotAlwaysAuthenticate)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_BBOOL always = CK_TRUE; // the module must WRITE false, not leave this
    CK_ATTRIBUTE attr[] = {{CKA_ALWAYS_AUTHENTICATE, &always, sizeof(always)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attr, 1), CKR_OK);
    EXPECT_EQ(always, CK_FALSE);
}

TEST(ModuleAbi, AKeyTheCardMarksIsAlwaysAuthenticate)
{
    SocketFixture agent(/*hasCard=*/true, "None", [](FakeSocketAgent& f) { f.setAlwaysAuthenticate(kCertId); });
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_BBOOL always = CK_FALSE;
    CK_ATTRIBUTE attr[] = {{CKA_ALWAYS_AUTHENTICATE, &always, sizeof(always)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attr, 1), CKR_OK);
    EXPECT_EQ(always, CK_TRUE);
}

// The module must NOT hold the global lock across the blocking
// agent RPC. With a sign parked on a slow fake SignRaw, an unrelated
// C_GetSlotList (served from the snapshot cache) must still proceed promptly.
TEST(ModuleAbi, NoAppWideStallWhileSignParked)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn); // first enumeration -> cache warm
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // Park a sign on a slow SignRaw (3s).
    agent.fake->delayCall(Call::PkSignRaw, std::chrono::milliseconds{3000});
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    auto signFut = std::async(std::launch::async, [&] {
        CK_BYTE sig[512];
        CK_ULONG sigLen = sizeof(sig);
        return m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen);
    });

    // Give the worker time to enter the parked SignRaw.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // C_GetSlotList (cache path: no agent round-trip) must return well within the
    // parked sign's 3s. If the module held g_mutex across the RPC it would block
    // here for ~3s.
    const auto t0 = std::chrono::steady_clock::now();
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    EXPECT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 1500)
        << "C_GetSlotList stalled behind the parked sign -> lock not narrowed";

    EXPECT_EQ(signFut.get(), CKR_OK);
}

// A slow (>25s) interactive op must NOT spuriously map to
// CKR_DEVICE_REMOVED — sd-bus's ~25s default would otherwise raise NoReply. The
// module sets a generous timeout on the interactive Pkcs11_1 calls.
TEST(ModuleAbi, SlowSignDoesNotMapToDeviceRemoved)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // 27s > sd-bus's ~25s default; with the module's larger timeout the call
    // completes normally instead of NoReply -> CKR_DEVICE_REMOVED.
    agent.fake->delayCall(Call::PkSignRaw, std::chrono::milliseconds{27000});
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    const CK_RV rv = m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen);
    EXPECT_NE(rv, CKR_DEVICE_REMOVED) << "slow op spuriously timed out to CKR_DEVICE_REMOVED";
    EXPECT_EQ(rv, CKR_OK);
}

// A CKA_VALUE (cert DER) fetch failure must map to the bus-state CKR_*
// (CKR_DEVICE_ERROR for a CommunicationError), not the generic CKR_FUNCTION_FAILED.
TEST(ModuleAbi, CertValueFetchFailureMapsToDeviceError)
{
    SocketFixture agent(true, "None",
                        [](FakeSocketAgent& f) { f.failCall(Call::GetCertDer, W::SyncError::CommunicationError); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE cert = findOne(m.fn, session, CKO_CERTIFICATE);
    ASSERT_NE(cert, CK_INVALID_HANDLE);

    CK_ATTRIBUTE val[] = {{CKA_VALUE, nullptr, 0}};
    EXPECT_EQ(m.fn->C_GetAttributeValue(session, cert, val, 1), CKR_DEVICE_ERROR);
}

// NSS reads a token certificate's subject, issuer and serial together with its
// DER, in one call, and files the certificate under them; one without them is
// never offered for client authentication. They are the certificate's own bytes.
TEST(ModuleAbi, ACertificateServesItsNamesAndSerialAsEncoded)
{
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) { f.setCertDer(kCertId, kTestLeafDer); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE cert = findOne(m.fn, session, CKO_CERTIFICATE);
    ASSERT_NE(cert, CK_INVALID_HANDLE);

    CK_ATTRIBUTE sizes[] = {
        {CKA_VALUE, nullptr, 0}, {CKA_SUBJECT, nullptr, 0}, {CKA_ISSUER, nullptr, 0}, {CKA_SERIAL_NUMBER, nullptr, 0}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, cert, sizes, 4), CKR_OK);
    EXPECT_EQ(attrBytes(m.fn, session, cert, CKA_SUBJECT), kTestLeafSubject);
    EXPECT_EQ(attrBytes(m.fn, session, cert, CKA_ISSUER), kTestLeafIssuer);
    EXPECT_EQ(attrBytes(m.fn, session, cert, CKA_SERIAL_NUMBER), kTestLeafSerial);
}

// A search by subject, or by issuer and serial, is how NSS finds a certificate's
// issuer and tells two certificates apart: it finds that certificate, no other.
TEST(ModuleAbi, FindObjectsMatchesACertificateByItsNames)
{
    constexpr const char* kCaCert = "cert-ca";
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) {
        f.setCertDer(kCertId, kTestLeafDer);
        f.addCert(kCard0, kCaCert, /*signingCapable=*/true, 0, "LibreSCRS Test CA");
        f.setCertDer(kCaCert, kTestCaDer);
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const auto find = [&](std::vector<CK_ATTRIBUTE> tmpl) {
        EXPECT_EQ(m.fn->C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size())), CKR_OK);
        CK_OBJECT_HANDLE objs[16];
        CK_ULONG n = 0;
        EXPECT_EQ(m.fn->C_FindObjects(session, objs, 16, &n), CKR_OK);
        EXPECT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
        return std::vector<CK_OBJECT_HANDLE>(objs, objs + n);
    };
    const auto derOf = [&](const std::vector<CK_OBJECT_HANDLE>& found) {
        return found.size() == 1 ? attrBytes(m.fn, session, found[0], CKA_VALUE) : std::vector<std::uint8_t>{};
    };
    auto caSubject = kTestLeafIssuer; // the leaf's issuer is the CA's subject
    auto leafSubject = kTestLeafSubject;
    auto leafIssuer = kTestLeafIssuer;
    auto leafSerial = kTestLeafSerial;
    std::vector<std::uint8_t> nobody(kTestLeafSubject);
    nobody.back() ^= 0x01;

    EXPECT_EQ(derOf(find({{CKA_SUBJECT, caSubject.data(), caSubject.size()}})), kTestCaDer)
        << "the CA alone: not the certificate it issued, and no key";
    EXPECT_EQ(derOf(find({{CKA_SUBJECT, leafSubject.data(), leafSubject.size()}})), kTestLeafDer);
    EXPECT_EQ(derOf(find({{CKA_ISSUER, leafIssuer.data(), leafIssuer.size()},
                          {CKA_SERIAL_NUMBER, leafSerial.data(), leafSerial.size()}})),
              kTestLeafDer)
        << "the CA has the same issuer; the serial tells them apart";
    EXPECT_TRUE(find({{CKA_SUBJECT, nobody.data(), nobody.size()}}).empty());
}

// The template's length is the caller's word: one no certificate field can have
// is no match, never an allocation of that size across the C boundary.
TEST(ModuleAbi, FindObjectsByANameOfImpossibleLengthFindsNothing)
{
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) { f.setCertDer(kCertId, kTestLeafDer); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    auto subject = kTestLeafSubject;
    CK_ATTRIBUTE tmpl[] = {{CKA_SUBJECT, subject.data(), ~CK_ULONG{0} >> 1}};
    ASSERT_EQ(m.fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[4];
    CK_ULONG n = 0;
    EXPECT_EQ(m.fn->C_FindObjects(session, objs, 4, &n), CKR_OK);
    EXPECT_EQ(n, 0u);
    EXPECT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
}

// Each certificate DER the agent sends is a read of the card -- over secure
// messaging on a contactless one -- and NSS asks for the DER, both names and the
// serial of every certificate in one call, then searches by them. The module
// reads each certificate once; its id is the DER's SHA-256, so what it keeps
// cannot stand for another certificate.
TEST(ModuleAbi, ACertificateIsReadFromTheCardOnce)
{
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) { f.setCertDer(kCertId, kTestLeafDer); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE cert = findOne(m.fn, session, CKO_CERTIFICATE);
    ASSERT_NE(cert, CK_INVALID_HANDLE);

    CK_ATTRIBUTE sizes[] = {
        {CKA_VALUE, nullptr, 0}, {CKA_SUBJECT, nullptr, 0}, {CKA_ISSUER, nullptr, 0}, {CKA_SERIAL_NUMBER, nullptr, 0}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, cert, sizes, 4), CKR_OK);
    EXPECT_EQ(attrBytes(m.fn, session, cert, CKA_SUBJECT), kTestLeafSubject);
    auto subject = kTestLeafSubject;
    CK_ATTRIBUTE bySubject[] = {{CKA_SUBJECT, subject.data(), subject.size()}};
    ASSERT_EQ(m.fn->C_FindObjectsInit(session, bySubject, 1), CKR_OK);
    ASSERT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
    EXPECT_EQ(agent.fake->callCount(Call::GetCertDer), 1);
}

// A certificate whose DER does not parse has no names: the attribute is absent,
// as on any object without one, and a search by name does not find it.
TEST(ModuleAbi, AMalformedCertificateHasNoNames)
{
    SocketFixture agent; // the double's canned DER is a truncated header
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE cert = findOne(m.fn, session, CKO_CERTIFICATE);
    ASSERT_NE(cert, CK_INVALID_HANDLE);

    CK_RV rv = CKR_OK;
    (void)attrBytes(m.fn, session, cert, CKA_SUBJECT, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_TYPE_INVALID);
    auto subject = kTestLeafSubject;
    CK_ATTRIBUTE bySubject[] = {{CKA_SUBJECT, subject.data(), subject.size()}};
    ASSERT_EQ(m.fn->C_FindObjectsInit(session, bySubject, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[4];
    CK_ULONG n = 0;
    EXPECT_EQ(m.fn->C_FindObjects(session, objs, 4, &n), CKR_OK);
    EXPECT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
    EXPECT_EQ(n, 0u);
}

// A second C_Login while already logged in returns CKR_USER_ALREADY_LOGGED_IN.
TEST(ModuleAbi, SecondLoginReturnsAlreadyLoggedIn)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_USER_ALREADY_LOGGED_IN);
}

// A loader (ssh-pkcs11, NSS, Firefox) re-authenticates a key whose
// CKA_ALWAYS_AUTHENTICATE is TRUE with C_Login(CKU_CONTEXT_SPECIFIC) between
// C_SignInit and C_Sign. That re-auth must SUCCEED (lease refresh) even while
// already CKU_USER-logged-in — NOT be rejected the way a repeat CKU_USER login
// is (cf. SecondLoginReturnsAlreadyLoggedIn). Without this, such a loader
// cannot sign with a key the card marks at all.
TEST(ModuleAbi, ContextSpecificLoginAcceptedForReauth)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(m.fn->C_Login(session, CKU_CONTEXT_SPECIFIC, nullptr, 0), CKR_OK);
    EXPECT_EQ(m.fn->C_Login(session, CKU_CONTEXT_SPECIFIC, nullptr, 0), CKR_OK)
        << "repeated per-operation re-auth must keep succeeding";
}

// The agent refuses a signature or a decryption with "not logged in" once the
// lease is gone (idle, lifetime, card removed). From that answer on the
// session is PUBLIC again, so a loader that reads the state logs in afresh --
// and that login is accepted rather than refused as already logged in.
TEST(ModuleAbi, AnExpiredLeaseReturnsTheSessionToPublic)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    CK_SESSION_INFO info{};

    // Sign.
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    agent.fake->failCall(Call::PkSignRaw, W::SyncError::UserNotLoggedIn);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen), CKR_USER_NOT_LOGGED_IN);
    ASSERT_EQ(m.fn->C_GetSessionInfo(session, &info), CKR_OK);
    EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION) << "a lapsed lease must not leave the session reading as logged in";

    // Decrypt, after a fresh login the module must accept.
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    agent.fake->failCall(Call::PkDecrypt, W::SyncError::UserNotLoggedIn);
    ASSERT_EQ(m.fn->C_DecryptInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> ct(256, 0x22);
    CK_BYTE plain[512];
    CK_ULONG plainLen = sizeof(plain);
    EXPECT_EQ(m.fn->C_Decrypt(session, ct.data(), ct.size(), plain, &plainLen), CKR_USER_NOT_LOGGED_IN);
    ASSERT_EQ(m.fn->C_GetSessionInfo(session, &info), CKR_OK);
    EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

CK_STATE sessionState(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info{};
    EXPECT_EQ(fn->C_GetSessionInfo(session, &info), CKR_OK);
    return info.state;
}

// PKCS#11 v2.40 section 5.6: a login is the application's, on the token. Every
// session of that token is a user session from C_Login on, the ones opened
// afterwards too, and C_Logout on any of them ends it for all.
TEST(ModuleAbi, ALoginCoversEverySessionOfTheToken)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    const CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE a = 0;
    CK_SESSION_HANDLE b = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &a), CKR_OK);
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &b), CKR_OK);

    ASSERT_EQ(m.fn->C_Login(a, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(sessionState(m.fn, b), CKS_RO_USER_FUNCTIONS) << "a session opened before the login";
    CK_SESSION_HANDLE c = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &c), CKR_OK);
    EXPECT_EQ(sessionState(m.fn, c), CKS_RO_USER_FUNCTIONS) << "a session opened after the login";
    EXPECT_EQ(m.fn->C_Login(b, CKU_USER, nullptr, 0), CKR_USER_ALREADY_LOGGED_IN);

    ASSERT_EQ(m.fn->C_Logout(b), CKR_OK);
    EXPECT_EQ(sessionState(m.fn, a), CKS_RO_PUBLIC_SESSION);
    EXPECT_EQ(sessionState(m.fn, c), CKS_RO_PUBLIC_SESSION);
}

// NSS asks whether it is logged in on a session of its own, and signs on
// another. When the agent says the login is gone on the signing session, the
// session NSS asks on must say so too, or NSS never logs in again and every
// later signature fails the same way.
TEST(ModuleAbi, ALapseSeenOnOneSessionEndsTheLoginOfAll)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    const CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE asked = 0;
    CK_SESSION_HANDLE signing = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &asked), CKR_OK);
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &signing), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(asked, CKU_USER, nullptr, 0), CKR_OK);
    const CK_OBJECT_HANDLE key = findPrivateKey(m.fn, signing);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    agent.fake->failCall(Call::PkSignRaw, W::SyncError::UserNotLoggedIn);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(signing, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    ASSERT_EQ(m.fn->C_Sign(signing, data.data(), data.size(), sig, &sigLen), CKR_USER_NOT_LOGGED_IN);

    EXPECT_EQ(sessionState(m.fn, asked), CKS_RO_PUBLIC_SESSION);
    EXPECT_EQ(m.fn->C_Login(asked, CKU_USER, nullptr, 0), CKR_OK) << "the application logs in afresh";
}

// The state names the session's own kind: read/write sessions of a logged-in
// token read as read/write user sessions.
TEST(ModuleAbi, ARwSessionReadsAsRwUser)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    const CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE ro = 0;
    CK_SESSION_HANDLE rw = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro), CKR_OK);
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &rw), CKR_OK);
    EXPECT_EQ(sessionState(m.fn, rw), CKS_RW_PUBLIC_SESSION);
    ASSERT_EQ(m.fn->C_Login(ro, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(sessionState(m.fn, rw), CKS_RW_USER_FUNCTIONS);
    EXPECT_EQ(sessionState(m.fn, ro), CKS_RO_USER_FUNCTIONS);
}

// A login is on the card it was made with. Once that card leaves the reader the
// token's sessions are public, whatever card is seated afterwards.
TEST(ModuleAbi, ANewCardInTheReaderEndsTheLogin)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    const CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    agent.fake->swapCard("another-card");
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_FALSE, slots, &n), CKR_OK); // the refresh sees the other card
    EXPECT_EQ(sessionState(m.fn, session), CKS_RO_PUBLIC_SESSION);
}

// For a key the card marks, every call that reaches the card is a PIN prompt.
// So asking how long the signature will be -- with no buffer, or with one too
// small -- is answered from the key's modulus and never reaches the agent's
// sign; the operation stays active, and the call that does sign signs once.
TEST(ModuleAbi, SignLengthQueriesNeverReachTheCard)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    const CK_ULONG modulusBytes = cannedModulus().size();

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);

    CK_ULONG len = 0;
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), nullptr, &len), CKR_OK);
    EXPECT_EQ(len, modulusBytes);
    EXPECT_EQ(agent.fake->callCount(Call::PkSignRaw), 0) << "a length query signed on the card";

    CK_BYTE small[8];
    len = sizeof(small);
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), small, &len), CKR_BUFFER_TOO_SMALL);
    EXPECT_EQ(len, modulusBytes);
    EXPECT_EQ(agent.fake->callCount(Call::PkSignRaw), 0) << "a too-small buffer signed on the card";

    CK_BYTE sig[512];
    len = sizeof(sig);
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &len), CKR_OK)
        << "the operation must still be active after the two length answers";
    EXPECT_EQ(agent.fake->callCount(Call::PkSignRaw), 1);
}

// The same for a decryption: with no buffer the module answers the modulus
// length, which bounds any PKCS#1 v1.5 plaintext, without decrypting.
TEST(ModuleAbi, DecryptLengthQueryNeverReachesTheCard)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_DecryptInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> ct(256, 0x22);

    CK_ULONG len = 0;
    EXPECT_EQ(m.fn->C_Decrypt(session, ct.data(), ct.size(), nullptr, &len), CKR_OK);
    EXPECT_EQ(len, static_cast<CK_ULONG>(cannedModulus().size()));
    EXPECT_EQ(agent.fake->callCount(Call::PkDecrypt), 0) << "a length query decrypted on the card";

    CK_BYTE plain[512];
    len = sizeof(plain);
    EXPECT_EQ(m.fn->C_Decrypt(session, ct.data(), ct.size(), plain, &len), CKR_OK)
        << "the operation must still be active after the length answer";
    EXPECT_EQ(len, static_cast<CK_ULONG>(kCannedPlain.size()));
    EXPECT_EQ(agent.fake->callCount(Call::PkDecrypt), 1);
}

// The widened userType check must NOT become a blanket accept: CKU_SO
// (security officer) is not a supported role for this token.
TEST(ModuleAbi, UnsupportedLoginUserTypeRejected)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    EXPECT_EQ(m.fn->C_Login(session, CKU_SO, nullptr, 0), CKR_USER_TYPE_INVALID);
}

TEST(ModuleAbi, LiveSlotUpdateOnCardRemoveAndInsert)
{
    // Card present -> 1 present slot. Remove the card + emit InterfacesRemoved
    // -> the next C_GetSlotList(present) drops it. Re-insert -> it returns.
    // ObjectManager signals invalidate the module's snapshot cache.
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_EQ(n, 1u);

    agent.fake->removeCard();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_EQ(n, 0u) << "card removal must drop the present-slot count";

    agent.fake->insertCard();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_EQ(n, 1u) << "card re-insertion must restore the present slot";
}

// C_Finalize concurrent with an in-flight blocking RPC must NOT destroy
// the library (g_lib.reset()) while the RPC thread is still inside signRaw on
// it — that is a use-after-free (the narrowing that released g_mutex across the
// RPC introduced it). C_Finalize must DRAIN the in-flight RPC count before the
// reset. With the fix the parked sign completes with CKR_OK (the library lived
// through the whole call) and C_Finalize returns CKR_OK only after the drain.
// Run under ASan (CTest 'asan' suite) to prove no UAF; the racer is otherwise
// never exercised by the suite.
TEST(ModuleAbi, FinalizeDrainsInFlightRpcNoUaf)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // Park a sign on a slow SignRaw: the RPC thread sits inside
    // g_lib->client.signRaw with g_mutex RELEASED for ~2s.
    agent.fake->delayCall(Call::PkSignRaw, std::chrono::milliseconds{2000});
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    std::atomic<CK_RV> signRv{CKR_VENDOR_DEFINED};
    std::thread signThread([&] {
        CK_BYTE sig[512];
        CK_ULONG sigLen = sizeof(sig);
        signRv.store(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen));
    });

    // Let the worker enter the parked SignRaw (g_lib in use, lock released).
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    // C_Finalize NOW, mid-RPC. It must wait for the RPC to drain before
    // g_lib.reset() — so the call blocks ~the rest of the 2s, then returns OK.
    // Without the drain it would reset g_lib under the RPC thread -> UAF.
    const auto t0 = std::chrono::steady_clock::now();
    const CK_RV finRv = m.fn->C_Finalize(nullptr);
    const auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_EQ(finRv, CKR_OK);
    EXPECT_GE(elapsedMs, 800) << "C_Finalize returned before the in-flight RPC drained";

    signThread.join();
    // The parked sign ran to completion against a live library (no UAF).
    EXPECT_EQ(signRv.load(), CKR_OK) << "the in-flight sign must complete against a live library";

    // We already finalized; the LoadedModule dtor's second C_Finalize is a
    // harmless NOT_INITIALIZED. Re-init is unnecessary.
}

// An EC key reads as one: CKK_EC, the curve's OID, the point (on the public
// key), the card's own CKA_ID, no RSA attributes, no decryption.
TEST(ModuleAbi, AnEcKeyIsAnEcKeyWithItsCurveAndPoint)
{
    SocketFixture agent(true, "Can", [](FakeSocketAgent& f) { seatEcKey(f, kCertId); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE pub = findKeyOfType(m.fn, session, CKO_PUBLIC_KEY, CKK_EC);
    const CK_OBJECT_HANDLE priv = findKeyOfType(m.fn, session, CKO_PRIVATE_KEY, CKK_EC);
    ASSERT_NE(pub, CK_INVALID_HANDLE);
    ASSERT_NE(priv, CK_INVALID_HANDLE);
    // Read back, not only searched by: the search and the attribute are two
    // code paths, and a loader reads the attribute.
    for (const CK_OBJECT_HANDLE key : {pub, priv}) {
        CK_KEY_TYPE kt = CKK_RSA;
        CK_ATTRIBUTE ktAttr{CKA_KEY_TYPE, &kt, sizeof(kt)};
        ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, &ktAttr, 1), CKR_OK);
        EXPECT_EQ(kt, static_cast<CK_KEY_TYPE>(CKK_EC));
    }

    const std::vector<std::uint8_t> p384Oid{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    EXPECT_EQ(attrBytes(m.fn, session, pub, CKA_EC_PARAMS), p384Oid);
    EXPECT_EQ(attrBytes(m.fn, session, priv, CKA_EC_PARAMS), p384Oid);
    const auto point = attrBytes(m.fn, session, pub, CKA_EC_POINT);
    ASSERT_EQ(point.size(), 2u + 97u);
    EXPECT_EQ(point[0], 0x04);
    EXPECT_EQ(point[1], 0x61);
    EXPECT_EQ(point[2], 0x04);
    EXPECT_EQ(attrBytes(m.fn, session, priv, CKA_ID), kLkKeyId);
    EXPECT_EQ(attrBytes(m.fn, session, pub, CKA_ID), kLkKeyId);

    CK_RV rv = CKR_OK;
    (void)attrBytes(m.fn, session, pub, CKA_MODULUS, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_TYPE_INVALID) << "no RSA attribute on an EC key";
    (void)attrBytes(m.fn, session, priv, CKA_EC_POINT, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_TYPE_INVALID) << "the point belongs to the public key";
    CK_BBOOL decrypt = CK_TRUE;
    CK_BBOOL unwrap = CK_TRUE;
    CK_BBOOL derive = CK_TRUE;
    CK_ATTRIBUTE flags[] = {{CKA_DECRYPT, &decrypt, sizeof(decrypt)},
                            {CKA_UNWRAP, &unwrap, sizeof(unwrap)},
                            {CKA_DERIVE, &derive, sizeof(derive)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, priv, flags, 3), CKR_OK);
    EXPECT_EQ(decrypt, CK_FALSE);
    EXPECT_EQ(unwrap, CK_FALSE);
    EXPECT_EQ(derive, CK_FALSE) << "a key the agent does not derive with";
    // Every key has CKA_DERIVE: a public key does not derive.
    derive = CK_TRUE;
    CK_ATTRIBUTE pubDerive{CKA_DERIVE, &derive, sizeof(derive)};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, pub, &pubDerive, 1), CKR_OK);
    EXPECT_EQ(derive, CK_FALSE);
}

TEST(ModuleAbi, AnRsaKeyHasNoEcAttributes)
{
    SocketFixture agent;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE pub = findKeyOfType(m.fn, session, CKO_PUBLIC_KEY, CKK_RSA);
    ASSERT_NE(pub, CK_INVALID_HANDLE);
    CK_RV rv = CKR_OK;
    (void)attrBytes(m.fn, session, pub, CKA_EC_PARAMS, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_TYPE_INVALID);
    (void)attrBytes(m.fn, session, pub, CKA_EC_POINT, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_TYPE_INVALID);
    const std::string id{kCertId};
    EXPECT_EQ(attrBytes(m.fn, session, pub, CKA_ID), (std::vector<std::uint8_t>(id.begin(), id.end())))
        << "CKA_ID is the agent's keyId (the double fills it with the certId's bytes), not a counter";
}

// The new ID card is a PACE card: its EC key signs CKM_ECDSA over the
// caller's digest, never the RSA hash-on-card mechanism, and every length
// question is answered from the model.
TEST(ModuleAbi, AnEcKeyOnAPaceCardSignsEcdsaNotHashOnCard)
{
    SocketFixture agent(true, "Can", [](FakeSocketAgent& f) { seatEcKey(f, kCertId); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    const CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_MECHANISM_TYPE mechs[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &n), CKR_OK);
    const std::vector<CK_MECHANISM_TYPE> list(mechs, mechs + n);
    EXPECT_NE(std::find(list.begin(), list.end(), CKM_ECDSA), list.end());
    EXPECT_EQ(std::find(list.begin(), list.end(), CKM_SHA256_RSA_PKCS), list.end());

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    const CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> digest(48, 0xAB);
    CK_ULONG len = 0;
    EXPECT_EQ(m.fn->C_Sign(session, digest.data(), digest.size(), nullptr, &len), CKR_OK);
    EXPECT_EQ(len, 96u) << "2 * ceil(384 / 8)";
    EXPECT_EQ(agent.fake->callCount(Call::PkSignRaw), 0);
    EXPECT_EQ(agent.fake->callCount(Call::PkPublicKey), 0) << "the length comes from the model, not the key";
    CK_BYTE sig[128];
    len = sizeof(sig);
    ASSERT_EQ(m.fn->C_Sign(session, digest.data(), digest.size(), sig, &len), CKR_OK);
    EXPECT_EQ(agent.fake->lastSignMechanism(), "ecdsa");
    EXPECT_EQ(agent.fake->lastSignInput(), std::vector<std::uint8_t>(digest.begin(), digest.end()));
}

// ECDSA takes the digest itself, 32/48/64 bytes; anything else is refused
// without the agent (narrower than v2.40, which would truncate a longer input).
TEST(ModuleAbi, EcdsaRefusesADigestOfTheWrongLength)
{
    SocketFixture agent(true, "Can", [](FakeSocketAgent& f) { seatEcKey(f, kCertId); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    const CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    for (const std::size_t bad : {std::size_t{20}, std::size_t{51}}) {
        CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
        ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
        std::vector<CK_BYTE> data(bad, 0x01);
        CK_BYTE sig[128];
        CK_ULONG len = sizeof(sig);
        EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &len), CKR_DATA_LEN_RANGE) << bad;
    }
    EXPECT_EQ(agent.fake->callCount(Call::PkSignRaw), 0);
}

// A mechanism of the other family is the key's type, not a missing mechanism.
TEST(ModuleAbi, AMechanismOfTheOtherFamilyIsKeyTypeInconsistent)
{
    constexpr const char* kEcCert = "cert-ec";
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) {
        f.addCert(kCard0, kEcCert, /*signingCapable=*/true, kDecryptableKeyUsage, "EC Holder");
        seatEcKey(f, kEcCert);
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE rsaKey = findKeyOfType(m.fn, session, CKO_PRIVATE_KEY, CKK_RSA);
    const CK_OBJECT_HANDLE ecKey = findKeyOfType(m.fn, session, CKO_PRIVATE_KEY, CKK_EC);
    ASSERT_NE(rsaKey, CK_INVALID_HANDLE);
    ASSERT_NE(ecKey, CK_INVALID_HANDLE);
    CK_MECHANISM ecdsa{CKM_ECDSA, nullptr, 0};
    CK_MECHANISM rsa{CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &ecdsa, rsaKey), CKR_KEY_TYPE_INCONSISTENT);
    EXPECT_EQ(m.fn->C_SignInit(session, &rsa, ecKey), CKR_KEY_TYPE_INCONSISTENT);
    EXPECT_EQ(m.fn->C_DecryptInit(session, &rsa, ecKey), CKR_KEY_TYPE_INCONSISTENT);
}

TEST(ModuleAbi, EcMechanismInfoCarriesTheCurveFlags)
{
    SocketFixture agent(true, "Can", [](FakeSocketAgent& f) { seatEcKey(f, kCertId); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_MECHANISM_INFO info{};
    ASSERT_EQ(m.fn->C_GetMechanismInfo(firstPresentSlot(m.fn), CKM_ECDSA, &info), CKR_OK);
    EXPECT_EQ(info.ulMinKeySize, 256u);
    EXPECT_EQ(info.ulMaxKeySize, 521u);
    EXPECT_EQ(info.flags, CKF_HW | CKF_SIGN | CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS);
}

// A search by key type or by CKA_PRIVATE no longer returns every object.
TEST(ModuleAbi, FindObjectsMatchesKeyTypeAndPrivate)
{
    constexpr const char* kEcCert = "cert-ec";
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) {
        f.addCert(kCard0, kEcCert, /*signingCapable=*/true, 0, "EC Holder");
        seatEcKey(f, kEcCert);
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const auto count = [&](CK_ATTRIBUTE* tmpl, CK_ULONG n) {
        EXPECT_EQ(m.fn->C_FindObjectsInit(session, tmpl, n), CKR_OK);
        CK_OBJECT_HANDLE objs[16];
        CK_ULONG found = 0;
        EXPECT_EQ(m.fn->C_FindObjects(session, objs, 16, &found), CKR_OK);
        EXPECT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
        return found;
    };
    CK_KEY_TYPE ec = CKK_EC;
    CK_ATTRIBUTE byType[] = {{CKA_KEY_TYPE, &ec, sizeof(ec)}};
    EXPECT_EQ(count(byType, 1), 2u) << "the EC public and private key, nothing else";
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE byPrivate[] = {{CKA_PRIVATE, &yes, sizeof(yes)}};
    EXPECT_EQ(count(byPrivate, 1), 2u) << "the two private keys";
}

// An input the agent refuses before any prompt reaches the caller as the
// standard's length error for that call -- and the session stays logged in.
TEST(ModuleAbi, AnInputTheAgentRefusesIsALengthError)
{
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) {
        f.failCall(Call::PkSignRaw, W::SyncError::InvalidRequest);
        f.failCall(Call::PkDecrypt, W::SyncError::InvalidRequest);
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    const CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(51, 0x30);
    CK_BYTE out[512];
    CK_ULONG len = sizeof(out);
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), out, &len), CKR_DATA_LEN_RANGE);
    ASSERT_EQ(m.fn->C_DecryptInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> ct(256, 0x01);
    len = sizeof(out);
    EXPECT_EQ(m.fn->C_Decrypt(session, ct.data(), ct.size(), out, &len), CKR_ENCRYPTED_DATA_LEN_RANGE);
    CK_SESSION_INFO si{};
    ASSERT_EQ(m.fn->C_GetSessionInfo(session, &si), CKR_OK);
    EXPECT_NE(si.state, static_cast<CK_STATE>(CKS_RO_PUBLIC_SESSION)) << "a refused input is not a lapsed lease";
}

// The agent's ECDSA answer is r||s at the curve's width. Anything else -- a
// DER-shaped or a truncated reply -- never reaches the caller (NSS, ssh) as a
// signature, and the operation ends.
TEST(ModuleAbi, AnEcdsaReplyOfTheWrongWidthIsADeviceError)
{
    SocketFixture agent(true, "Can", [](FakeSocketAgent& f) {
        seatEcKey(f, kCertId);
        f.setSignResponder([](const W::PkSignRaw&) { return std::vector<std::uint8_t>(95, 0x5A); });
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    const CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> digest(48, 0xAB);
    CK_BYTE sig[128];
    CK_ULONG len = sizeof(sig);
    EXPECT_EQ(m.fn->C_Sign(session, digest.data(), digest.size(), sig, &len), CKR_DEVICE_ERROR);
    EXPECT_EQ(agent.fake->callCount(Call::PkSignRaw), 1);
    len = sizeof(sig);
    EXPECT_EQ(m.fn->C_Sign(session, digest.data(), digest.size(), sig, &len), CKR_OPERATION_NOT_INITIALIZED)
        << "the failed signature ended the operation";
}

// The point served is the one on the curve CKA_EC_PARAMS names for the key's
// size. An agent that reports a P-384 key and answers a well-formed P-256 point
// would publish a key that contradicts itself; the point is withheld instead.
TEST(ModuleAbi, AnEcPointOffTheKeysCurveIsNotServed)
{
    SocketFixture agent(true, "Can", [](FakeSocketAgent& f) {
        seatEcKey(f, kCertId);
        f.setEcPoint(kCertId, "P-256", std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 0x22));
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    const CK_OBJECT_HANDLE pub = findKeyOfType(m.fn, session, CKO_PUBLIC_KEY, CKK_EC);
    ASSERT_NE(pub, CK_INVALID_HANDLE);
    EXPECT_EQ(attrBytes(m.fn, session, pub, CKA_EC_PARAMS),
              (std::vector<std::uint8_t>{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}));
    CK_RV rv = CKR_OK;
    (void)attrBytes(m.fn, session, pub, CKA_EC_POINT, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_TYPE_INVALID) << "a P-256 point served for a P-384 key";
}

namespace {

// A logged-in session on an EC card whose key derives.
struct DeriveRig
{
    SocketFixture agent;
    LoadedModule m;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;

    explicit DeriveRig(const std::function<void(FakeSocketAgent&)>& extra = {})
        : agent(true, "None", [&extra](FakeSocketAgent& f) {
              seatEcKey(f, kCertId, /*canDerive=*/true);
              if (extra)
                  extra(f);
          })
    {
        EXPECT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
        EXPECT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
        EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
        base = findPrivateKey(m.fn, session);
    }
};

std::vector<std::uint8_t> p384Point()
{
    std::vector<std::uint8_t> p(97, 0x33);
    p[0] = 0x04;
    return p;
}

CK_RV deriveWith(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE base,
                 std::vector<std::uint8_t> publicData, CK_ATTRIBUTE* tmpl, CK_ULONG count, CK_OBJECT_HANDLE* out,
                 CK_EC_KDF_TYPE kdf = CKD_NULL, CK_ULONG sharedLen = 0)
{
    CK_BYTE shared = 0x01;
    CK_ECDH1_DERIVE_PARAMS params{kdf, sharedLen, sharedLen ? &shared : nullptr,
                                  static_cast<CK_ULONG>(publicData.size()), publicData.data()};
    CK_MECHANISM mech{CKM_ECDH1_DERIVE, &params, sizeof(params)};
    return fn->C_DeriveKey(s, &mech, base, tmpl, count, out);
}

CK_BBOOL kCkTrue = CK_TRUE;
CK_BBOOL kCkFalse = CK_FALSE;

} // namespace

TEST(ModuleAbi, DeriveKeyRunsEcdhWithCkdNullAndKeepsTheSecretSensitive)
{
    DeriveRig rig;
    ASSERT_NE(rig.base, CK_INVALID_HANDLE);
    CK_BBOOL derive = CK_FALSE;
    CK_ATTRIBUTE d{CKA_DERIVE, &derive, sizeof(derive)};
    ASSERT_EQ(rig.m.fn->C_GetAttributeValue(rig.session, rig.base, &d, 1), CKR_OK);
    EXPECT_EQ(derive, CK_TRUE);

    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
    EXPECT_NE(key & (CK_OBJECT_HANDLE{1} << 63), 0u) << "a derived key lives in its own handle space";
    EXPECT_EQ(rig.agent.fake->lastDerivePoint(), p384Point());
    CK_RV rv = CKR_OK;
    (void)attrBytes(rig.m.fn, rig.session, key, CKA_VALUE, &rv);
    EXPECT_EQ(rv, CKR_ATTRIBUTE_SENSITIVE);
    CK_ULONG len = 0;
    CK_ATTRIBUTE vl{CKA_VALUE_LEN, &len, sizeof(len)};
    ASSERT_EQ(rig.m.fn->C_GetAttributeValue(rig.session, key, &vl, 1), CKR_OK);
    EXPECT_EQ(len, kCannedSecret.size());

    CK_SESSION_INFO info{};
    ASSERT_EQ(rig.m.fn->C_GetSessionInfo(rig.session, &info), CKR_OK);
    CK_MECHANISM_INFO mi{};
    ASSERT_EQ(rig.m.fn->C_GetMechanismInfo(info.slotID, CKM_ECDH1_DERIVE, &mi), CKR_OK);
    EXPECT_EQ(mi.ulMinKeySize, 256u);
    EXPECT_EQ(mi.ulMaxKeySize, 521u);
    EXPECT_EQ(mi.flags, CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS);
}

TEST(ModuleAbi, DeriveKeyAcceptsThePointWrappedInDer)
{
    DeriveRig rig;
    auto der = p384Point();
    der.insert(der.begin(), {0x04, 0x61});
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, der, nullptr, 0, &key), CKR_OK);
    EXPECT_EQ(rig.agent.fake->lastDerivePoint(), p384Point()) << "the agent gets the raw point";
}

// Everything the module can decide is decided before the agent is asked.
TEST(ModuleAbi, DeriveKeyChecksEverythingBeforeTheAgent)
{
    DeriveRig rig;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key, CKD_SHA256_KDF),
              CKR_MECHANISM_PARAM_INVALID);
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key, CKD_NULL, 1),
              CKR_MECHANISM_PARAM_INVALID);
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, std::vector<std::uint8_t>(96, 0x04), nullptr, 0, &key),
              CKR_MECHANISM_PARAM_INVALID);
    CK_ATTRIBUTE onToken[] = {{CKA_TOKEN, &kCkTrue, sizeof(kCkTrue)}};
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), onToken, 1, &key), CKR_TEMPLATE_INCONSISTENT);
    auto point = p384Point();
    CK_ECDH1_DERIVE_PARAMS params{CKD_NULL, 0, nullptr, static_cast<CK_ULONG>(point.size()), point.data()};
    CK_MECHANISM shortParams{CKM_ECDH1_DERIVE, &params, sizeof(params) - 1};
    EXPECT_EQ(rig.m.fn->C_DeriveKey(rig.session, &shortParams, rig.base, nullptr, 0, &key),
              CKR_MECHANISM_PARAM_INVALID);
    CK_ECDH1_DERIVE_PARAMS noPoint{CKD_NULL, 0, nullptr, 0, nullptr};
    CK_MECHANISM noPointMech{CKM_ECDH1_DERIVE, &noPoint, sizeof(noPoint)};
    EXPECT_EQ(rig.m.fn->C_DeriveKey(rig.session, &noPointMech, rig.base, nullptr, 0, &key),
              CKR_MECHANISM_PARAM_INVALID);
    CK_MECHANISM notEcdh{CKM_ECDSA, &params, sizeof(params)};
    EXPECT_EQ(rig.m.fn->C_DeriveKey(rig.session, &notEcdh, rig.base, nullptr, 0, &key), CKR_MECHANISM_INVALID);
    CK_MECHANISM ecdh{CKM_ECDH1_DERIVE, &params, sizeof(params)};
    EXPECT_EQ(rig.m.fn->C_DeriveKey(rig.session, &ecdh, rig.base, nullptr, 0, nullptr), CKR_ARGUMENTS_BAD);
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, findOne(rig.m.fn, rig.session, CKO_PUBLIC_KEY), p384Point(), nullptr, 0,
                         &key),
              CKR_KEY_HANDLE_INVALID);
    ASSERT_EQ(rig.m.fn->C_Logout(rig.session), CKR_OK);
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_USER_NOT_LOGGED_IN);
    EXPECT_EQ(rig.agent.fake->callCount(Call::PkDerive), 0);

    // A derived key is not a base key.
    ASSERT_EQ(rig.m.fn->C_Login(rig.session, CKU_USER, nullptr, 0), CKR_OK);
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &derived), CKR_OK);
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, derived, p384Point(), nullptr, 0, &key), CKR_KEY_HANDLE_INVALID);
    EXPECT_EQ(rig.agent.fake->callCount(Call::PkDerive), 1);

    // An uninitialised module says so before it looks at the arguments, as
    // every other call does.
    ASSERT_EQ(rig.m.fn->C_Finalize(nullptr), CKR_OK);
    EXPECT_EQ(rig.m.fn->C_DeriveKey(rig.session, nullptr, rig.base, nullptr, 0, nullptr), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(ModuleAbi, DeriveKeyRefusesAnRsaBaseKey)
{
    constexpr const char* kEcCert = "cert-ec";
    SocketFixture agent(true, "None", [](FakeSocketAgent& f) {
        f.addCert(kCard0, kEcCert, /*signingCapable=*/true, 0, "EC Holder");
        seatEcKey(f, kEcCert, /*canDerive=*/true);
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(firstPresentSlot(m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    const CK_OBJECT_HANDLE rsaKey = findKeyOfType(m.fn, session, CKO_PRIVATE_KEY, CKK_RSA);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    EXPECT_EQ(deriveWith(m.fn, session, rsaKey, p384Point(), nullptr, 0, &key), CKR_KEY_TYPE_INCONSISTENT);
    EXPECT_EQ(agent.fake->callCount(Call::PkDerive), 0);
}

// pkcs11-tool --derive asks for a readable generic secret; a shorter
// CKA_VALUE_LEN gives the last bytes, a longer one is the template's fault.
TEST(ModuleAbi, AReadableDerivedKeyGivesItsLastBytes)
{
    DeriveRig rig;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
    CK_ULONG sixteen = 16;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_TOKEN, &kCkFalse, sizeof(kCkFalse)},
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_SENSITIVE, &kCkFalse, sizeof(kCkFalse)},
        {CKA_EXTRACTABLE, &kCkTrue, sizeof(kCkTrue)},
        {CKA_ENCRYPT, &kCkTrue, sizeof(kCkTrue)},
        {CKA_DECRYPT, &kCkTrue, sizeof(kCkTrue)},
        {CKA_WRAP, &kCkTrue, sizeof(kCkTrue)},
        {CKA_UNWRAP, &kCkTrue, sizeof(kCkTrue)},
        {CKA_VALUE_LEN, &sixteen, sizeof(sixteen)},
    };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), tmpl, 10, &key), CKR_OK);
    EXPECT_EQ(attrBytes(rig.m.fn, rig.session, key, CKA_VALUE),
              std::vector<std::uint8_t>(kCannedSecret.end() - 16, kCannedSecret.end()));
    // Longer than a P-384 secret: refused from the key's size, before the
    // agent -- and so before the card and any PIN prompt.
    const int derivesBefore = rig.agent.fake->callCount(Call::PkDerive);
    CK_ULONG tooLong = 49;
    tmpl[9].pValue = &tooLong;
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), tmpl, 10, &key), CKR_TEMPLATE_INCONSISTENT);
    EXPECT_EQ(rig.agent.fake->callCount(Call::PkDerive), derivesBefore) << "the card derived for a refused template";
    CK_ULONG whole = 48;
    tmpl[9].pValue = &whole;
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), tmpl, 10, &key), CKR_OK);
}

// A derived key belongs to the application: another session of it finds the
// key, and it goes when its creator closes.
TEST(ModuleAbi, DerivedKeysLiveForTheirApplication)
{
    DeriveRig rig;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
    const CK_SLOT_ID slot = firstPresentSlot(rig.m.fn);
    // The login is the token's: a session opened after it is a user session
    // and sees the application's private objects without logging in again.
    CK_SESSION_HANDLE other = 0;
    CK_SESSION_HANDLE last = 0;
    ASSERT_EQ(rig.m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &other), CKR_OK);
    ASSERT_EQ(rig.m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &last), CKR_OK);
    EXPECT_EQ(findOne(rig.m.fn, other, CKO_SECRET_KEY), key);
    ASSERT_EQ(rig.m.fn->C_CloseSession(other), CKR_OK);
    EXPECT_EQ(findOne(rig.m.fn, rig.session, CKO_SECRET_KEY), key) << "closing another session leaves it";
    ASSERT_EQ(rig.m.fn->C_CloseSession(rig.session), CKR_OK);
    CK_RV rv = CKR_OK;
    (void)attrBytes(rig.m.fn, last, key, CKA_VALUE_LEN, &rv);
    EXPECT_EQ(rv, CKR_OBJECT_HANDLE_INVALID) << "closing its creator destroys it";
}

TEST(ModuleAbi, DerivedKeysGoWithLogoutLapseCloseAllAndTheCard)
{
    const auto alive = [](DeriveRig& rig, CK_OBJECT_HANDLE key) {
        CK_RV rv = CKR_OK;
        (void)attrBytes(rig.m.fn, rig.session, key, CKA_VALUE_LEN, &rv);
        return rv == CKR_OK;
    };
    {
        DeriveRig rig;
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
        ASSERT_EQ(rig.m.fn->C_Logout(rig.session), CKR_OK);
        ASSERT_EQ(rig.m.fn->C_Login(rig.session, CKU_USER, nullptr, 0), CKR_OK);
        EXPECT_FALSE(alive(rig, key)) << "C_Logout";
    }
    {
        DeriveRig rig([](FakeSocketAgent& f) { f.failCall(Call::PkSignRaw, W::SyncError::UserNotLoggedIn); });
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
        CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
        ASSERT_EQ(rig.m.fn->C_SignInit(rig.session, &mech, rig.base), CKR_OK);
        std::vector<CK_BYTE> digest(48, 0x01);
        CK_BYTE sig[128];
        CK_ULONG len = sizeof(sig);
        EXPECT_EQ(rig.m.fn->C_Sign(rig.session, digest.data(), digest.size(), sig, &len), CKR_USER_NOT_LOGGED_IN);
        ASSERT_EQ(rig.m.fn->C_Login(rig.session, CKU_USER, nullptr, 0), CKR_OK);
        EXPECT_FALSE(alive(rig, key)) << "a lapsed lease";
    }
    {
        DeriveRig rig;
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
        const CK_SLOT_ID slot = firstPresentSlot(rig.m.fn);
        CK_SESSION_HANDLE again = 0;
        ASSERT_EQ(rig.m.fn->C_CloseAllSessions(slot), CKR_OK);
        ASSERT_EQ(rig.m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &again), CKR_OK);
        ASSERT_EQ(rig.m.fn->C_Login(again, CKU_USER, nullptr, 0), CKR_OK);
        EXPECT_EQ(findOne(rig.m.fn, again, CKO_SECRET_KEY), CK_INVALID_HANDLE) << "C_CloseAllSessions";
    }
    {
        DeriveRig rig;
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
        rig.agent.fake->removeCard();
        CK_SLOT_ID slots[8];
        CK_ULONG n = 8;
        ASSERT_EQ(rig.m.fn->C_GetSlotList(CK_FALSE, slots, &n), CKR_OK); // the refresh sees the empty reader
        rig.agent.fake->insertCard();
        n = 8;
        ASSERT_EQ(rig.m.fn->C_GetSlotList(CK_FALSE, slots, &n), CKR_OK);
        EXPECT_FALSE(alive(rig, key)) << "the card it was derived with left";
    }
}

// Only a derived key can be destroyed; the card's objects are the card's.
TEST(ModuleAbi, DestroyObjectRemovesADerivedKeyAndRefusesACardObject)
{
    DeriveRig rig;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
    EXPECT_EQ(rig.m.fn->C_DestroyObject(rig.session, rig.base), CKR_ACTION_PROHIBITED);
    ASSERT_EQ(rig.m.fn->C_DestroyObject(rig.session, key), CKR_OK);
    EXPECT_EQ(rig.m.fn->C_DestroyObject(rig.session, key), CKR_OBJECT_HANDLE_INVALID);
}

// A derived key's handle survives the module's every-query model refresh.
TEST(ModuleAbi, ADerivedHandleSurvivesARefresh)
{
    DeriveRig rig;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    ASSERT_EQ(rig.m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    CK_ULONG len = 0;
    CK_ATTRIBUTE vl{CKA_VALUE_LEN, &len, sizeof(len)};
    EXPECT_EQ(rig.m.fn->C_GetAttributeValue(rig.session, key, &vl, 1), CKR_OK);
}

// A point the agent refuses before any prompt is a parameter error.
TEST(ModuleAbi, APointTheAgentRefusesIsAParameterError)
{
    DeriveRig rig([](FakeSocketAgent& f) { f.failCall(Call::PkDerive, W::SyncError::InvalidRequest); });
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_MECHANISM_PARAM_INVALID);
}

// The secret comes back after the login it was derived under has ended: it is
// wiped, never kept for a later login to find (C_Logout destroys derived keys).
TEST(ModuleAbi, ADeriveThatOutlivesItsLoginKeepsNoKey)
{
    DeriveRig rig([](FakeSocketAgent& f) { f.delayCall(Call::PkDerive, std::chrono::milliseconds{400}); });
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    auto parked = std::async(std::launch::async, [&rig, &key] {
        return deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key);
    });
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (rig.agent.fake->callCount(Call::PkDerive) == 0 && std::chrono::steady_clock::now() < until)
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    ASSERT_EQ(rig.agent.fake->callCount(Call::PkDerive), 1) << "the derive never reached the agent";
    ASSERT_EQ(rig.m.fn->C_Logout(rig.session), CKR_OK); // while the derive is parked in the agent
    EXPECT_EQ(parked.get(), CKR_USER_NOT_LOGGED_IN);
    ASSERT_EQ(rig.m.fn->C_Login(rig.session, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(findOne(rig.m.fn, rig.session, CKO_SECRET_KEY), CK_INVALID_HANDLE)
        << "no key may outlive the login it was derived under";
}

// The card is changed while the agent derives, and the module re-reads the
// slots before it takes its lock back: the secret belongs to the card that
// left, so it is wiped, never kept for the card now in the reader.
TEST(ModuleAbi, ADeriveThatOutlivesItsCardKeepsNoKey)
{
    ::setenv("LIBRESCRS_TEST_REFRESH_AFTER_DERIVE", "1", 1);
    DeriveRig rig([](FakeSocketAgent& f) {
        f.setDeriveResponder([&f](const W::PkDerive&) {
            f.swapCard("/org/librescrs/Agent/card/9");
            return kCannedSecret;
        });
    });
    ::unsetenv("LIBRESCRS_TEST_REFRESH_AFTER_DERIVE"); // read once, by C_Initialize
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_DEVICE_REMOVED);
    EXPECT_EQ(key, CK_INVALID_HANDLE);
    EXPECT_EQ(rig.agent.fake->callCount(Call::PkDerive), 1);
    EXPECT_EQ(findOne(rig.m.fn, rig.session, CKO_SECRET_KEY), CK_INVALID_HANDLE)
        << "no key may outlive the card it was derived with";
}

// A base key without CKA_DERIVE is refused before the agent, even on a slot
// whose other key derives.
TEST(ModuleAbi, DeriveKeyRefusesABaseKeyThatDoesNotDerive)
{
    constexpr const char* kSignOnly = "cert-sign-only";
    const std::vector<std::uint8_t> signOnlyId{0x51, 0x6E};
    DeriveRig rig([&signOnlyId](FakeSocketAgent& f) {
        f.addCert(kCard0, kSignOnly, /*signingCapable=*/true, 0, "Sign Only");
        f.setKeyFacts(kSignOnly, signOnlyId, LibreSCRS::Agent::KeyType::Ec, 384, /*canDerive=*/false);
        f.setEcPoint(kSignOnly, "P-384", std::vector<std::uint8_t>(48, 0x11), std::vector<std::uint8_t>(48, 0x22));
    });
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    std::vector<std::uint8_t> id = signOnlyId;
    CK_ATTRIBUTE byId[] = {{CKA_CLASS, &cls, sizeof(cls)}, {CKA_ID, id.data(), static_cast<CK_ULONG>(id.size())}};
    ASSERT_EQ(rig.m.fn->C_FindObjectsInit(rig.session, byId, 2), CKR_OK);
    CK_OBJECT_HANDLE signOnly = CK_INVALID_HANDLE;
    CK_ULONG n = 0;
    ASSERT_EQ(rig.m.fn->C_FindObjects(rig.session, &signOnly, 1, &n), CKR_OK);
    ASSERT_EQ(rig.m.fn->C_FindObjectsFinal(rig.session), CKR_OK);
    ASSERT_EQ(n, 1u);
    CK_BBOOL derive = CK_TRUE;
    CK_ATTRIBUTE d{CKA_DERIVE, &derive, sizeof(derive)};
    ASSERT_EQ(rig.m.fn->C_GetAttributeValue(rig.session, signOnly, &d, 1), CKR_OK);
    EXPECT_EQ(derive, CK_FALSE);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    EXPECT_EQ(deriveWith(rig.m.fn, rig.session, signOnly, p384Point(), nullptr, 0, &key),
              CKR_KEY_FUNCTION_NOT_PERMITTED);
    EXPECT_EQ(rig.agent.fake->callCount(Call::PkDerive), 0);
}

// C_Finalize ends the application's use of the module; its derived keys go
// with it, and a new C_Initialize starts with none.
TEST(ModuleAbi, DerivedKeysDoNotSurviveFinalize)
{
    DeriveRig rig;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(deriveWith(rig.m.fn, rig.session, rig.base, p384Point(), nullptr, 0, &key), CKR_OK);
    ASSERT_EQ(rig.m.fn->C_Finalize(nullptr), CKR_OK);
    ASSERT_EQ(rig.m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE again = 0;
    ASSERT_EQ(rig.m.fn->C_OpenSession(firstPresentSlot(rig.m.fn), CKF_SERIAL_SESSION, nullptr, nullptr, &again),
              CKR_OK);
    ASSERT_EQ(rig.m.fn->C_Login(again, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(findOne(rig.m.fn, again, CKO_SECRET_KEY), CK_INVALID_HANDLE);
    CK_RV rv = CKR_OK;
    (void)attrBytes(rig.m.fn, again, key, CKA_VALUE_LEN, &rv);
    EXPECT_EQ(rv, CKR_OBJECT_HANDLE_INVALID);
}
