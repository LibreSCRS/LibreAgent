// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The first line of evidence for EC keys before a card proves them: the real
// module, the socket double holding a REAL EC key, and OpenSSL checking what
// comes out. An ECDSA signature made through C_Sign verifies against the
// public key read back through CKA_EC_POINT, and the secret C_DeriveKey stores
// equals the one OpenSSL computes from the other side.
#include "SocketFixture.h"

#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <dlfcn.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent::Test;
namespace W = LibreSCRS::Agent::Wire;

namespace {

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

struct LoadedModule
{
    void* handle = nullptr;
    CK_FUNCTION_LIST_PTR fn = nullptr;
    LoadedModule()
    {
        handle = dlopen(LIBRESCRS_PKCS11_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
        if (handle) {
            auto get = reinterpret_cast<CK_C_GetFunctionList>(dlsym(handle, "C_GetFunctionList"));
            if (get)
                get(&fn);
        }
    }
    ~LoadedModule()
    {
        if (fn)
            fn->C_Finalize(nullptr);
        if (handle)
            dlclose(handle);
    }
};

std::vector<std::uint8_t> encodedPoint(EVP_PKEY* key)
{
    std::size_t len = 0;
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0, &len);
    std::vector<std::uint8_t> out(len);
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out.data(), out.size(), &len);
    return out;
}

PkeyPtr publicKeyFromPoint(const char* group, const std::vector<std::uint8_t>& point)
{
    CtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free};
    EVP_PKEY_fromdata_init(ctx.get());
    std::string g{group};
    std::vector<std::uint8_t> pub = point;
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, g.data(), 0),
                           OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size()),
                           OSSL_PARAM_construct_end()};
    EVP_PKEY* out = nullptr;
    EVP_PKEY_fromdata(ctx.get(), &out, EVP_PKEY_PUBLIC_KEY, params);
    return PkeyPtr{out, &EVP_PKEY_free};
}

// What a card's plugin answers for ECDSA: r||s at the field's width.
std::vector<std::uint8_t> ecdsaRaw(EVP_PKEY* key, const std::vector<std::uint8_t>& digest, std::size_t width)
{
    CtxPtr ctx{EVP_PKEY_CTX_new(key, nullptr), &EVP_PKEY_CTX_free};
    EVP_PKEY_sign_init(ctx.get());
    std::size_t derLen = 0;
    EVP_PKEY_sign(ctx.get(), nullptr, &derLen, digest.data(), digest.size());
    std::vector<std::uint8_t> der(derLen);
    EVP_PKEY_sign(ctx.get(), der.data(), &derLen, digest.data(), digest.size());
    const unsigned char* p = der.data();
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig{d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(derLen)),
                                                              &ECDSA_SIG_free};
    std::vector<std::uint8_t> raw(2 * width);
    BN_bn2binpad(ECDSA_SIG_get0_r(sig.get()), raw.data(), static_cast<int>(width));
    BN_bn2binpad(ECDSA_SIG_get0_s(sig.get()), raw.data() + width, static_cast<int>(width));
    return raw;
}

bool ecdsaVerifies(EVP_PKEY* pub, const std::vector<std::uint8_t>& digest, const std::vector<std::uint8_t>& raw)
{
    const std::size_t width = raw.size() / 2;
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig{ECDSA_SIG_new(), &ECDSA_SIG_free};
    ECDSA_SIG_set0(sig.get(), BN_bin2bn(raw.data(), static_cast<int>(width), nullptr),
                   BN_bin2bn(raw.data() + width, static_cast<int>(width), nullptr));
    unsigned char* der = nullptr;
    const int derLen = i2d_ECDSA_SIG(sig.get(), &der);
    CtxPtr ctx{EVP_PKEY_CTX_new(pub, nullptr), &EVP_PKEY_CTX_free};
    EVP_PKEY_verify_init(ctx.get());
    const int ok = EVP_PKEY_verify(ctx.get(), der, static_cast<std::size_t>(derLen), digest.data(), digest.size());
    OPENSSL_free(der);
    return ok == 1;
}

std::vector<std::uint8_t> ecdh(EVP_PKEY* mine, EVP_PKEY* theirs)
{
    CtxPtr ctx{EVP_PKEY_CTX_new(mine, nullptr), &EVP_PKEY_CTX_free};
    EVP_PKEY_derive_init(ctx.get());
    EVP_PKEY_derive_set_peer(ctx.get(), theirs);
    std::size_t len = 0;
    EVP_PKEY_derive(ctx.get(), nullptr, &len);
    std::vector<std::uint8_t> z(len);
    EVP_PKEY_derive(ctx.get(), z.data(), &len);
    z.resize(len);
    return z;
}

const std::vector<std::uint8_t> kKeyId{0xF7, 0x13, 0x4B, 0x02};

CK_OBJECT_HANDLE findOneOf(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE s, CK_OBJECT_CLASS cls)
{
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    fn->C_FindObjectsInit(s, tmpl, 1);
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG n = 0;
    fn->C_FindObjects(s, &h, 1, &n);
    fn->C_FindObjectsFinal(s);
    return n == 1 ? h : CK_INVALID_HANDLE;
}

std::vector<std::uint8_t> attribute(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                                    CK_ATTRIBUTE_TYPE t)
{
    CK_ATTRIBUTE a{t, nullptr, 0};
    EXPECT_EQ(fn->C_GetAttributeValue(s, o, &a, 1), CKR_OK);
    std::vector<std::uint8_t> out(a.ulValueLen);
    a.pValue = out.data();
    EXPECT_EQ(fn->C_GetAttributeValue(s, o, &a, 1), CKR_OK);
    return out;
}

} // namespace

TEST(EcInterop, AnEcdsaSignatureThroughTheModuleVerifiesWithOpenSsl)
{
    PkeyPtr card{EVP_EC_gen("P-384"), &EVP_PKEY_free};
    const auto point = encodedPoint(card.get());
    ASSERT_EQ(point.size(), 97u);
    SocketFixture agent(true, "Can", [&](FakeSocketAgent& f) {
        f.setKeyFacts(kCertId, kKeyId, LibreSCRS::Agent::KeyType::Ec, 384, false);
        f.setEcPoint(kCertId, "P-384", {point.begin() + 1, point.begin() + 49}, {point.begin() + 49, point.end()});
        f.setSignResponder([&card](const W::PkSignRaw& r) { return ecdsaRaw(card.get(), r.data, 48); });
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = 0;
    CK_ULONG n = 1;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, &slot, &n), CKR_OK);
    CK_SESSION_HANDLE s = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &s), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(s, CKU_USER, nullptr, 0), CKR_OK);

    std::vector<std::uint8_t> digest(48);
    unsigned int dlen = 0;
    const std::string msg = "interop";
    EVP_Digest(msg.data(), msg.size(), digest.data(), &dlen, EVP_sha384(), nullptr);
    CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(s, &mech, findOneOf(m.fn, s, CKO_PRIVATE_KEY)), CKR_OK);
    std::vector<CK_BYTE> sig(96);
    CK_ULONG sigLen = sig.size();
    ASSERT_EQ(m.fn->C_Sign(s, digest.data(), digest.size(), sig.data(), &sigLen), CKR_OK);
    ASSERT_EQ(sigLen, 96u);

    const auto ecPoint = attribute(m.fn, s, findOneOf(m.fn, s, CKO_PUBLIC_KEY), CKA_EC_POINT);
    ASSERT_EQ(ecPoint.size(), 99u);
    const auto pub = publicKeyFromPoint("secp384r1", {ecPoint.begin() + 2, ecPoint.end()});
    ASSERT_NE(pub, nullptr);
    const std::vector<std::uint8_t> raw(sig.begin(), sig.end());
    EXPECT_TRUE(ecdsaVerifies(pub.get(), digest, raw));
    // The verifier can say no: the same signature over another digest fails.
    std::vector<std::uint8_t> otherDigest = digest;
    otherDigest[0] ^= 0x01;
    EXPECT_FALSE(ecdsaVerifies(pub.get(), otherDigest, raw));
}

TEST(EcInterop, AnEcdhSecretThroughTheModuleMatchesOpenSsl)
{
    PkeyPtr card{EVP_EC_gen("P-256"), &EVP_PKEY_free};
    PkeyPtr peer{EVP_EC_gen("P-256"), &EVP_PKEY_free};
    const auto cardPoint = encodedPoint(card.get());
    const auto peerPoint = encodedPoint(peer.get());
    SocketFixture agent(true, "None", [&](FakeSocketAgent& f) {
        f.setKeyFacts(kCertId, kKeyId, LibreSCRS::Agent::KeyType::Ec, 256, /*canDerive=*/true);
        f.setEcPoint(kCertId, "P-256", {cardPoint.begin() + 1, cardPoint.begin() + 33},
                     {cardPoint.begin() + 33, cardPoint.end()});
        f.setDeriveResponder([&card](const W::PkDerive& d) {
            const auto other = publicKeyFromPoint("prime256v1", d.data);
            return ecdh(card.get(), other.get());
        });
    });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = 0;
    CK_ULONG n = 1;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, &slot, &n), CKR_OK);
    CK_SESSION_HANDLE s = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &s), CKR_OK);
    ASSERT_EQ(m.fn->C_Login(s, CKU_USER, nullptr, 0), CKR_OK);

    std::vector<std::uint8_t> publicData = peerPoint;
    CK_ECDH1_DERIVE_PARAMS params{CKD_NULL, 0, nullptr, static_cast<CK_ULONG>(publicData.size()), publicData.data()};
    CK_MECHANISM mech{CKM_ECDH1_DERIVE, &params, sizeof(params)};
    CK_BBOOL no = CK_FALSE;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE readable[] = {{CKA_SENSITIVE, &no, sizeof(no)}, {CKA_EXTRACTABLE, &yes, sizeof(yes)}};
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_EQ(m.fn->C_DeriveKey(s, &mech, findOneOf(m.fn, s, CKO_PRIVATE_KEY), readable, 2, &key), CKR_OK);

    const auto ecPoint = attribute(m.fn, s, findOneOf(m.fn, s, CKO_PUBLIC_KEY), CKA_EC_POINT);
    const auto cardPub = publicKeyFromPoint("prime256v1", {ecPoint.begin() + 2, ecPoint.end()});
    ASSERT_NE(cardPub, nullptr);
    const auto expected = ecdh(peer.get(), cardPub.get());
    ASSERT_EQ(expected.size(), 32u) << "OpenSSL computed no secret to compare with";
    EXPECT_EQ(attribute(m.fn, s, key, CKA_VALUE), expected)
        << "Z through the module equals Z computed from the other side";
}
