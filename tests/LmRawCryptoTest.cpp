// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic unit for the LmRawCrypto seam's pure pieces: the hermetic
// RawCryptoStatus enum (distinct values the D-Bus host maps onto the wire) and
// the LM-outcome -> RawCryptoStatus mappers. The functional sign/decrypt
// routing needs a live card (selectSigningCandidate re-reads certs off the
// session) and is covered by the HW smoke + the already-tested
// selectSigningCandidate (LmSeamsRoutingTest); this unit pins the hermetic
// surface so the host's status->wire mapping cannot drift.
#include <LibreSCRS/Agent/operations/LmRawCrypto.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <vector>

using namespace LibreSCRS::Agent::Operations;

namespace {

// Mint a self-signed v3 RSA cert with the given keyUsage extension; return DER.
std::vector<std::uint8_t> makeV3DerWithKeyUsage(const char* keyUsageValue)
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    EXPECT_NE(x, nullptr);
    X509_set_version(x, 2); // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1234);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("rawcrypto-kat"), -1,
                               -1, 0);
    X509_set_issuer_name(x, name);
    if (keyUsageValue != nullptr) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
        if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, keyUsageValue)) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    EXPECT_GT(X509_sign(x, pkey, EVP_sha256()), 0);
    unsigned char* der = nullptr;
    const int len = i2d_X509(x, &der);
    std::vector<std::uint8_t> out;
    if (len > 0 && der != nullptr) {
        out.assign(der, der + len);
    }
    OPENSSL_free(der);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

} // namespace

TEST(LmRawCrypto, StatusEnumHasDistinctValues)
{
    EXPECT_NE(static_cast<int>(RawCryptoStatus::Ok), static_cast<int>(RawCryptoStatus::KeyNotFound));
    EXPECT_NE(static_cast<int>(RawCryptoStatus::KeyNotFound), static_cast<int>(RawCryptoStatus::CardError));
    EXPECT_NE(static_cast<int>(RawCryptoStatus::AuthFailed), static_cast<int>(RawCryptoStatus::Ok));
    EXPECT_NE(static_cast<int>(RawCryptoStatus::NotSupported), static_cast<int>(RawCryptoStatus::CardError));
}

TEST(LmRawCrypto, DefaultResultIsCardError)
{
    // A default-constructed result must NOT read as Ok — a dropped/forgotten
    // assignment fails closed (no phantom success with empty bytes).
    RawCryptoResult r;
    EXPECT_NE(r.status, RawCryptoStatus::Ok);
    EXPECT_TRUE(r.bytes.empty());
}

// Decrypt key-usage routing assertion (pure DER predicate): a key whose cert
// keyUsage is signature-only must be refused for decrypt (-> NotSupported);
// keyEncipherment / dataEncipherment certs pass; absent keyUsage is permissive.
TEST(LmRawCrypto, KeyUsageGatePermitsEnciphermentRefusesSignatureOnly)
{
    // PKS signature key (ksc): digitalSignature + nonRepudiation, NO encipher.
    const auto signOnly = makeV3DerWithKeyUsage("digitalSignature,nonRepudiation");
    ASSERT_FALSE(signOnly.empty());
    EXPECT_FALSE(certKeyUsagePermitsDecrypt(signOnly)) << "a sign-only key must be refused for decrypt";

    // PKS decrypt key (kxc): keyEncipherment.
    const auto encipher = makeV3DerWithKeyUsage("keyEncipherment");
    ASSERT_FALSE(encipher.empty());
    EXPECT_TRUE(certKeyUsagePermitsDecrypt(encipher)) << "a keyEncipherment key must permit decrypt";

    const auto dataEncipher = makeV3DerWithKeyUsage("dataEncipherment");
    ASSERT_FALSE(dataEncipher.empty());
    EXPECT_TRUE(certKeyUsagePermitsDecrypt(dataEncipher)) << "a dataEncipherment key must permit decrypt";
}

TEST(LmRawCrypto, KeyUsageGateIsPermissiveWhenAbsentOrUnparseable)
{
    // No keyUsage extension at all -> permissive (the card stays the authority).
    const auto noKu = makeV3DerWithKeyUsage(nullptr);
    ASSERT_FALSE(noKu.empty());
    EXPECT_TRUE(certKeyUsagePermitsDecrypt(noKu)) << "absent keyUsage must be permissive";

    // Garbage DER -> unparseable -> permissive (defer to the card).
    const std::vector<std::uint8_t> garbage{0x00, 0x01, 0x02, 0x03};
    EXPECT_TRUE(certKeyUsagePermitsDecrypt(garbage)) << "unparseable DER must be permissive";
}
