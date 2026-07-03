// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// KAT for the RSA public-key extractor the PKCS#11 module serves as
// CKA_MODULUS / CKA_PUBLIC_EXPONENT (ssh-pkcs11 needs them). A cert is minted
// with OpenSSL at runtime with a KNOWN public exponent; the extracted bytes are
// asserted against the source key (round-trip), and non-RSA / garbage inputs are
// rejected.
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <vector>

using namespace LibreSCRS::Agent::Operations;

namespace {

std::vector<std::uint8_t> bnBytes(const BIGNUM* bn)
{
    std::vector<std::uint8_t> out(static_cast<std::size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, out.data());
    return out;
}

// Mint an RSA cert and ALSO return the source modulus + exponent bytes.
struct MintedRsa
{
    std::vector<std::uint8_t> der;
    std::vector<std::uint8_t> modulus;
    std::vector<std::uint8_t> exponent;
};

MintedRsa mintRsaCert()
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x2026);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("rsa-pub-kat"), -1, -1,
                               0);
    X509_set_issuer_name(x, name);
    EXPECT_GT(X509_sign(x, pkey, EVP_sha256()), 0);

    MintedRsa out;
    unsigned char* der = nullptr;
    const int len = i2d_X509(x, &der);
    if (len > 0) {
        out.der.assign(der, der + len);
    }
    OPENSSL_free(der);

    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
    out.modulus = bnBytes(n);
    out.exponent = bnBytes(e);
    BN_free(n);
    BN_free(e);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

std::vector<std::uint8_t> mintEcCert()
{
    EVP_PKEY* pkey = EVP_EC_gen("prime256v1");
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x2027);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("ec-kat"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    EXPECT_GT(X509_sign(x, pkey, EVP_sha256()), 0);
    unsigned char* der = nullptr;
    const int len = i2d_X509(x, &der);
    std::vector<std::uint8_t> out;
    if (len > 0) {
        out.assign(der, der + len);
    }
    OPENSSL_free(der);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

} // namespace

TEST(RsaPublicKey, ExtractsModulusAndExponentMatchingTheSourceKey)
{
    const auto minted = mintRsaCert();
    ASSERT_FALSE(minted.der.empty());

    const auto pk = rsaPublicKeyFromCertDer(minted.der);
    ASSERT_TRUE(pk.has_value());
    // Round-trip against the source key — exact CKA_* big-endian unpadded bytes.
    EXPECT_EQ(pk->modulus, minted.modulus);
    EXPECT_EQ(pk->exponent, minted.exponent);
    // RSA-2048 modulus is 256 bytes with no leading zero (top bit set by gen).
    EXPECT_EQ(pk->modulus.size(), 256u);
    EXPECT_FALSE(pk->modulus.empty());
    EXPECT_EQ(pk->modulus.front() & 0x80, 0x80) << "no leading zero byte (CKA_MODULUS convention)";
    // Default exponent 65537 == 0x010001.
    EXPECT_EQ(pk->exponent, (std::vector<std::uint8_t>{0x01, 0x00, 0x01}));
}

TEST(RsaPublicKey, RejectsNonRsaKey)
{
    const auto ec = mintEcCert();
    ASSERT_FALSE(ec.empty());
    EXPECT_FALSE(rsaPublicKeyFromCertDer(ec).has_value()) << "an EC cert has no RSA modulus/exponent";
}

TEST(RsaPublicKey, RejectsGarbageAndEmpty)
{
    EXPECT_FALSE(rsaPublicKeyFromCertDer({}).has_value());
    const std::vector<std::uint8_t> garbage{0x30, 0x03, 0x02, 0x01, 0x00};
    EXPECT_FALSE(rsaPublicKeyFromCertDer(garbage).has_value());
}
