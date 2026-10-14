// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// KAT for the RSA public-key extractor the PKCS#11 module serves as
// CKA_MODULUS / CKA_PUBLIC_EXPONENT (ssh-pkcs11 needs them). A cert is minted
// with OpenSSL at runtime with a KNOWN public exponent; the extracted bytes are
// asserted against the source key (round-trip), and non-RSA / garbage inputs are
// rejected.
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>

#include "TestCertMint.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <tuple>
#include <variant>
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

namespace {

std::vector<std::uint8_t> sha1Of(std::span<const std::uint8_t> in)
{
    std::vector<std::uint8_t> out(SHA_DIGEST_LENGTH);
    SHA1(in.data(), in.size(), out.data());
    return out;
}

} // namespace

// The point a certificate carries, split into fixed-width halves on each of the
// three curves the agent serves.
TEST(RsaPublicKey, EcPublicKeyServesThePointOnEveryNistCurve)
{
    namespace T = LibreSCRS::Agent::Test;
    const std::array<std::tuple<const char*, const char*, std::size_t>, 3> curves{
        {{"P-256", "P-256", 32}, {"P-384", "P-384", 48}, {"P-521", "P-521", 66}}};
    for (const auto& [group, crv, width] : curves) {
        auto key = T::ecKey(group);
        ASSERT_NE(key, nullptr) << group;
        const auto der = T::selfSignedCert(key.get(), "ec-pub-kat");
        const auto point = T::encodedPublicPoint(key.get());
        ASSERT_EQ(point.size(), 1 + 2 * width) << group;
        const auto ec = ecPublicKeyFromCertDer(der);
        ASSERT_TRUE(ec.has_value()) << group;
        EXPECT_EQ(ec->crv, crv);
        EXPECT_EQ(ec->x, (std::vector<std::uint8_t>(point.begin() + 1, point.begin() + 1 + width))) << group;
        EXPECT_EQ(ec->y, (std::vector<std::uint8_t>(point.begin() + 1 + width, point.end()))) << group;
    }
}

// About one key in 256 has an X coordinate whose first byte is zero; an
// extractor that went through BN_bn2bin would serve 31 bytes for it.
TEST(RsaPublicKey, AnXCoordinateWithALeadingZeroKeepsItsWidth)
{
    namespace T = LibreSCRS::Agent::Test;
    for (int attempt = 0; attempt < 8192; ++attempt) {
        auto key = T::ecKey("P-256");
        const auto point = T::encodedPublicPoint(key.get());
        if (point.size() != 65 || point[1] != 0x00) {
            continue;
        }
        const auto ec = ecPublicKeyFromCertDer(T::selfSignedCert(key.get(), "leading-zero"));
        ASSERT_TRUE(ec.has_value());
        EXPECT_EQ(ec->x.size(), 32u);
        EXPECT_EQ(ec->x.front(), 0x00);
        return;
    }
    FAIL() << "no P-256 key with a leading zero in X in 8192 tries";
}

TEST(RsaPublicKey, EcPublicKeyRefusesEveryOtherKey)
{
    namespace T = LibreSCRS::Agent::Test;
    EXPECT_FALSE(ecPublicKeyFromCertDer(T::selfSignedCert(T::rsaKey().get(), "rsa")).has_value());
    EXPECT_FALSE(ecPublicKeyFromCertDer(T::selfSignedCert(T::ecKey("brainpoolP256r1").get(), "bp")).has_value());
    EXPECT_FALSE(ecPublicKeyFromCertDer(T::selfSignedCert(T::namedKey("ED25519").get(), "ed")).has_value());
    const std::vector<std::uint8_t> garbage{0x30, 0x03, 0x02, 0x01, 0x00};
    EXPECT_FALSE(ecPublicKeyFromCertDer(garbage).has_value());
}

// The ID the agent computes when the card gives none, the way OpenSC does:
// SHA-1 of the RSA modulus, of the EC X coordinate, else of the
// subjectPublicKey bits -- and of the whole DER when nothing parses. Never empty.
TEST(RsaPublicKey, FallbackKeyIdFollowsTheKeyFamily)
{
    namespace T = LibreSCRS::Agent::Test;
    auto rsa = T::rsaKey();
    const auto rsaDer = T::selfSignedCert(rsa.get(), "rsa");
    const auto rsaPub = rsaPublicKeyFromCertDer(rsaDer);
    ASSERT_TRUE(rsaPub.has_value());
    EXPECT_EQ(fallbackKeyIdFromCertDer(rsaDer), sha1Of(rsaPub->modulus));

    auto ec = T::ecKey("P-384");
    const auto ecDer = T::selfSignedCert(ec.get(), "ec");
    const auto ecPub = ecPublicKeyFromCertDer(ecDer);
    ASSERT_TRUE(ecPub.has_value());
    EXPECT_EQ(fallbackKeyIdFromCertDer(ecDer), sha1Of(ecPub->x));

    auto ed = T::namedKey("ED25519");
    const auto edDer = T::selfSignedCert(ed.get(), "ed");
    const unsigned char* p = edDer.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert{d2i_X509(nullptr, &p, static_cast<long>(edDer.size())),
                                                     &X509_free};
    ASSERT_NE(cert, nullptr);
    const ASN1_BIT_STRING* bits = X509_get0_pubkey_bitstr(cert.get());
    EXPECT_EQ(fallbackKeyIdFromCertDer(edDer),
              sha1Of(std::span<const std::uint8_t>{bits->data, static_cast<std::size_t>(bits->length)}));

    const std::vector<std::uint8_t> garbage{0x30, 0x03, 0x02, 0x01, 0x00};
    EXPECT_EQ(fallbackKeyIdFromCertDer(garbage), sha1Of(garbage));
}

// The peer point of a key agreement is checked against the curve of the
// card's certificate: on it, uncompressed, not at infinity, of the curve's size.
TEST(RsaPublicKey, APeerPointMustLieOnTheCertificatesCurve)
{
    namespace T = LibreSCRS::Agent::Test;
    auto card = T::ecKey("P-384");
    const auto der = T::selfSignedCert(card.get(), "card");
    auto peer = T::ecKey("P-384");
    const auto good = T::encodedPublicPoint(peer.get());
    EXPECT_TRUE(ecPeerPointOnCertCurve(der, good));

    auto offCurve = good;
    offCurve.back() ^= 0x01;
    EXPECT_FALSE(ecPeerPointOnCertCurve(der, offCurve)) << "a flipped Y bit leaves the curve";
    auto compressed = good;
    compressed[0] = 0x02;
    EXPECT_FALSE(ecPeerPointOnCertCurve(der, compressed));
    EXPECT_FALSE(ecPeerPointOnCertCurve(der, std::vector<std::uint8_t>{0x00}));
    EXPECT_FALSE(ecPeerPointOnCertCurve(der, std::span<const std::uint8_t>{good.data(), good.size() - 1}));
    EXPECT_FALSE(ecPeerPointOnCertCurve(der, T::encodedPublicPoint(T::ecKey("P-256").get())))
        << "a P-256 point against a P-384 key";
    EXPECT_FALSE(ecPeerPointOnCertCurve(T::selfSignedCert(T::rsaKey().get(), "rsa"), good));
}

// The agent's PublicKey answer: an RSA certificate's modulus and exponent, an
// EC certificate's point on its curve, and nothing for any other key.
TEST(RsaPublicKey, TheServedPublicKeyIsTheCertificatesOwn)
{
    namespace T = LibreSCRS::Agent::Test;
    const auto rsa = publicKeyFromCertDer(T::selfSignedCert(T::rsaKey().get(), "RSA"));
    ASSERT_TRUE(rsa.has_value());
    ASSERT_TRUE(std::holds_alternative<RsaPublicKey>(*rsa));
    EXPECT_EQ(std::get<RsaPublicKey>(*rsa).modulus.size(), 256u);

    const auto ec = publicKeyFromCertDer(T::selfSignedCert(T::ecKey("P-384").get(), "LK"));
    ASSERT_TRUE(ec.has_value());
    ASSERT_TRUE(std::holds_alternative<EcPublicKey>(*ec));
    EXPECT_EQ(std::get<EcPublicKey>(*ec).crv, "P-384");
    EXPECT_EQ(std::get<EcPublicKey>(*ec).x.size(), 48u);

    EXPECT_FALSE(publicKeyFromCertDer(T::selfSignedCert(T::namedKey("ED25519").get(), "Ed")).has_value());
    EXPECT_FALSE(publicKeyFromCertDer(std::vector<std::uint8_t>{0x30, 0x03, 0x02, 0x01, 0x00}).has_value());
}
