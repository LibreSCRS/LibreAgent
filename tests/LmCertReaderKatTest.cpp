// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Known-answer test for the agent-side X.509 parser (certSnapshotFromDer). A
// self-signed v3 certificate is minted with OpenSSL at runtime, fed through the
// exposed parser, and the rendered CertSnapshot fields are asserted. This is the
// regression lock for the frozen Certificates1 field values — in particular the
// version rendering ("v3", not "v4": ParsedCertificate::version() already
// returns the human number) and the keyUsage -> bitmask / signingCapable logic.
#include <LibreSCRS/Agent/operations/LmSeams.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// Mint a self-signed v3 RSA cert with a keyUsage extension; return its DER.
std::vector<std::uint8_t> makeSelfSignedV3Der(const char* commonName, const char* keyUsageValue)
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    EXPECT_NE(x, nullptr);

    X509_set_version(x, 2); // 2 == v3 (raw OpenSSL field is 0-indexed)
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1234);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("LibreSCRS Test"), -1,
                               -1, 0);
    X509_set_issuer_name(x, name); // self-signed: issuer == subject

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, keyUsageValue)) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
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

std::optional<std::string> field(const CertSnapshot& s, const std::string& group, const std::string& key)
{
    for (const auto& g : s.fields) {
        if (g.groupKey == group) {
            for (const auto& f : g.fields) {
                if (f.fieldKey == key) {
                    return f.textValue;
                }
            }
        }
    }
    return std::nullopt;
}

constexpr std::uint32_t kDigitalSignatureBit = 1u << 0; // RFC 5280 bit 0

} // namespace

TEST(LmCertReaderKat, ParsesV3SigningCert)
{
    const auto der = makeSelfSignedV3Der("Pera Peric", "critical,digitalSignature");
    ASSERT_FALSE(der.empty());

    LibreSCRS::Plugin::CertificateData cd;
    cd.label = "Signature";
    cd.derBytes = der;
    cd.keyFID = std::uint16_t{0x1234}; // pairs to an on-card key

    const CertSnapshot s = certSnapshotFromDer(cd);

    EXPECT_EQ(s.certId.size(), 64u) << "certId is lowercase-hex SHA-256(DER)";
    EXPECT_TRUE(s.signingCapable) << "keyFID present + digitalSignature usage";
    EXPECT_NE(s.keyUsageBits & kDigitalSignatureBit, 0u);

    EXPECT_EQ(field(s, "subject", "cn"), "Pera Peric");
    EXPECT_EQ(field(s, "issuer", "cn"), "Pera Peric"); // self-signed
    EXPECT_EQ(field(s, "publicKey", "algorithm"), "RSA");
    EXPECT_EQ(field(s, "publicKey", "sizeBits"), "2048");
    // THE version regression lock: human "v3", not "v4".
    EXPECT_EQ(field(s, "cert", "version"), "v3");
    ASSERT_TRUE(field(s, "validity", "notAfter").has_value());
    EXPECT_NE(field(s, "validity", "notAfter")->find('Z'), std::string::npos) << "ISO-8601 UTC";
    EXPECT_TRUE(field(s, "subject", "dn").has_value());
}

TEST(LmCertReaderKat, NonSigningKeyUsageIsNotSigningCapable)
{
    // keyEncipherment-only cert with a paired key must NOT be signingCapable.
    const auto der = makeSelfSignedV3Der("Enc Only", "critical,keyEncipherment");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der;
    cd.keyFID = std::uint16_t{0x1};
    const CertSnapshot s = certSnapshotFromDer(cd);
    EXPECT_FALSE(s.signingCapable) << "keyUsage lacks digitalSignature/nonRepudiation";
}

TEST(LmCertReaderKat, NoPairedKeyIsNotSigningCapable)
{
    const auto der = makeSelfSignedV3Der("No Key", "critical,digitalSignature");
    ASSERT_FALSE(der.empty());
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = der; // keyFID unset
    const CertSnapshot s = certSnapshotFromDer(cd);
    EXPECT_FALSE(s.signingCapable) << "no on-card private key paired";
}

TEST(LmCertReaderKat, GarbageDerYieldsDiagnosticNotCrash)
{
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = {0xDE, 0xAD, 0xBE, 0xEF};
    cd.keyFID = std::uint16_t{0x1};
    const CertSnapshot s = certSnapshotFromDer(cd);
    EXPECT_EQ(s.certId.size(), 64u) << "certId still minted from the raw bytes";
    EXPECT_FALSE(s.signingCapable) << "unparseable cert is never a usable signing handle";
    EXPECT_TRUE(field(s, "diagnostic", "parseError").has_value()) << "failure surfaced in the reserved group";
    EXPECT_TRUE(s.chainSubjectCns.empty()) << "no PKCS#15 label leaks into chainSubjectCns";
}
