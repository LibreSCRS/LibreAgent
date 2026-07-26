// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Direct unit coverage for LmTrustVerifier::verify() -- the production
// trust-computation seam. Before this test it was exercised only via
// FakeTrustVerifier at flow level (CertReadFlowTest); this pins the ONE branch
// reachable on a Linux CI box with no TslSources configured: the offline
// early-return. Constructs the REAL LmTrustVerifier over a SigningEngineProvider
// built from a fresh (empty-TSL) ConfigStore -- same fixture shape as
// SigningEngineProviderTest -- and calls verify() with a KAT-style minted
// certificate (LmCertReaderKatTest's own corpus pattern: a self-signed v3 RSA
// cert minted with OpenSSL at runtime). Asserts BOTH the numeric verdict AND
// the exact securityStatus token, pinning the numeric<->token pairing that
// securityToken() encodes.
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
namespace fs = std::filesystem;

namespace {

fs::path uniqueDir(const char* tag)
{
    return fs::temp_directory_path() / (std::string{"ll-trustverifier-"} + tag);
}

// Minimal self-signed v3 cert, same minting pattern as LmCertReaderKatTest's
// makeSelfSignedV3Der -- content is irrelevant to this test (the offline
// early-return in LmTrustVerifier::verify() never parses leafDer), but a real
// KAT-style DER is used rather than garbage bytes so the test stays meaningful
// if verify() ever starts inspecting the leaf before checking for TSL sources.
std::vector<std::uint8_t> mintKatCertDer()
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    EXPECT_NE(x, nullptr);

    X509_set_version(x, 2); // 2 == v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("LmTrustVerifier KAT"),
                               -1, -1, 0);
    X509_set_issuer_name(x, name); // self-signed

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

TEST(LmTrustVerifier, OfflineUnverifiedWhenNoTslSourcesConfigured)
{
    // A fresh ConfigStore (no config file on disk yet) applies built-in
    // defaults, which carry an empty tslSources -- the production-reachable
    // configuration on a Linux box with no TSL configured.
    const auto dir = uniqueDir("offline");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    SigningEngineProvider engine{cfg};
    LmTrustVerifier verifier{engine};

    const auto der = mintKatCertDer();
    ASSERT_FALSE(der.empty());

    const auto verdict = verifier.verify(der, {});

    EXPECT_EQ(verdict.status, CertTrustStatus::OfflineUnverified);
    ASSERT_EQ(verdict.securityStatus.size(), 1u);
    EXPECT_EQ(verdict.securityStatus[0], "offline-unverified");
    fs::remove_all(dir);
}
