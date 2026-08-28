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

#include <LibreSCRS/Agent/util/Sha256Hex.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
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

namespace {

// Mint a self-signed EC cert on the named curve; return DER.
std::vector<std::uint8_t> makeEcDer(const char* curve)
{
    EVP_PKEY* pkey = EVP_EC_gen(curve);
    EXPECT_NE(pkey, nullptr);
    X509* x = X509_new();
    EXPECT_NE(x, nullptr);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x5678);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("rawcrypto-ec-kat"), -1,
                               -1, 0);
    X509_set_issuer_name(x, name);
    EXPECT_GT(X509_sign(x, pkey, EVP_sha384()), 0);
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

// Mechanism-family criterion (pure DER predicate): the resolved certificate's
// public-key algorithm routes an EC key to the pre-hashed ECDSA path; RSA and
// unparseable certs keep the RSA flow.
TEST(LmRawCrypto, EcdsaFamilyCriterionReadsThePublicKeyAlgorithm)
{
    const auto ec = makeEcDer("P-384");
    ASSERT_FALSE(ec.empty());
    EXPECT_TRUE(certPublicKeyIsEcdsa(ec)) << "a P-384 cert must route to the ECDSA family";

    const auto rsa = makeV3DerWithKeyUsage("digitalSignature");
    ASSERT_FALSE(rsa.empty());
    EXPECT_FALSE(certPublicKeyIsEcdsa(rsa)) << "an RSA cert must keep the RSA flow";

    const std::vector<std::uint8_t> garbage{0x00, 0x01, 0x02, 0x03};
    EXPECT_FALSE(certPublicKeyIsEcdsa(garbage)) << "unparseable DER must keep the RSA flow";
}

// The pre-hashed ECDSA mechanism only names the digest family for transport
// (the plugin signs the bytes as-given); the mapping is by canonical digest
// length with SHA-512 as the long-input catch-all.
TEST(LmRawCrypto, EcdsaMechanismFollowsDigestLength)
{
    using M = LibreSCRS::Plugin::SignMechanism;
    EXPECT_EQ(ecdsaMechanismForDigestLength(32), M::ECDSA_SHA256); // SHA-256
    EXPECT_EQ(ecdsaMechanismForDigestLength(48), M::ECDSA_SHA384); // SHA-384
    EXPECT_EQ(ecdsaMechanismForDigestLength(64), M::ECDSA_SHA512); // SHA-512
    EXPECT_EQ(ecdsaMechanismForDigestLength(20), M::ECDSA_SHA256); // SHA-1-sized rides the smallest
    EXPECT_EQ(ecdsaMechanismForDigestLength(49), M::ECDSA_SHA512); // between 384 and 512 -> catch-all
}

// --- signRaw end-to-end mechanism routing (hermetic, no card) -------------
//
// selectSigningCandidate resolves certId against the candidate's
// readCertificates off the session; a recording stub captures the mechanism
// signRaw dispatches to and the PIN it verifies, so a regression in the
// EC-vs-RSA routing, the pre-hashed-ECDSA mechanism, or the fail-closed PIN
// verify is caught without a live card.

namespace {

using LibreSCRS::Agent::sha256Hex;
using LibreSCRS::Plugin::CardCapabilities;
using LibreSCRS::Plugin::CertificateData;
using LibreSCRS::Plugin::DecipherMechanism;
using LibreSCRS::Plugin::DecipherResult;
using LibreSCRS::Plugin::PINResult;
using LibreSCRS::Plugin::PINResultOutcome;
using LibreSCRS::Plugin::SignMechanism;
using LibreSCRS::Plugin::SignResult;
using LibreSCRS::Plugin::SignResultOutcome;

class RecordingStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    RecordingStubPlugin(std::string id, CertificateData cert, PINResultOutcome verifyOutcome)
        : m_cert(std::move(cert)), m_verifyOutcome(verifyOutcome)
    {
        setIdentity(std::move(id), "recording-stub", 0);
    }

    CardCapabilities capabilities() const override
    {
        return CardCapabilities::PKI | CardCapabilities::PinManagement;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    std::vector<CertificateData> readCertificates(LibreSCRS::SmartCard::CardSession&) const override
    {
        return {m_cert};
    }
    PINResult verifyPIN(LibreSCRS::SmartCard::CardSession&, const LibreSCRS::Secure::String&) const override
    {
        ++m_verifyCalls;
        PINResult r;
        r.outcome = m_verifyOutcome;
        return r;
    }

    // Mutable capture (the crypto NVIs are const).
    mutable int m_verifyCalls = 0;
    mutable int m_signCalls = 0;
    mutable std::optional<SignMechanism> m_lastSignMechanism;

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }
    SignResult doSign(LibreSCRS::SmartCard::CardSession&, std::uint16_t, std::span<const std::uint8_t>,
                      SignMechanism mechanism) const override
    {
        ++m_signCalls;
        m_lastSignMechanism = mechanism;
        SignResult r;
        r.outcome = SignResultOutcome::Ok;
        r.signature = {0x01, 0x02, 0x03};
        return r;
    }

private:
    CertificateData m_cert;
    PINResultOutcome m_verifyOutcome;
};

CertificateData ecCert(std::uint16_t keyFid)
{
    CertificateData cd;
    cd.derBytes = makeEcDer("P-384");
    cd.keyFID = keyFid;
    return cd;
}

} // namespace

TEST(LmRawCrypto, SignRawRoutesEcKeyToEcdsaMechanism)
{
    auto cert = ecCert(0x47);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    // A 48-byte (SHA-384) digest drives the SHA-384 mechanism.
    const std::vector<std::uint8_t> digest(48, 0xAB);
    const auto result = signRaw(candidates, certId, digest, &pin, *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(stub->m_lastSignMechanism.has_value());
    EXPECT_EQ(*stub->m_lastSignMechanism, SignMechanism::ECDSA_SHA384) << "EC key must route to pre-hashed ECDSA";
    EXPECT_EQ(stub->m_verifyCalls, 1) << "PIN-as-consent must verify before the EC sign";
    EXPECT_EQ(stub->m_signCalls, 1);
}

TEST(LmRawCrypto, SignRawEcPathFailsClosedOnWrongPin)
{
    auto cert = ecCert(0x47);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::InvalidPin);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};

    const std::vector<std::uint8_t> digest(48, 0xAB);
    const auto result = signRaw(candidates, certId, digest, &pin, *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::AuthFailed);
    EXPECT_EQ(stub->m_verifyCalls, 1);
    EXPECT_EQ(stub->m_signCalls, 0) << "a wrong PIN must NOT reach the card's sign op";
}

TEST(LmRawCrypto, SignRawEcMechanismFollowsDigestLength)
{
    auto cert = ecCert(0x47);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> digest(32, 0xCD); // SHA-256 sized
    const auto result = signRaw(candidates, certId, digest, &pin, *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(stub->m_lastSignMechanism.has_value());
    EXPECT_EQ(*stub->m_lastSignMechanism, SignMechanism::ECDSA_SHA256) << "input.size() drives the mechanism value";
}
