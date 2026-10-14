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

#include "TestCertMint.h"

#include <LibreSCRS/Agent/util/Sha256Hex.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent::Operations;
using LibreSCRS::Agent::Mechanism;

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
    EXPECT_NE(static_cast<int>(RawCryptoStatus::ConsentRequired), static_cast<int>(RawCryptoStatus::Ok));
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

// --- signRaw end-to-end mechanism routing (hermetic, no card) -------------
//
// selectSigningCandidate resolves certId against the candidate's
// readCertificates off the session; a recording stub captures the mechanism
// signRaw dispatches to and the PIN it hands the plugin, so a regression in
// the EC-vs-RSA routing, the pre-hashed-ECDSA mechanism, or the PIN's
// deposit-and-erase is caught without a live card.

namespace {

using LibreSCRS::Agent::sha256Hex;
using LibreSCRS::Plugin::CardCapabilities;
using LibreSCRS::Plugin::CertificateData;
using LibreSCRS::Plugin::DecipherMechanism;
using LibreSCRS::Plugin::DecipherResult;
using LibreSCRS::Plugin::DecipherResultOutcome;
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
        ++m_readCalls;
        return {m_cert};
    }
    PINResult verifyPIN(LibreSCRS::SmartCard::CardSession&, const LibreSCRS::Secure::String&) const override
    {
        ++m_verifyCalls;
        PINResult r;
        r.outcome = m_verifyOutcome;
        return r;
    }
    void setCredentials(LibreSCRS::SmartCard::CardSession&, std::string_view key,
                        const LibreSCRS::Secure::String& value) override
    {
        m_credentialWrites.emplace_back(std::string{key}, value.empty());
        if (m_throwOnErase && value.empty()) {
            throw std::runtime_error("card gone");
        }
    }
    void setAlwaysAuthenticate(bool on)
    {
        m_cert.alwaysAuthenticate = on;
    }
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession&) const override
    {
        return m_preReadAuth;
    }

    // Mutable capture (the crypto NVIs are const).
    mutable int m_readCalls = 0;
    mutable int m_verifyCalls = 0;
    mutable int m_signCalls = 0;
    mutable int m_decipherCalls = 0;
    mutable std::optional<SignMechanism> m_lastSignMechanism;
    mutable std::optional<DecipherMechanism> m_lastDecipherMechanism;
    // (key, the value was empty) per setCredentials call, in order.
    std::vector<std::pair<std::string, bool>> m_credentialWrites;
    bool m_throwOnErase = false;
    bool m_throwOnSign = false;
    // false: a DigestInfo card, which has no hash-on-card RSA_SHA256.
    bool m_signsHashOnCard = true;
    // The length of the secret an ECDH answers with (a P-384 key's is 48).
    std::size_t m_ecdhSecretLength = 48;
    // Can: a PACE card whose RSA key hashes the message itself.
    LibreSCRS::Auth::PreReadAuthMethod m_preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::None;
    SignResultOutcome m_signOutcome = SignResultOutcome::Ok;
    DecipherResultOutcome m_decipherOutcome = DecipherResultOutcome::Ok;

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
        if (m_throwOnSign) {
            throw std::runtime_error("reader gone");
        }
        SignResult r;
        if (mechanism == SignMechanism::RSA_SHA256 && !m_signsHashOnCard) {
            r.outcome = SignResultOutcome::NotImplemented;
            return r;
        }
        r.outcome = m_signOutcome;
        if (r.outcome == SignResultOutcome::Ok) {
            r.signature = {0x01, 0x02, 0x03};
        }
        return r;
    }
    DecipherResult doDecipher(LibreSCRS::SmartCard::CardSession&, std::uint16_t, std::span<const std::uint8_t>,
                              DecipherMechanism mechanism) const override
    {
        ++m_decipherCalls;
        m_lastDecipherMechanism = mechanism;
        DecipherResult r;
        r.outcome = m_decipherOutcome;
        if (r.outcome == DecipherResultOutcome::Ok && mechanism == DecipherMechanism::ECDH_RAW) {
            r.plaintext.assign(m_ecdhSecretLength, 0x5A);
        } else if (r.outcome == DecipherResultOutcome::Ok) {
            r.plaintext = {0x11, 0x22};
        }
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

CertificateData rsaCert(std::uint16_t keyFid, bool alwaysAuthenticate)
{
    CertificateData cd;
    cd.derBytes = makeV3DerWithKeyUsage("digitalSignature,keyEncipherment");
    cd.keyFID = keyFid;
    cd.alwaysAuthenticate = alwaysAuthenticate;
    return cd;
}

// The key a preflight would hand the operation: the same routing, read once.
SigningSelection resolved(const CandidateList& candidates, const std::string& certId,
                          LibreSCRS::SmartCard::CardSession& session)
{
    auto selection = selectSigningCandidate(candidates, certId, session);
    EXPECT_TRUE(selection.has_value()) << "the stub owns the certificate";
    return selection.value_or(SigningSelection{});
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
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                                LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(stub->m_lastSignMechanism.has_value());
    EXPECT_EQ(*stub->m_lastSignMechanism, SignMechanism::ECDSA_SHA384) << "EC key must route to pre-hashed ECDSA";
    EXPECT_EQ(stub->m_verifyCalls, 0) << "the plugin presents the PIN inside the sign itself";
    EXPECT_EQ(stub->m_signCalls, 1);
}

TEST(LmRawCrypto, SignRawEcPathFailsClosedOnWrongPin)
{
    // The plugin presents the PIN in the sign's own card transaction and
    // reports the card's refusal; nothing is signed and the host hears
    // AuthFailed, as it did from a rejected verifyPIN.
    auto cert = ecCert(0x47);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::InvalidPin);
    stub->m_signOutcome = SignResultOutcome::PinIncorrect;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};

    const std::vector<std::uint8_t> digest(48, 0xAB);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                                LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::AuthFailed);
    EXPECT_EQ(stub->m_verifyCalls, 0) << "no separate VERIFY before the operation";
    EXPECT_TRUE(result.bytes.empty()) << "a refused PIN yields no signature";
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
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                                LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(stub->m_lastSignMechanism.has_value());
    EXPECT_EQ(*stub->m_lastSignMechanism, SignMechanism::ECDSA_SHA256) << "input.size() drives the mechanism value";
}

// --- the card's per-operation consent rule and the PIN's lifetime ----------

TEST(LmRawCrypto, SignRawWithoutAPinAsksForConsentOnAKeyTheCardMarks)
{
    auto cert = rsaCert(0x9C, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> input(51, 0x30);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, /*pin=*/nullptr,
                                *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::ConsentRequired);
    EXPECT_TRUE(result.alwaysAuthenticate);
    EXPECT_EQ(stub->m_signCalls, 0) << "the key must not be used without this operation's PIN";
    EXPECT_EQ(stub->m_verifyCalls, 0);
}

TEST(LmRawCrypto, DecryptRawWithoutAPinAsksForConsentOnAKeyTheCardMarks)
{
    auto cert = rsaCert(0x9D, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> ciphertext(256, 0x42);
    const auto result = decryptRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Decrypt, ciphertext,
                                   nullptr, *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::ConsentRequired);
    EXPECT_EQ(stub->m_verifyCalls, 0);
    EXPECT_EQ(stub->m_decipherCalls, 0) << "the key must not be used without this operation's PIN";
}

TEST(LmRawCrypto, AnOrdinaryKeyWithoutAPinSignsUnderTheLease)
{
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> input(51, 0x30);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, nullptr,
                                *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    EXPECT_FALSE(result.alwaysAuthenticate);
    EXPECT_EQ(stub->m_signCalls, 1);
    EXPECT_TRUE(stub->m_credentialWrites.empty()) << "no PIN given, none handed over or erased";
}

TEST(LmRawCrypto, AMarkedKeyKeepsNoPinPastItsOperation)
{
    auto cert = rsaCert(0x9C, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("pkcs15", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> input(32, 0x11);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, &pin, *session,
                                LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    EXPECT_TRUE(result.alwaysAuthenticate);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_EQ(stub->m_credentialWrites[0], (std::pair<std::string, bool>{"pin", false}))
        << "the PIN is handed to the plugin for this operation";
    EXPECT_EQ(stub->m_credentialWrites[1], (std::pair<std::string, bool>{"pin", true}))
        << "and only the PIN is erased once the operation is done";
}

TEST(LmRawCrypto, AnOrdinaryKeyKeepsItsPinForTheLease)
{
    // A hash-on-card card signs only with a deposited PIN, so an ordinary
    // key's deposit serves the rest of the lease; it reaches the card only
    // through the plugin, never through a separate VERIFY.
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("pkcs15", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> input(32, 0x11);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, &pin, *session,
                                LibreSCRS::CancelToken{});
    ASSERT_EQ(result.status, RawCryptoStatus::Ok);
    EXPECT_FALSE(result.alwaysAuthenticate);
    EXPECT_EQ(stub->m_verifyCalls, 0);
    ASSERT_EQ(stub->m_credentialWrites.size(), 1u) << "an ordinary key's deposit serves the rest of the lease";
    EXPECT_EQ(stub->m_credentialWrites[0], (std::pair<std::string, bool>{"pin", false}));
}

TEST(LmRawCrypto, ARefusedPinOnAnOrdinaryKeyIsErased)
{
    // The host ends the lease on AuthFailed; the PIN the card refused must not
    // stay behind for the plugin to present again.
    auto cert = ecCert(0x9A);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_signOutcome = SignResultOutcome::PinIncorrect;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};

    const std::vector<std::uint8_t> digest(32, 0xCD);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_EQ(stub->m_credentialWrites[1], (std::pair<std::string, bool>{"pin", true}));
}

TEST(LmRawCrypto, AFailedOperationOnAnOrdinaryKeyErasesItsPin)
{
    // Only a PIN that just worked is kept: a lease does not start on a failure.
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("pkcs15", cert, PINResultOutcome::Ok);
    stub->m_signOutcome = SignResultOutcome::PluginError;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> input(32, 0x11);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, &pin, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::CardError);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_TRUE(stub->m_credentialWrites[1].second);
}

TEST(LmRawCrypto, AnOrdinaryKeysPinIsErasedWhenTheOperationThrows)
{
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("pkcs15", cert, PINResultOutcome::Ok);
    stub->m_throwOnSign = true;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> input(32, 0x11);
    EXPECT_THROW((void)signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, &pin, *session,
                               LibreSCRS::CancelToken{}),
                 std::runtime_error);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_TRUE(stub->m_credentialWrites[1].second) << "erased on the way out of the exception";
}

TEST(LmRawCrypto, AKeptPinTheCardRefusesIsErased)
{
    // An ordinary key's PIN stays deposited for the lease. If the card refuses
    // it later (the PIN was changed meanwhile), the plugin must not present it
    // again for the next caller: every attempt would cost a retry nobody typed.
    auto cert = ecCert(0x9A);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_signOutcome = SignResultOutcome::PinIncorrect;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> digest(32, 0xCD);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, /*pin=*/nullptr, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    ASSERT_EQ(stub->m_credentialWrites.size(), 1u);
    EXPECT_EQ(stub->m_credentialWrites[0], (std::pair<std::string, bool>{"pin", true}));
}

TEST(LmRawCrypto, AKeptPinTheCardRefusesForADecryptionIsErased)
{
    auto cert = rsaCert(0x9D, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_decipherOutcome = DecipherResultOutcome::PinIncorrect;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> ciphertext(256, 0x42);
    EXPECT_EQ(decryptRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Decrypt, ciphertext, nullptr,
                         *session, LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    ASSERT_EQ(stub->m_credentialWrites.size(), 1u);
    EXPECT_EQ(stub->m_credentialWrites[0], (std::pair<std::string, bool>{"pin", true}));
}

TEST(LmRawCrypto, TheConsentRuleIsReadFromTheCardOnEveryCall)
{
    // Nothing remembered: the card in the reader decides each time.
    auto cert = rsaCert(0x9C, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const std::vector<std::uint8_t> input(51, 0x30);

    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, nullptr, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::Ok);
    stub->setAlwaysAuthenticate(true);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, nullptr, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::ConsentRequired);
}

TEST(LmRawCrypto, ErasingThePinNeverThrowsOutOfTheOperation)
{
    auto cert = rsaCert(0x9C, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("pkcs15", cert, PINResultOutcome::Ok);
    stub->m_throwOnErase = true;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};
    const std::vector<std::uint8_t> input(32, 0x11);

    RawCryptoResult result;
    EXPECT_NO_THROW(result = signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, &pin,
                                     *session, LibreSCRS::CancelToken{}));
    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
}

TEST(LmRawCrypto, AMarkedKeySignsWithThePinInOneCall)
{
    // VERIFY and the PSO in one card transaction: no separate verifyPIN, the
    // PIN handed over for this operation and erased after it.
    auto cert = ecCert(0x9C);
    cert.alwaysAuthenticate = true;
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> digest(32, 0xCD);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                                LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    EXPECT_EQ(stub->m_verifyCalls, 0) << "no separate VERIFY before the operation";
    EXPECT_EQ(stub->m_signCalls, 1);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_EQ(stub->m_credentialWrites[0], (std::pair<std::string, bool>{"pin", false}));
    EXPECT_EQ(stub->m_credentialWrites[1], (std::pair<std::string, bool>{"pin", true}));
}

TEST(LmRawCrypto, AMarkedKeyDecryptsWithThePinInOneCall)
{
    auto cert = rsaCert(0x9D, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> ciphertext(256, 0x42);
    const auto result = decryptRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Decrypt, ciphertext, &pin,
                                   *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    EXPECT_TRUE(result.alwaysAuthenticate);
    EXPECT_EQ(stub->m_verifyCalls, 0);
    EXPECT_EQ(stub->m_decipherCalls, 1);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u) << "handed over, then erased";
    EXPECT_FALSE(stub->m_credentialWrites[0].second);
    EXPECT_TRUE(stub->m_credentialWrites[1].second);
}

TEST(LmRawCrypto, AWrongPinOnAMarkedKeyIsAnAuthFailure)
{
    // The plugin reports the PIN it verified itself; the host must hear the
    // same answer a rejected verifyPIN gives (it revokes the lease), not a
    // card fault. The PIN is erased on this exit too.
    auto cert = ecCert(0x9C);
    cert.alwaysAuthenticate = true;
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_signOutcome = SignResultOutcome::PinIncorrect;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};

    const std::vector<std::uint8_t> digest(32, 0xCD);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_TRUE(stub->m_credentialWrites[1].second) << "erased on the failure path as well";
}

TEST(LmRawCrypto, ABlockedPinOnAMarkedKeyIsAnAuthFailure)
{
    auto cert = ecCert(0x9C);
    cert.alwaysAuthenticate = true;
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_signOutcome = SignResultOutcome::PinBlocked;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};

    const std::vector<std::uint8_t> digest(32, 0xCD);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::EcdsaSign, digest, &pin, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
}

TEST(LmRawCrypto, AWrongPinOnAMarkedKeysDecryptionIsAnAuthFailure)
{
    auto cert = rsaCert(0x9D, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_decipherOutcome = DecipherResultOutcome::PinIncorrect;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};

    const std::vector<std::uint8_t> ciphertext(256, 0x42);
    EXPECT_EQ(decryptRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Decrypt, ciphertext, &pin, *session,
                         LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
}

TEST(LmRawCrypto, TheRsaPkcsMechanismPresentsThePinThroughThePluginToo)
{
    // A DigestInfo card signs RSA_PKCS over the caller's block; the deposited
    // PIN is presented by the plugin inside the sign, with no separate VERIFY
    // in between.
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    stub->m_signsHashOnCard = false;
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};

    const std::vector<std::uint8_t> digestInfo(51, 0x30);
    const auto result = signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, digestInfo, &pin,
                                *session, LibreSCRS::CancelToken{});

    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(stub->m_lastSignMechanism.has_value());
    EXPECT_EQ(*stub->m_lastSignMechanism, SignMechanism::RSA_PKCS);
    EXPECT_EQ(stub->m_verifyCalls, 0) << "no separate VERIFY before the sign";
    EXPECT_EQ(stub->m_signCalls, 1);
    ASSERT_EQ(stub->m_credentialWrites.size(), 1u) << "deposited once, kept for the lease";
    EXPECT_FALSE(stub->m_credentialWrites[0].second);
}

TEST(LmRawCrypto, AnEmptyPinIsNeverHandedToThePlugin)
{
    // An empty value erases the plugin's deposit, so the card would run the
    // operation on whatever the held session is already verified for. Refused
    // as a failed PIN, before the key is used; a PIN kept from an earlier
    // operation is erased on the way out like on any other failure.
    auto cert = rsaCert(0x9C, /*alwaysAuthenticate=*/true);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const LibreSCRS::Secure::String empty;

    const std::vector<std::uint8_t> input(32, 0x11);
    EXPECT_EQ(signRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Sign, input, &empty, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    const std::vector<std::uint8_t> ciphertext(256, 0x42);
    EXPECT_EQ(decryptRaw(resolved(candidates, certId, *session), Mechanism::RsaPkcs1Decrypt, ciphertext, &empty,
                         *session, LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    EXPECT_EQ(stub->m_signCalls, 0);
    EXPECT_EQ(stub->m_decipherCalls, 0);
    for (const auto& write : stub->m_credentialWrites) {
        EXPECT_EQ(write, (std::pair<std::string, bool>{"pin", true})) << "only erasures, never a deposit";
    }
}

TEST(LmRawCrypto, AMarkedKeyThatMayNotDecryptAsksForNoConsent)
{
    // The certificate forbids decryption: answering ConsentRequired first
    // would cost the human a PIN prompt for an operation refused right after.
    CertificateData cd;
    cd.derBytes = makeV3DerWithKeyUsage("digitalSignature,nonRepudiation");
    cd.keyFID = 0x9C;
    cd.alwaysAuthenticate = true;
    const std::string certId = sha256Hex(cd.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    const CandidateList candidates{stub};
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> ciphertext(256, 0x42);
    EXPECT_EQ(preflight(candidates, certId, Mechanism::RsaPkcs1Decrypt, ciphertext, *session).status,
              RawCryptoStatus::NotSupported);
    EXPECT_EQ(stub->m_decipherCalls, 0);
}

// The digest IS the ECDSA mechanism's input, so its length names the hash --
// exactly, no rounding: 20 (SHA-1) and 51 (a DigestInfo) are refused.
TEST(LmRawCrypto, EcdsaMechanismIsTheDigestsOwn)
{
    using M = LibreSCRS::Plugin::SignMechanism;
    EXPECT_EQ(ecdsaMechanismForDigest(32), M::ECDSA_SHA256);
    EXPECT_EQ(ecdsaMechanismForDigest(48), M::ECDSA_SHA384);
    EXPECT_EQ(ecdsaMechanismForDigest(64), M::ECDSA_SHA512);
    for (std::size_t bad : {std::size_t{0}, std::size_t{20}, std::size_t{49}, std::size_t{51}, std::size_t{65}}) {
        EXPECT_FALSE(ecdsaMechanismForDigest(bad).has_value()) << bad;
    }
}

// A mechanism of the wrong family for the key is refused before anything
// else: no PIN is deposited, the key is not used.
TEST(LmRawCrypto, PreflightRefusesAMechanismOfTheWrongFamily)
{
    namespace T = LibreSCRS::Agent::Test;
    CertificateData ec;
    ec.derBytes = T::selfSignedCert(T::ecKey("P-384").get(), "LK", "critical,digitalSignature,keyEncipherment");
    ec.keyFID = std::uint16_t{0x47};
    auto ecStub = std::make_shared<RecordingStubPlugin>("pkcs15", ec, PINResultOutcome::Ok);
    auto rsa = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    auto rsaStub = std::make_shared<RecordingStubPlugin>("opensc", rsa, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");

    const std::vector<std::uint8_t> digestInfo(51, 0x30);
    EXPECT_EQ(preflight({ecStub}, sha256Hex(ec.derBytes), Mechanism::RsaPkcs1Sign, digestInfo, *session).status,
              RawCryptoStatus::InvalidInput);
    EXPECT_EQ(preflight({ecStub}, sha256Hex(ec.derBytes), Mechanism::RsaPkcs1Decrypt,
                        std::vector<std::uint8_t>(96, 0x01), *session)
                  .status,
              RawCryptoStatus::InvalidInput)
        << "an EC key with keyEncipherment still does not decrypt";
    EXPECT_EQ(preflight({rsaStub}, sha256Hex(rsa.derBytes), Mechanism::EcdsaSign, std::vector<std::uint8_t>(32, 0x01),
                        *session)
                  .status,
              RawCryptoStatus::InvalidInput);
    EXPECT_EQ(ecStub->m_signCalls + ecStub->m_decipherCalls + rsaStub->m_signCalls, 0);
    EXPECT_TRUE(ecStub->m_credentialWrites.empty());
    EXPECT_TRUE(rsaStub->m_credentialWrites.empty());
}

// Lengths the card would refuse -- or worse, answer with a plain 6A80 that ends
// a PACE secure-messaging session -- are refused here instead.
TEST(LmRawCrypto, PreflightRefusesAnInputOfTheWrongLength)
{
    namespace T = LibreSCRS::Agent::Test;
    CertificateData ec;
    ec.derBytes = T::selfSignedCert(T::ecKey("P-384").get(), "LK", "critical,digitalSignature");
    ec.keyFID = std::uint16_t{0x47};
    auto rsa = rsaCert(0x9A, /*alwaysAuthenticate=*/false); // 2048 bits: k = 256
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const CandidateList ecCand{std::make_shared<RecordingStubPlugin>("pkcs15", ec, PINResultOutcome::Ok)};
    const CandidateList rsaCand{std::make_shared<RecordingStubPlugin>("opensc", rsa, PINResultOutcome::Ok)};
    auto hashing = std::make_shared<RecordingStubPlugin>("pkcs15", rsa, PINResultOutcome::Ok);
    hashing->m_preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::Can;
    const CandidateList paceCand{hashing};
    const auto ecId = sha256Hex(ec.derBytes);
    const auto rsaId = sha256Hex(rsa.derBytes);
    const auto status = [&](const CandidateList& c, const std::string& id, Mechanism m, std::size_t len) {
        return preflight(c, id, m, std::vector<std::uint8_t>(len, 0x01), *session).status;
    };
    EXPECT_EQ(status(ecCand, ecId, Mechanism::EcdsaSign, 20), RawCryptoStatus::InvalidInput);
    EXPECT_EQ(status(ecCand, ecId, Mechanism::EcdsaSign, 51), RawCryptoStatus::InvalidInput);
    EXPECT_EQ(status(ecCand, ecId, Mechanism::EcdsaSign, 48), RawCryptoStatus::Ok);
    EXPECT_EQ(status(rsaCand, rsaId, Mechanism::RsaPkcs1Sign, 0), RawCryptoStatus::InvalidInput);
    EXPECT_EQ(status(rsaCand, rsaId, Mechanism::RsaPkcs1Sign, 246), RawCryptoStatus::InvalidInput); // > k - 11
    EXPECT_EQ(status(rsaCand, rsaId, Mechanism::RsaPkcs1Sign, 245), RawCryptoStatus::Ok);
    EXPECT_EQ(status(paceCand, rsaId, Mechanism::Sha256RsaPkcs1Sign, 0), RawCryptoStatus::InvalidInput);
    EXPECT_EQ(status(paceCand, rsaId, Mechanism::Sha256RsaPkcs1Sign, 4096), RawCryptoStatus::Ok);
    EXPECT_EQ(status(rsaCand, rsaId, Mechanism::RsaPkcs1Decrypt, 255), RawCryptoStatus::InvalidInput);
    EXPECT_EQ(status(rsaCand, rsaId, Mechanism::RsaPkcs1Decrypt, 256), RawCryptoStatus::Ok);
}

// The preflight's read is the one the operation uses: one read of the card's
// certificates for the whole signature, and the resolved key is the one asked for.
TEST(LmRawCrypto, PreflightResolvesTheKeyTheOperationThenUses)
{
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};
    const std::vector<std::uint8_t> digestInfo(51, 0x30);

    const auto checked = preflight({stub}, certId, Mechanism::RsaPkcs1Sign, digestInfo, *session);
    ASSERT_EQ(checked.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(checked.key.has_value());
    EXPECT_EQ(sha256Hex(checked.key->cert.derBytes), certId);
    EXPECT_EQ(
        signRaw(*checked.key, Mechanism::RsaPkcs1Sign, digestInfo, &pin, *session, LibreSCRS::CancelToken{}).status,
        RawCryptoStatus::Ok);
    EXPECT_EQ(stub->m_readCalls, 1) << "the card's certificates are read once per signature";
}

// The operation runs exactly the mechanism the caller named. A plugin that
// lacks it answers NotSupported -- there is no second, different try.
TEST(LmRawCrypto, SignRawCallsExactlyTheRequestedPluginMechanism)
{
    auto cert = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    const std::string certId = sha256Hex(cert.derBytes);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};
    const std::vector<std::uint8_t> input(51, 0x30);

    auto hashOnCard = std::make_shared<RecordingStubPlugin>("pkcs15", cert, PINResultOutcome::Ok);
    EXPECT_EQ(signRaw(resolved({hashOnCard}, certId, *session), Mechanism::Sha256RsaPkcs1Sign, input, &pin, *session,
                      LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::Ok);
    EXPECT_EQ(hashOnCard->m_lastSignMechanism, SignMechanism::RSA_SHA256);
    EXPECT_EQ(hashOnCard->m_signCalls, 1);

    auto digestInfoCard = std::make_shared<RecordingStubPlugin>("opensc", cert, PINResultOutcome::Ok);
    digestInfoCard->m_signsHashOnCard = false;
    EXPECT_EQ(signRaw(resolved({digestInfoCard}, certId, *session), Mechanism::Sha256RsaPkcs1Sign, input, &pin,
                      *session, LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::NotSupported)
        << "a card without on-card hashing is told so, never handed the block as a DigestInfo";
    EXPECT_EQ(digestInfoCard->m_signCalls, 1) << "no fallback to another mechanism";
}

// A PACE card's RSA key hashes the message on the card, so a caller-built
// PKCS#1 block cannot be signed with it, and any other card's RSA key takes
// only such a block, never a message to hash: each is refused before any PIN
// prompt, for every client alike, rather than after the PIN in the plugin.
// The mechanism each key does take, and ECDSA with an EC key on a PACE card,
// still pass.
TEST(LmRawCrypto, PreflightGivesAnRsaKeyOnlyTheMechanismItsCardTakes)
{
    namespace T = LibreSCRS::Agent::Test;
    auto rsa = rsaCert(0x9A, /*alwaysAuthenticate=*/false);
    auto pace = std::make_shared<RecordingStubPlugin>("pkcs15", rsa, PINResultOutcome::Ok);
    pace->m_preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::Can;
    auto plain = std::make_shared<RecordingStubPlugin>("opensc", rsa, PINResultOutcome::Ok);
    CertificateData ec;
    ec.derBytes = T::selfSignedCert(T::ecKey("P-384").get(), "LK", "critical,digitalSignature");
    ec.keyFID = std::uint16_t{0x47};
    auto paceEc = std::make_shared<RecordingStubPlugin>("pkcs15", ec, PINResultOutcome::Ok);
    paceEc->m_preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::Can;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const auto rsaId = sha256Hex(rsa.derBytes);
    const std::vector<std::uint8_t> digestInfo(51, 0x30);

    EXPECT_EQ(preflight({pace}, rsaId, Mechanism::RsaPkcs1Sign, digestInfo, *session).status,
              RawCryptoStatus::InvalidInput);
    EXPECT_EQ(preflight({pace}, rsaId, Mechanism::Sha256RsaPkcs1Sign, digestInfo, *session).status,
              RawCryptoStatus::Ok);
    EXPECT_EQ(preflight({plain}, rsaId, Mechanism::RsaPkcs1Sign, digestInfo, *session).status, RawCryptoStatus::Ok);
    EXPECT_EQ(preflight({plain}, rsaId, Mechanism::Sha256RsaPkcs1Sign, digestInfo, *session).status,
              RawCryptoStatus::InvalidInput)
        << "a card that does not hash is never handed a message to hash";
    EXPECT_EQ(
        preflight({paceEc}, sha256Hex(ec.derBytes), Mechanism::EcdsaSign, std::vector<std::uint8_t>(48, 0x01), *session)
            .status,
        RawCryptoStatus::Ok);
    EXPECT_EQ(pace->m_signCalls + plain->m_signCalls + paceEc->m_signCalls, 0);
    EXPECT_TRUE(pace->m_credentialWrites.empty());
}

// --- deriveRaw: ECDH with the resolved key ---------------------------------

namespace {

CertificateData lkDeriveCert(bool canDerive, LibreSCRS::Agent::Test::PkeyPtr& keyOut)
{
    namespace T = LibreSCRS::Agent::Test;
    keyOut = T::ecKey("P-384");
    CertificateData cd;
    cd.derBytes = T::selfSignedCert(keyOut.get(), "LK", "critical,digitalSignature,keyAgreement");
    cd.keyFID = std::uint16_t{0x47};
    cd.canDerive = canDerive;
    return cd;
}

} // namespace

TEST(LmRawCrypto, DeriveRunsEcdhRawOnTheResolvedKey)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());

    const auto checked = preflight({stub}, sha256Hex(cd.derBytes), Mechanism::EcdhDerive, peer, *session);
    ASSERT_EQ(checked.status, RawCryptoStatus::Ok);
    ASSERT_TRUE(checked.key.has_value());
    const auto result = deriveRaw(*checked.key, Mechanism::EcdhDerive, peer, &pin, *session, LibreSCRS::CancelToken{});
    EXPECT_EQ(result.status, RawCryptoStatus::Ok);
    EXPECT_EQ(result.bytes, std::vector<std::uint8_t>(48, 0x5A));
    EXPECT_EQ(stub->m_lastDecipherMechanism, DecipherMechanism::ECDH_RAW);
    ASSERT_EQ(stub->m_credentialWrites.size(), 1u) << "deposited once, kept for an ordinary key's lease";
}

// The secret is ceil(bits/8) bytes of the key's curve, as the wire promises
// its clients: a plugin answer of any other length is a card error, and
// none of it is handed on.
TEST(LmRawCrypto, ADeriveAnswerOfAnotherLengthIsACardError)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());
    for (const std::size_t length : {std::size_t{47}, std::size_t{49}, std::size_t{0}}) {
        auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
        stub->m_ecdhSecretLength = length;
        const auto r = deriveRaw(resolved({stub}, sha256Hex(cd.derBytes), *session), Mechanism::EcdhDerive, peer, &pin,
                                 *session, LibreSCRS::CancelToken{});
        EXPECT_EQ(r.status, RawCryptoStatus::CardError) << length;
        EXPECT_TRUE(r.bytes.empty()) << length;
    }
}

TEST(LmRawCrypto, ADeriveWithoutAPinOnAMarkedKeyAsksForConsent)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    cd.alwaysAuthenticate = true;
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());
    const auto r = deriveRaw(resolved({stub}, sha256Hex(cd.derBytes), *session), Mechanism::EcdhDerive, peer, nullptr,
                             *session, LibreSCRS::CancelToken{});
    EXPECT_EQ(r.status, RawCryptoStatus::ConsentRequired);
    EXPECT_EQ(stub->m_decipherCalls, 0);
}

// The peer point is checked against the card key's curve before any prompt:
// a wrong length, a compressed or infinity point, a point off the curve, a
// point of another curve -- all refused, none reaches the card (a plain 6A80
// under PACE secure messaging would end the session).
TEST(LmRawCrypto, PreflightRefusesAPointTheKeysCurveDoesNotHold)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const auto id = sha256Hex(cd.derBytes);
    const auto good = T::encodedPublicPoint(T::ecKey("P-384").get());
    EXPECT_EQ(preflight({stub}, id, Mechanism::EcdhDerive, good, *session).status, RawCryptoStatus::Ok);
    auto offCurve = good;
    offCurve.back() ^= 0x01;
    auto compressed = good;
    compressed[0] = 0x02;
    const std::vector<std::vector<std::uint8_t>> bad{offCurve, compressed, std::vector<std::uint8_t>{0x00},
                                                     std::vector<std::uint8_t>(good.begin(), good.end() - 1),
                                                     T::encodedPublicPoint(T::ecKey("P-256").get())};
    for (const auto& point : bad) {
        EXPECT_EQ(preflight({stub}, id, Mechanism::EcdhDerive, point, *session).status, RawCryptoStatus::InvalidInput)
            << point.size();
    }
    EXPECT_EQ(stub->m_decipherCalls, 0);
    EXPECT_TRUE(stub->m_credentialWrites.empty());
}

TEST(LmRawCrypto, PreflightRefusesDeriveOnAKeyThePluginCannotDriveWith)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/false, key);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());
    auto stub = std::make_shared<RecordingStubPlugin>("pkcs15", cd, PINResultOutcome::Ok);
    EXPECT_EQ(preflight({stub}, sha256Hex(cd.derBytes), Mechanism::EcdhDerive, peer, *session).status,
              RawCryptoStatus::InvalidInput);
    auto rsa = rsaCert(0x9A, false);
    rsa.canDerive = true;
    auto rsaStub = std::make_shared<RecordingStubPlugin>("opensc", rsa, PINResultOutcome::Ok);
    EXPECT_EQ(preflight({rsaStub}, sha256Hex(rsa.derBytes), Mechanism::EcdhDerive, peer, *session).status,
              RawCryptoStatus::InvalidInput);
}

// The PIN guards signRaw keeps, held for a derive too: an empty PIN never
// reaches the plugin and leaves only erasures behind -- otherwise the card
// would run ECDH on whatever the held session is already verified for.
TEST(LmRawCrypto, ADeriveWithAnEmptyPinNeverReachesThePlugin)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    const LibreSCRS::Secure::String empty;
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());
    EXPECT_EQ(deriveRaw(resolved({stub}, sha256Hex(cd.derBytes), *session), Mechanism::EcdhDerive, peer, &empty,
                        *session, LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    EXPECT_EQ(stub->m_decipherCalls, 0);
    for (const auto& write : stub->m_credentialWrites) {
        EXPECT_EQ(write, (std::pair<std::string, bool>{"pin", true})) << "only erasures, never a deposit";
    }
}

// A key the card marks for consent per operation keeps no PIN past its derive.
TEST(LmRawCrypto, AMarkedKeysPinIsErasedAfterADerive)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    cd.alwaysAuthenticate = true;
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"654321"};
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());
    const auto r = deriveRaw(resolved({stub}, sha256Hex(cd.derBytes), *session), Mechanism::EcdhDerive, peer, &pin,
                             *session, LibreSCRS::CancelToken{});
    EXPECT_EQ(r.status, RawCryptoStatus::Ok);
    EXPECT_TRUE(r.alwaysAuthenticate);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_EQ(stub->m_credentialWrites[0], (std::pair<std::string, bool>{"pin", false}))
        << "the PIN is handed to the plugin for this derive";
    EXPECT_EQ(stub->m_credentialWrites[1], (std::pair<std::string, bool>{"pin", true}))
        << "and erased once the derive is done";
}

// The card refused the PIN: it must not stay behind for the plugin to present again.
TEST(LmRawCrypto, ARefusedPinOnADeriveIsErased)
{
    namespace T = LibreSCRS::Agent::Test;
    T::PkeyPtr key{nullptr, &EVP_PKEY_free};
    auto cd = lkDeriveCert(/*canDerive=*/true, key);
    auto stub = std::make_shared<RecordingStubPlugin>("opensc", cd, PINResultOutcome::Ok);
    stub->m_decipherOutcome = DecipherResultOutcome::PinIncorrect;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
    LibreSCRS::Secure::String pin{"000000"};
    const auto peer = T::encodedPublicPoint(T::ecKey("P-384").get());
    EXPECT_EQ(deriveRaw(resolved({stub}, sha256Hex(cd.derBytes), *session), Mechanism::EcdhDerive, peer, &pin, *session,
                        LibreSCRS::CancelToken{})
                  .status,
              RawCryptoStatus::AuthFailed);
    ASSERT_EQ(stub->m_credentialWrites.size(), 2u);
    EXPECT_EQ(stub->m_credentialWrites[1], (std::pair<std::string, bool>{"pin", true}));
}
