// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Deterministic, card-free unit coverage for the seam routing-selection logic
// extracted out of LmSigner::sign and LmCertificateReader::read. Both decisions
// are exercised here against stub plugins that return canned CertificateData
// (no real signing engine, no real card I/O), so the certId-owner selection and
// the first-non-empty selection are no longer HW-smoke-only.
//
// The expected certId is computed with the production sha256Hex(DER) so each
// case is a true known-answer test, not a tautology against the same code path.
#include "util/Sha256Hex.h" // sha256Hex (certId)
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include "TestCertMint.h"
#include "../src/operations/LmSignResultMapping.h" // mapSigningResultStatus (extracted, unit-testable)

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Signing/SigningResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/Secure/String.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
namespace sign = LibreSCRS::Signing;

namespace {

// Stub CardPlugin whose readCertificates returns a canned list (or throws). The
// rest of the CardPlugin surface is unused by the routing decisions under test.
class CertStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    CertStubPlugin(std::string id, std::vector<LibreSCRS::Plugin::CertificateData> certs, bool throwOnRead = false)
        : m_certs(std::move(certs)), m_throw(throwOnRead)
    {
        setIdentity(std::move(id), 0);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI | LibreSCRS::Plugin::CardCapabilities::PinManagement;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    std::vector<LibreSCRS::Plugin::CertificateData>
    doReadCertificates(LibreSCRS::SmartCard::CardSession&) const override
    {
        if (m_throw) {
            throw std::runtime_error{"stub: readCertificates failed"};
        }
        return m_certs;
    }
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    std::vector<LibreSCRS::Plugin::CertificateData> m_certs;
    bool m_throw;
};

// A certificate the card pairs with a key (a signing candidate).
LibreSCRS::Plugin::CertificateData certWithDer(std::vector<std::uint8_t> der)
{
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = std::move(der);
    cd.keyFID = 0x4401;
    return cd;
}

// A certificate the card lists with no key of its own (an issuer's).
LibreSCRS::Plugin::CertificateData certWithoutKey(std::vector<std::uint8_t> der)
{
    LibreSCRS::Plugin::CertificateData cd;
    cd.derBytes = std::move(der);
    return cd;
}

std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
mkStub(std::string id, std::vector<LibreSCRS::Plugin::CertificateData> certs, bool throwOnRead = false)
{
    return std::make_shared<CertStubPlugin>(std::move(id), std::move(certs), throwOnRead);
}

// A detached CardSession: the stubs ignore it, so it is never touched. Shared
// across cases.
std::shared_ptr<LibreSCRS::SmartCard::CardSession> detachedSession()
{
    return LibreSCRS::SmartCard::Testing::makeDetachedCardSession("FakeReader");
}

} // namespace

// --- selectSigningCandidate (LmSigner::sign routing) ----------------------

TEST(LmSeamsRouting, SelectsTheCandidateOwningTheTargetCertId)
{
    const std::vector<std::uint8_t> derA{0x01, 0x02, 0x03};
    const std::vector<std::uint8_t> derB{0x0A, 0x0B, 0x0C};
    const std::string certIdB = sha256Hex(derB); // the target

    CandidateList candidates{
        mkStub("plugin-a", {certWithDer(derA)}),
        mkStub("plugin-b", {certWithDer(derB)}),
    };
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, certIdB, *session);
    ASSERT_TRUE(sel.has_value()) << "the cert owner must be found";
    EXPECT_EQ(sel->plugin->pluginId(), "plugin-b") << "selects the candidate whose DER hashes to certId";
    EXPECT_EQ(sel->cert.derBytes, derB) << "returns the exact CertificateData selected";
}

TEST(LmSeamsRouting, SkipsAThrowingCandidateAndChoosesTheNextOwner)
{
    const std::vector<std::uint8_t> derTarget{0xDE, 0xAD, 0xBE, 0xEF};
    const std::string certId = sha256Hex(derTarget);

    // First candidate throws on readCertificates, which CardPlugin turns into
    // an empty listing; the owner is the second.
    CandidateList candidates{
        mkStub("plugin-throws", {}, /*throwOnRead=*/true),
        mkStub("plugin-owner", {certWithDer(derTarget)}),
    };
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, certId, *session);
    ASSERT_TRUE(sel.has_value()) << "a throwing candidate is skipped, not fatal";
    EXPECT_EQ(sel->plugin->pluginId(), "plugin-owner");
    EXPECT_EQ(sel->cert.derBytes, derTarget);
}

TEST(LmSeamsRouting, NoCandidateOwnsCertIdYieldsNullopt)
{
    const std::vector<std::uint8_t> derA{0x11};
    const std::vector<std::uint8_t> derB{0x22};
    const std::string certIdAbsent = sha256Hex(std::vector<std::uint8_t>{0x99, 0x88}); // owned by nobody

    CandidateList candidates{
        mkStub("plugin-a", {certWithDer(derA)}),
        mkStub("plugin-b", {certWithDer(derB)}),
    };
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, certIdAbsent, *session);
    ASSERT_FALSE(sel.has_value());
    EXPECT_EQ(sel.error(), SignOutcome::Status::KeyNotFound) << "an unowned certId is a key not found";
}

TEST(LmSeamsRouting, NullCandidateEntryIsSkipped)
{
    const std::vector<std::uint8_t> der{0x42};
    const std::string certId = sha256Hex(der);
    CandidateList candidates{nullptr, mkStub("plugin-owner", {certWithDer(der)})};
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, certId, *session);
    ASSERT_TRUE(sel.has_value());
    EXPECT_EQ(sel->plugin->pluginId(), "plugin-owner");
}

// One candidate that lists the same certificate under two different keys does
// not say which key signs: refused as ambiguous, never the first guessed.
TEST(LmSeamsRouting, OneCandidateWithTheSameCertUnderTwoKeysIsAmbiguous)
{
    const std::vector<std::uint8_t> der{0x5A, 0x5B};
    const std::string certId = sha256Hex(der);
    auto first = certWithDer(der);
    first.keyFID = 0x4410;
    auto second = certWithDer(der);
    second.keyFID = 0x4411;
    CandidateList candidates{mkStub("plugin-dup", {first, second})};
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, certId, *session);
    ASSERT_FALSE(sel.has_value());
    EXPECT_EQ(sel.error(), SignOutcome::Status::KeyAmbiguous);
}

// Two candidates that expose the same certificate expose the same key: the
// card holds one private key per public key. The first candidate, in priority
// order, signs -- a card two plugins both claim is not refused.
TEST(LmSeamsRouting, TwoCandidatesExposingTheSameCertSelectTheFirst)
{
    const std::vector<std::uint8_t> der{0x6A, 0x6B};
    const std::string certId = sha256Hex(der);
    auto cert = certWithDer(der);
    cert.keyFID = 0x4410;
    CandidateList candidates{mkStub("plugin-first", {cert}), mkStub("plugin-second", {cert})};
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, certId, *session);
    ASSERT_TRUE(sel.has_value());
    EXPECT_EQ(sel->plugin->pluginId(), "plugin-first");
}

// --- LmSigner::sign: one read of the card per signature -----------------

namespace {

// A card with two RSA keys held in memory: readCertificates reports both
// certificates (and counts the reads), sign answers with a real PKCS#1 v1.5
// signature by the key the handle names, so the signing service's own checks
// of the result pass.
class TwoKeyCard final : public LibreSCRS::Plugin::CardPlugin
{
public:
    static constexpr std::uint16_t kSignerKey = 0x4410;
    static constexpr std::uint16_t kOtherKey = 0x4411;

    TwoKeyCard()
    {
        setIdentity("two-key", 0);
        signerCert = LibreSCRS::Agent::Test::selfSignedCert(m_signer.get(), "Signer", "critical,digitalSignature");
        otherCert = LibreSCRS::Agent::Test::selfSignedCert(m_other.get(), "Other", "critical,digitalSignature");
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI | LibreSCRS::Plugin::CardCapabilities::PinManagement;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    std::vector<std::uint8_t> signerCert;
    std::vector<std::uint8_t> otherCert;
    mutable int reads = 0;
    mutable std::vector<std::uint16_t> signedWith;

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }
    std::vector<LibreSCRS::Plugin::CertificateData>
    doReadCertificates(LibreSCRS::SmartCard::CardSession&) const override
    {
        ++reads;
        LibreSCRS::Plugin::CertificateData signer;
        signer.label = "Signer";
        signer.derBytes = signerCert;
        signer.keyFID = kSignerKey;
        signer.ckaId = {0x45};
        LibreSCRS::Plugin::CertificateData other;
        other.label = "Other";
        other.derBytes = otherCert;
        other.keyFID = kOtherKey;
        other.ckaId = {0x46};
        return {other, signer};
    }
    LibreSCRS::Plugin::SignResult doSign(LibreSCRS::SmartCard::CardSession&, std::uint16_t keyReference,
                                         std::span<const std::uint8_t> data,
                                         LibreSCRS::Plugin::SignMechanism mechanism) const override
    {
        signedWith.push_back(keyReference);
        LibreSCRS::Plugin::SignResult r;
        r.outcome = LibreSCRS::Plugin::SignResultOutcome::PluginError;
        EVP_PKEY* key = keyReference == kSignerKey  ? m_signer.get()
                        : keyReference == kOtherKey ? m_other.get()
                                                    : nullptr;
        if (key == nullptr) {
            return r;
        }
        // RSA_SHA256 hashes on the card; RSA_PKCS takes the DigestInfo as is.
        const EVP_MD* md = mechanism == LibreSCRS::Plugin::SignMechanism::RSA_SHA256 ? EVP_sha256() : nullptr;
        if (md == nullptr && mechanism != LibreSCRS::Plugin::SignMechanism::RSA_PKCS) {
            r.outcome = LibreSCRS::Plugin::SignResultOutcome::NotImplemented;
            return r;
        }
        std::vector<std::uint8_t> digest(data.begin(), data.end());
        if (md != nullptr) {
            digest.resize(32);
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), digest.data(), &len, md, nullptr);
        }
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
        std::size_t sigLen = 0;
        bool ok = ctx != nullptr && EVP_PKEY_sign_init(ctx) == 1 &&
                  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1 &&
                  (md == nullptr || EVP_PKEY_CTX_set_signature_md(ctx, md) == 1) &&
                  EVP_PKEY_sign(ctx, nullptr, &sigLen, digest.data(), digest.size()) == 1;
        if (ok) {
            r.signature.resize(sigLen);
            ok = EVP_PKEY_sign(ctx, r.signature.data(), &sigLen, digest.data(), digest.size()) == 1;
            r.signature.resize(sigLen);
        }
        EVP_PKEY_CTX_free(ctx);
        if (ok) {
            r.outcome = LibreSCRS::Plugin::SignResultOutcome::Ok;
        } else {
            r.signature.clear();
        }
        return r;
    }

private:
    LibreSCRS::Agent::Test::PkeyPtr m_signer = LibreSCRS::Agent::Test::rsaKey();
    LibreSCRS::Agent::Test::PkeyPtr m_other = LibreSCRS::Agent::Test::rsaKey();
};

LibreSCRS::Auth::CredentialResult aPin(const LibreSCRS::Auth::AuthRequirement&)
{
    std::vector<LibreSCRS::Auth::CredentialEntry> values;
    values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
    return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
}

} // namespace

// The agent reads the card's certificates to find the key the request names;
// the signing service then signs with that key and builds the chain from the
// same read. Reading them a second time costs a SELECT and READ BINARY per
// certificate -- under secure messaging on an eID -- and lets a second rule
// choose again.
TEST(LmSignerSign, OneSignatureReadsTheCardsCertificatesOnceAndSignsWithTheChosenKey)
{
    namespace fs = std::filesystem;
    const auto dir = fs::temp_directory_path() / "la-lmsigner-one-read";
    fs::remove_all(dir);
    {
        Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
        ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{}).ok);
        SigningEngineProvider engine{cfg};
        ASSERT_NE(engine.snapshot().engine, nullptr);
        LmSigner signer{engine};

        auto card = std::make_shared<TwoKeyCard>();
        SignParams params;
        params.certId = sha256Hex(card->signerCert);
        params.inputDocument = {'a', ' ', 'd', 'o', 'c', 'u', 'm', 'e', 'n', 't'};
        params.format = "cades";
        params.level = "b-b";
        params.packaging = "enveloped";

        const auto out = signer.sign(detachedSession(), params, CandidateList{card}, aPin, LibreSCRS::CancelToken{});

        EXPECT_EQ(out.status, SignOutcome::Status::Ok) << out.msgFallback;
        EXPECT_FALSE(out.signedDocumentBytes.empty());
        EXPECT_EQ(card->reads, 1) << "the certificates are read once per signature";
        EXPECT_EQ(card->signedWith, std::vector<std::uint16_t>{TwoKeyCard::kSignerKey});
    }
    fs::remove_all(dir);
}

// A certificate the card lists without a key handle names no key to sign with:
// not found, before any PIN is asked for or any key touched.
TEST(LmSeamsRouting, ACertificateWithoutAKeyHandleIsNotASigningKey)
{
    const std::vector<std::uint8_t> der{0x7A, 0x7B};
    CandidateList candidates{mkStub("plugin-no-key", {certWithoutKey(der)})};
    auto session = detachedSession();

    auto sel = selectSigningCandidate(candidates, sha256Hex(der), *session);
    ASSERT_FALSE(sel.has_value());
    EXPECT_EQ(sel.error(), SignOutcome::Status::KeyNotFound);
}

// --- LmCertificateReader::read (first-non-empty routing) ------------------

TEST(LmCertReaderRouting, FirstCandidateWithANonEmptyCertListWins)
{
    const std::vector<std::uint8_t> derA{0x01, 0x02};
    const std::vector<std::uint8_t> derB{0x03, 0x04};
    // First candidate is empty; the second has the certs.
    CandidateList candidates{
        mkStub("empty", {}),
        mkStub("has-certs", {certWithDer(derA), certWithDer(derB)}),
    };
    auto session = detachedSession();
    LibreSCRS::CancelSource source;

    auto outcome = LmCertificateReader{}.read(*session, candidates, source.token());
    EXPECT_EQ(outcome.status, CertReadOutcome::Status::Ok);
    ASSERT_EQ(outcome.certs.size(), 2u) << "the first non-empty candidate's certs are returned";
}

TEST(LmCertReaderRouting, AllEmptyCandidatesYieldOkWithNoCerts)
{
    CandidateList candidates{mkStub("empty-1", {}), mkStub("empty-2", {})};
    auto session = detachedSession();
    LibreSCRS::CancelSource source;

    auto outcome = LmCertificateReader{}.read(*session, candidates, source.token());
    EXPECT_EQ(outcome.status, CertReadOutcome::Status::Ok) << "all-empty is Ok-with-no-certs, not an error";
    EXPECT_TRUE(outcome.certs.empty());
}

// The read's throw does not cross CardPlugin::readCertificates: it arrives as
// an empty list, and the next candidate's certificates are the answer.
TEST(LmCertReaderRouting, ThrowingCandidateIsSkippedThenNextOwnerWins)
{
    const std::vector<std::uint8_t> der{0xAB, 0xCD};
    CandidateList candidates{
        mkStub("throws", {}, /*throwOnRead=*/true),
        mkStub("has-certs", {certWithDer(der)}),
    };
    auto session = detachedSession();
    LibreSCRS::CancelSource source;

    auto outcome = LmCertificateReader{}.read(*session, candidates, source.token());
    EXPECT_EQ(outcome.status, CertReadOutcome::Status::Ok);
    ASSERT_EQ(outcome.certs.size(), 1u) << "a throwing candidate is skipped, the next owner wins";
}

// --- mapSigningResultStatus (BatchSignFlow's halt-code seam) ---------------
//
// BatchSignFlow's own unit tests exercise a fake Signer and can only prove
// its OWN classification of SignOutcome::Status::AuthFailed/CardBlocked into
// the two halt codes (ErrorCode::CredentialWrong/CredentialBlocked) — they
// never invoke LmSigner, so they would silently miss a regression in HOW an
// LM SigningResult is classified into those two statuses in the first
// place. These two cases close that gap: LM's own PinVerificationFailed and
// CardBlocked statuses, constructed via their real named factories (no live
// card, no signing engine), must still reach the exact two SignOutcome
// values BatchSignFlow halts a batch on.

TEST(LmSeamsResultMapping, PinVerificationFailedMapsToTheStatusBatchSignFlowHaltsOn)
{
    const auto result = sign::SigningResult::pinVerificationFailed(LibreSCRS::Auth::ErrorKeys::genericComm());
    EXPECT_EQ(mapSigningResultStatus(result), SignOutcome::Status::AuthFailed);
}

TEST(LmSeamsResultMapping, CardBlockedMapsToTheStatusBatchSignFlowHaltsOn)
{
    const auto result = sign::SigningResult::cardBlocked(LibreSCRS::Auth::ErrorKeys::genericComm());
    EXPECT_EQ(mapSigningResultStatus(result), SignOutcome::Status::CardBlocked);
}

TEST(LmSeamsResultMapping, OkMapsToOk)
{
    const auto result = sign::SigningResult::okWithBytes({0x01, 0x02});
    EXPECT_EQ(mapSigningResultStatus(result), SignOutcome::Status::Ok);
}
