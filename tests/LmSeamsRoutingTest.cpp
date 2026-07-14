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
#include <LibreSCRS/Agent/util/Sha256Hex.h> // sha256Hex (certId)
#include <LibreSCRS/Agent/operations/LmSeams.h>

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// Stub CardPlugin whose readCertificates returns a canned list (or throws). The
// rest of the CardPlugin surface is unused by the routing decisions under test.
class CertStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    CertStubPlugin(std::string id, std::vector<LibreSCRS::Plugin::CertificateData> certs, bool throwOnRead = false)
        : m_certs(std::move(certs)), m_throw(throwOnRead)
    {
        setIdentity(std::move(id), "stub", 0);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI | LibreSCRS::Plugin::CardCapabilities::PinManagement;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    std::vector<LibreSCRS::Plugin::CertificateData> readCertificates(LibreSCRS::SmartCard::CardSession&) const override
    {
        if (m_throw) {
            throw std::runtime_error{"stub: readCertificates failed"};
        }
        return m_certs;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    std::vector<LibreSCRS::Plugin::CertificateData> m_certs;
    bool m_throw;
};

LibreSCRS::Plugin::CertificateData certWithDer(std::vector<std::uint8_t> der)
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
    return LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
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

    // First candidate throws on readCertificates; the owner is the second.
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
    EXPECT_FALSE(sel.has_value()) << "unowned certId maps to KeyNotFound upstream";
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

// --- signingDiagnosticIsModuleLoadFailure (item 72: EngineUnavailable bridge) -

TEST(LmSeamsDiagnostic, NulloptIsNotAModuleLoadFailure)
{
    EXPECT_FALSE(signingDiagnosticIsModuleLoadFailure(std::nullopt));
}

TEST(LmSeamsDiagnostic, DlopenBareNameFailureIsDetected)
{
    EXPECT_TRUE(signingDiagnosticIsModuleLoadFailure(
        std::optional<std::string>{"Cannot load PKCS#11 module: librescrs-pkcs11.so: cannot open shared object file"}));
}

TEST(LmSeamsDiagnostic, EitherMarkerAloneMatches)
{
    EXPECT_TRUE(signingDiagnosticIsModuleLoadFailure(std::optional<std::string>{"... PKCS#11 module ..."}));
    EXPECT_TRUE(signingDiagnosticIsModuleLoadFailure(std::optional<std::string>{"foo: cannot open shared object x"}));
}

TEST(LmSeamsDiagnostic, UnrelatedEngineErrorIsNotAModuleLoadFailure)
{
    EXPECT_FALSE(signingDiagnosticIsModuleLoadFailure(std::optional<std::string>{"TSA responded with HTTP 500"}));
    EXPECT_FALSE(signingDiagnosticIsModuleLoadFailure(std::optional<std::string>{""}));
}
