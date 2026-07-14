// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <memory>

namespace LibreSCRS::Agent::Operations {

// Stateless identity router: holds no plugin. read() iterates the passed
// candidates (already identity-filtered by the flow) and returns the first that
// reports Ok — the active applet — else the last failure.
class LmCardReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                     LibreSCRS::CancelToken token) override;
};

// Stateless cert router: holds no plugin. read() iterates the passed candidates
// (already PKI-filtered by the flow) and returns the first that yields a
// non-empty cert list — else the last status (empty == Ok-with-no-certs).
class LmCertificateReader final : public CertificateReader
{
public:
    CertReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                         LibreSCRS::CancelToken token) override;
};

class SigningEngineProvider;

// Production Signer: resolves certId against the live card (anti-TOCTOU DER
// re-assert), enforces the per-level expired-cert gate, then drives the
// in-process buffer-based SigningService::sign via the SigningEngineProvider
// snapshot. This is the ONLY agent TU that consumes the LM Signing surface;
// all LM Signing types stay inside LmSeams.cpp so the seam boundary holds.
// Stateless signing router: holds no plugin, only the engine provider. sign()
// iterates the passed candidates (PKI+PinManagement-filtered by the flow) and
// signs through the one that OWNS params.certId.
class LmSigner final : public Signer
{
public:
    explicit LmSigner(SigningEngineProvider& engine) : m_engine(engine) {}
    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session, const SignParams& params,
                     const CandidateList& candidates, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken token) override;

private:
    SigningEngineProvider& m_engine;
};

// Agent-side certificate parser, exposed for unit testing (a DER + card pairing
// -> CertSnapshot KAT). The production read path is LmCertificateReader::read;
// this is the same pure mapping it uses internally.
[[nodiscard]] CertSnapshot certSnapshotFromDer(const LibreSCRS::Plugin::CertificateData& cd);

// True when an LM SigningResult diagnostic indicates the signing engine could
// not LOAD its PKCS#11 security module (a deployment fault) — used to route
// such a failure to SignOutcome::Status::EngineUnavailable rather than the
// generic SigningEngineError. Exposed for unit testing; a pragmatic substring
// bridge on libresign's fixed dlopen text until LM exposes a typed key
// (BACKLOG item 72). Allocation-free and noexcept.
[[nodiscard]] bool signingDiagnosticIsModuleLoadFailure(const std::optional<std::string>& diagnosticDetail) noexcept;

// Result of resolving a signing request's certId against the present card: the
// candidate plugin that owns the cert and the exact CertificateData selected.
struct SigningSelection
{
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin;
    LibreSCRS::Plugin::CertificateData cert;
};

// Pure routing decision used by LmSigner::sign, exposed for unit testing. Walks
// @p candidates in order, re-reading each candidate's certs off the live
// @p session (anti-TOCTOU: the assertion is against the card present NOW), and
// returns the FIRST candidate that owns a cert whose sha256Hex(derBytes) equals
// @p certId. A candidate whose readCertificates throws is skipped (it cannot own
// the cert). Returns nullopt when no candidate owns @p certId. Null candidate
// entries are skipped. The re-read also (re)establishes the PACE channel for
// travel-document cards so the live session is registered for in-process
// adoption — hence the live session is required even though selection is "pure".
[[nodiscard]] std::optional<SigningSelection> selectSigningCandidate(const CandidateList& candidates,
                                                                     const std::string& certId,
                                                                     LibreSCRS::SmartCard::CardSession& session);

} // namespace LibreSCRS::Agent::Operations
