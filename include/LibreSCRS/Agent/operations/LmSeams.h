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

// Stateless credential router: holds no plugin. Each method iterates the
// passed candidates (already capability-filtered by the flow) on the SAME
// passed session — never opens a new one. list() returns the first candidate's
// non-empty getPINList (the active applet) together with that candidate's
// pluginId, so the flow can bind the produced snapshot to the listing plugin;
// a throwing candidate is skipped (read-only). The mutating entry points route
// a REAL Unsupported (the LM base default — the plugin did not implement the
// flow, so no card interaction happened) to the next candidate; ANY other
// outcome is final: a mutation is never retried across candidates, so a failed
// attempt cannot burn a second retry counter, and a throw maps to PluginError
// and stops routing (card state unknown). All-Unsupported (or no candidates)
// answers Unsupported — the valid outcome for a card that advertises no
// credential management. Mutation flows put the snapshot's listing plugin
// FIRST in the candidate order (prioritizeCandidate), so the plugin that
// minted the label namespace answers the mutation addressed against it.
class LmCredentialManager final : public CredentialManager
{
public:
    CredentialListing list(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates) override;
    LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                                           std::string_view pinLabel, const LibreSCRS::Secure::String& oldPin,
                                           const LibreSCRS::Secure::String& newPin) override;
    LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession& session,
                                                      const CandidateList& candidates, std::string_view pinLabel,
                                                      const LibreSCRS::Secure::String& transportValue,
                                                      const LibreSCRS::Secure::String& newPin) override;
    LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession& session,
                                                    const CandidateList& candidates,
                                                    const LibreSCRS::Secure::String& signPin) override;
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
// bridge on libresign's fixed dlopen text until LM exposes a typed key.
// Allocation-free and noexcept.
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
