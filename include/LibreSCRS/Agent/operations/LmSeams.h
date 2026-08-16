// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin {
class CardPluginService;
}

namespace LibreSCRS::Agent::Operations {

// Stateless identity router: holds no plugin. read() iterates the passed
// candidates (already identity-filtered by the flow) and returns the first that
// reports Ok — the active applet — else the last failure.
class LmCardReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                     LibreSCRS::CancelToken token, GroupReadCallback onGroup = {}) override;
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
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

// Resolve the MUTABLE plugin handles a deposit needs for @p candidates, matched
// by pluginId against the registry's PURE, no-card-I/O snapshot. Exposed for
// unit testing; also the compile-level restriction that keeps the deposit path
// honest — this function takes NO CardSession, so the registry's OTHER,
// session-taking candidate lookup is simply unreachable from it.
//
// Why that matters (the rule this seam exists to obey): inside an OPEN flow the
// session-taking lookup AID-probes every non-ATR-matching plugin. On a travel
// document that probe wipes the plugin's per-session credential store —
// destroying the very deposit being made — and emits plain APDUs that desync an
// established secure-messaging tunnel. The read path's candidate list carries
// const handles by discipline; the mutable ones come from the registry, so no
// const_cast is involved anywhere.
[[nodiscard]] std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>>
resolveDepositTargets(LibreSCRS::Plugin::CardPluginService& service, const CandidateList& candidates);

// Production CredentialDepositor: holds the SAME plugin registry the production
// candidate resolver wraps, and deposits the chosen MRZ trio into every
// candidate that can consume it (through the plugin's own session-credential
// keys, keyed per session by the plugin itself). Stateless beyond the registry
// reference; a candidate that throws is skipped, exactly like the other routers.
class LmCredentialDepositor final : public CredentialDepositor
{
public:
    explicit LmCredentialDepositor(LibreSCRS::Plugin::CardPluginService& service) : m_service(service) {}
    bool depositMrz(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                    const MrzParts& parts) override;

private:
    LibreSCRS::Plugin::CardPluginService& m_service;
};

class SigningEngineProvider;

// Production TrustVerifier: wraps LM's Trust::TrustStore, configured from
// ConfigStore's TslSources/TslCacheDir. Reuses the SigningEngineProvider's
// already-built TrustStoreService (SigningEngineProvider::trustSnapshot())
// rather than constructing a second trust store -- see that method's comment.
// No TSL source configured, or the trust store unavailable, answers
// TrustVerdict{OfflineUnverified, {"offline-unverified"}}; otherwise walks
// issuers up from the leaf via TrustStore::findIssuerOf (the card supplies
// only the leaf DER; LM's validateChain does not walk issuers itself --
// mirrors LibreCelik's own certificate-hierarchy chain walk) and validates the
// assembled chain, mapping LM's Trust::TrustStore::ChainStatus onto
// CertTrustStatus by an explicit switch (pinned ordinal alignment via
// static_assert in the .cpp).
class LmTrustVerifier final : public TrustVerifier
{
public:
    explicit LmTrustVerifier(SigningEngineProvider& engine) : m_engine(engine) {}
    TrustVerdict verify(std::span<const std::uint8_t> leafDer,
                        std::span<const std::vector<std::uint8_t>> chainDer) override;

private:
    SigningEngineProvider& m_engine;
};

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

// --- Card-independent visual-signature layout preview --------------------
//
// Manager1.LayoutVisualSignature / GetAppearanceFont are synchronous, pure-CPU
// calls with NO card and NO Operation object — the same request/reply round
// trip a client uses to render a PIXEL-PARITY preview of the visible-signature
// appearance a subsequent `Card1.Sign` would actually stamp. Both platform
// daemons (LibreLinux's D-Bus ManagerObject, LibreDarwin's SocketFrontend) call
// through these TWO free functions rather than each re-deriving the LM call
// itself, so the computation is defined exactly once (unlike the validation
// orchestration around `Sign`'s `visualSignature` option, which the two
// daemons still duplicate copy-paste style — a known, separately-tracked
// asymmetry this does not repeat).

// Mirrors LM's `Signing::Rect` field-for-field (PDF user units) without
// naming the LM type in this public header — the same seam-boundary
// invariant the file comment above states ("all LM Signing types stay inside
// LmSeams.cpp"). Caller validates via `SignatureParams::isValidLayoutRect`
// BEFORE calling `layoutVisualSignature` below; an invalid box is a
// method-entry rejection each daemon performs itself (mirrors `Sign`'s own
// `visualSignature` geometry gate), not something this function re-checks.
struct LayoutBox
{
    double x{0.0};
    double y{0.0};
    double width{0.0};
    double height{0.0};
};

// Mirrors LM's `Signing::VisualSignatureLayout` field-for-field (fontSize,
// lineHeight, lines, clipped) — see that header's own doc comment for the
// full word-wrap/clipping contract this pass-through inherits unchanged.
// `clipped == true` is pixel-parity load-bearing: it tells the caller to
// install the SAME clip path the PAdES emitter installs when it stamps the
// real signature, so a preview that omits it would silently diverge from the
// signed output.
struct VisualLayoutResult
{
    double fontSize{0.0};
    double lineHeight{0.0};
    std::vector<std::string> lines;
    bool clipped{false};
};

// The ONE production entry point every platform daemon calls through for
// `Manager1.LayoutVisualSignature`. Narrows @p box (already validated by the
// caller) to LM's integer `Rect` exactly like `buildSigningRequest` narrows
// `Sign`'s `visualSignature` option (`static_cast<int>(std::lround(...))`),
// then forwards @p textUtf8 verbatim to LM's own `layoutVisualSignature`.
[[nodiscard]] VisualLayoutResult layoutVisualSignature(std::string_view textUtf8, LayoutBox box);

// The embedded appearance font's raw bytes (Liberation Sans Regular TTF) —
// the ONE production entry point every platform daemon calls through for
// `Manager1.GetAppearanceFont`. Copies LM's `embeddedAppearanceFontData()`
// span into a caller-owned buffer (rather than returning the span itself) so
// this public header never names `std::span<const std::byte>` tied to an
// LM-owned static array across the seam boundary; each daemon seals/anonymises
// the returned bytes into its own reply fd (`SealedMemfd`/`anonFdFromBytes`).
// Non-empty, deterministic, and identical byte-for-byte on every call — LM's
// own contract for the underlying span.
[[nodiscard]] std::vector<std::uint8_t> appearanceFontBytes();

} // namespace LibreSCRS::Agent::Operations
