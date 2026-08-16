// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/cache/MrzPayload.h>             // MrzParts
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h> // PINResult
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// 3. CardReader — drives the plugin read entry-point and converts the
//    LM result into a CardReadSnapshot. Production: LmCardReader.
struct ReadOutcome
{
    enum class Status { Ok, AuthFailed, ParseError, UnsupportedCard, CommunicationError, Cancelled };
    Status status{Status::CommunicationError};
    std::optional<CardReadSnapshot> snapshot;
    std::string msgFallback;
};
// Forwarded from IdentityReadFlow to CardReader::read: fires once per group,
// in read order, as the underlying plugin produces it — the agent-side
// GroupSnapshot one level up the seam boundary from LM's own
// CardPlugin::GroupCallback, which this wraps. Empty (default) means no
// streaming: the reader then behaves exactly as it always has, returning the
// full snapshot at once inside ReadOutcome.
using GroupReadCallback = std::function<void(const GroupSnapshot&)>;

class CardReader
{
public:
    virtual ~CardReader() = default;
    // candidates: the capability-filtered, priority-ordered plugin list for this
    // operation (identity readers). The reader routes across them with lazy
    // fallback on the SAME passed session — never opens a new one. onGroup, when
    // non-empty, is forwarded into the underlying plugin's own streaming
    // callback (see GroupReadCallback) so a caller gets progressive delivery
    // ahead of the ReadOutcome this still returns in full at the end.
    [[nodiscard]] virtual ReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                                           LibreSCRS::CancelToken token, GroupReadCallback onGroup = {}) = 0;

    // Lightweight token-info read, sibling to read() exactly as
    // CardPlugin::readTokenInfo is a sibling of CardPlugin::readCard: routes
    // across @p candidates (already PKI-filtered by the flow) on the SAME
    // passed session, returning the first candidate's non-empty group — the
    // active applet. A plugin that does not implement it (the LM base
    // default) or that found nothing answers an EMPTY group (a normalized
    // GroupSnapshot with groupKey "token" and zero fields): a VALID,
    // successful outcome, never an error — production LmCardReader never
    // fails this call once a session is open (spec's empty-group
    // resilience). Kept hermetic like read(): no LM types cross this
    // boundary.
    [[nodiscard]] virtual GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession& session,
                                                      const CandidateList& candidates,
                                                      LibreSCRS::CancelToken token) = 0;
};

// 3b. CertificateReader — reads the card's certificates and parses them
//     agent-side into CertSnapshots (no DER on the wire). Production:
//     LmCertificateReader wraps CardPlugin::readCertificates + ParsedCertificate.
//     CardPlugin::readCertificates has no CancelToken, so the token is a
//     pre-dispatch best-effort check only (checked before the read; the read
//     itself is not cancellable mid-call).
struct CertReadOutcome
{
    enum class Status { Ok, AuthFailed, ParseError, UnsupportedCard, CommunicationError, Cancelled };
    Status status{Status::CommunicationError};
    std::vector<CertSnapshot> certs;
    std::string msgFallback;
    // Agent-internal only, index-aligned with `certs` (never the wire: no DER
    // crosses the wire). Threads each cert's DER forward from the plugin read
    // so CertReadFlow can feed it to the TrustVerifier seam without
    // re-opening the card or re-reading certificates. Empty when `certs` is
    // empty; a producer that pushes to `certs` pushes the matching DER here
    // in the SAME step so the two vectors never drift apart. Declared LAST so
    // existing 3-positional-arg brace-inits (status, certs, msgFallback) keep
    // compiling with this defaulted to empty.
    std::vector<std::vector<std::uint8_t>> derBytes;
};
class CertificateReader
{
public:
    virtual ~CertificateReader() = default;
    // candidates: the capability-filtered, priority-ordered PKI plugin list. The
    // reader routes across them with lazy fallback on the SAME passed session.
    [[nodiscard]] virtual CertReadOutcome read(LibreSCRS::SmartCard::CardSession& session,
                                               const CandidateList& candidates, LibreSCRS::CancelToken token) = 0;
};

// 3b'. TrustVerifier — computes the chain/trust verdict for one certificate,
//      given its leaf DER and (when known) any additional chain DER to
//      present alongside it. Kept as its own seam (rather than folded into
//      CertificateReader) so CertReadFlow can drive it per-cert with a fake in
//      unit tests, independent of the card-plugin routing. Production:
//      LmTrustVerifier wraps LM's Trust::TrustStore, configured from
//      ConfigStore's TslSources/TslCacheDir (via the SigningEngineProvider's
//      already-built TrustStoreService -- no separate trust-store instance,
//      no new LM API).
struct TrustVerdict
{
    CertTrustStatus status{CertTrustStatus::Unknown};
    // Closed-vocabulary tokens mirroring `status` -- see CertSnapshot.h's
    // CertTrustStatus comment. Mutually exclusive today (a chain has exactly
    // one verdict), but kept as a vector for forward-compatible orthogonal
    // conditions (e.g. a future revocation-aware verdict alongside an
    // expiry-aware one).
    std::vector<std::string> securityStatus;
};
class TrustVerifier
{
public:
    virtual ~TrustVerifier() = default;
    // leafDer: the certificate under evaluation. chainDer: any additional
    // certificate DER to present alongside it (currently always empty from
    // CertReadFlow -- the on-card chain ladder is not walked yet; see
    // CertSnapshot::chainSubjectCns). Never throws and never fails the read:
    // an unreachable/unconfigured trust source answers
    // TrustVerdict{OfflineUnverified, {"offline-unverified"}}, never an error
    // -- certificate trust is advisory metadata, not a blocking precondition
    // for serving the parsed certificate.
    [[nodiscard]] virtual TrustVerdict verify(std::span<const std::uint8_t> leafDer,
                                              std::span<const std::vector<std::uint8_t>> chainDer) = 0;
};

// 3c. Signer — produces an AdES signature over an in-memory document using a
//     key on the live card session, keeping SignFlow free of LM Signing types.
//     Production: LmSigner wraps the buffer-based SigningService::sign (driven
//     via the SigningEngineProvider snapshot); Fake* for tests.
//
//     The session is taken as a shared_ptr because the in-process signing path
//     adopts the live session through SessionPresence (a weak_ptr resolved
//     inside SigningService::sign): the agent's shared owner must outlive the
//     call so PACE-established secure messaging is reused, never re-established.

// A per-request PAdES visual-signature appearance override, hermetic (no LM
// Signing types): mapped onto LM's `VisualSignatureParams::Builder`
// (pageIndex/rect/textTemplate) inside LmSigner. page/x/y/width/height mirror
// the wire's `visualSignature` nested map field-for-field (page 0-based;
// x/y/width/height in PDF user units, float on the wire, narrowed to LM's
// integer `Rect` inside LmSigner). Entry validation (method-entry, before a
// SignParams is even constructed) enforces format==pades and a positive
// width/height — this struct itself carries no further invariant.
struct VisualParams
{
    int page{0};
    float x{0.0F};
    float y{0.0F};
    float width{0.0F};
    float height{0.0F};
    std::string text;
};

struct SignParams
{
    std::string certId;                      // opaque SHA-256(DER); selects the exact cert
    std::vector<std::uint8_t> inputDocument; // the bytes to sign (already read off the input fd)
    // Resolved (concrete) vocabulary as lower-case wire strings, mapped to the
    // LM Signing enums inside LmSigner so this header stays LM-Signing-free.
    // format: pades|cades|xades|jades|asice. level: b-b|b-t|b-lt|b-lta.
    // packaging: enveloped|detached.
    std::string format;
    std::string level;
    std::string packaging;
    bool allowExpired{false}; // B-B only; ignored for the timestamped/LT family
    std::string displayName;  // client-supplied chrome — never trusted
    std::string reason;
    std::string location;
    // Per-request TSA override (https-only, validated at method entry before
    // this struct is built): empty means "use the agent's configured
    // TsaUrls default" (the engine's own bound provider); non-empty is
    // forwarded to LM as a `staticTsa` override inside LmSigner, taking
    // priority for exactly this one sign. Meaningful only for the
    // timestamped/long-term family (b-t/b-lt/b-lta) — entry validation
    // rejects a tsaUrl paired with level "b-b" rather than silently
    // ignoring it.
    std::string tsaUrl;
    // Per-request PAdES visual-signature appearance; absent means invisible
    // (the pre-existing default). Entry validation rejects a populated
    // `visual` on any format other than "pades".
    std::optional<VisualParams> visual;
};

struct SignOutcome
{
    enum class Status {
        Ok,
        KeyNotFound,
        KeyAmbiguous,
        CertExpiredBlocked,
        ChainIncomplete,
        TsaUnreachable,
        AuthFailed,
        CardBlocked,
        CommunicationError,
        Cancelled,
        SigningEngineError,
        EngineUnavailable, // engine/security module could not load (deployment)
        InvalidDocument,   // the document to sign is invalid/unreadable (client input)
    };
    Status status{Status::CommunicationError};
    std::vector<std::uint8_t> signedDocumentBytes; // the finished AdES artifact (empty unless Ok)
    std::string resolvedFormat;                    // echoed back for Sign1.meta
    std::string resolvedLevel;
    bool tsaUsed{false};
    bool chainComplete{false};
    std::string msgFallback;
};

class Signer
{
public:
    virtual ~Signer() = default;
    // candidates: the capability-filtered (PKI+PinManagement), priority-ordered
    // plugin list. The signer picks the candidate that OWNS params.certId and
    // signs through it, all on the SAME passed session.
    [[nodiscard]] virtual SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>& session,
                                           const SignParams& params, const CandidateList& candidates,
                                           LibreSCRS::Auth::CredentialProvider credentials,
                                           LibreSCRS::CancelToken token) = 0;
};

// 3d. CredentialManager — drives the plugin PIN-credential lifecycle entry
//     points on the live session: per-PIN status, PIN change, transport-PIN
//     activation, signing-key activation. One virtual per CardPlugin entry
//     point; signatures mirror the LM virtuals (secrets are cleansing
//     Secure::Strings — pinned by the LM's own static_asserts — never
//     std::string copies). The session comes from the flow's
//     CardSessionHolder exactly like the cert seam; candidates are the
//     capability-filtered, priority-ordered plugin list for this card, routed
//     on the SAME passed session — never a new one. A card whose plugins
//     advertise no credential management answers with the Unsupported
//     outcome: a VALID result, not an entry error. Production:
//     LmCredentialManager; Fake* for tests.

// Result of CredentialManager::list: the entries of the first candidate that
// reported a non-empty getPINList, plus that candidate's plugin identity
// (CardPlugin::pluginId). `pluginId` is empty iff no candidate produced
// entries. The list flow binds the produced snapshot to this identity so a
// later mutation is routed to the SAME plugin first — the listing plugin owns
// the label namespace the mutation addresses, so another candidate must not
// intercept a mutation for a card it listed nothing for.
struct CredentialListing
{
    std::vector<LibreSCRS::Plugin::PinStatusEntry> entries;
    std::string pluginId;
};

class CredentialManager
{
public:
    virtual ~CredentialManager() = default;
    // -> CardPlugin::getPINList: per-PIN status for all PINs the card exposes,
    //    bound to the identity of the candidate that produced them.
    [[nodiscard]] virtual CredentialListing list(LibreSCRS::SmartCard::CardSession& session,
                                                 const CandidateList& candidates) = 0;
    // -> CardPlugin::changePIN: change the PIN selected by pinLabel (labels
    //    come from list(); they are not secret material).
    [[nodiscard]] virtual LibreSCRS::Plugin::PINResult
    changePIN(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates, std::string_view pinLabel,
              const LibreSCRS::Secure::String& oldPin, const LibreSCRS::Secure::String& newPin) = 0;
    // -> CardPlugin::activateTransportPin: set the holder's PIN from the
    //    issuance transport value.
    [[nodiscard]] virtual LibreSCRS::Plugin::PINResult
    activateTransportPin(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                         std::string_view pinLabel, const LibreSCRS::Secure::String& transportValue,
                         const LibreSCRS::Secure::String& newPin) = 0;
    // -> CardPlugin::activateSigningKey: VERIFY the operational SIGN PIN and
    //    perform the key ACTIVATE within one locked session.
    [[nodiscard]] virtual LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession& session,
                                                                          const CandidateList& candidates,
                                                                          const LibreSCRS::Secure::String& signPin) = 0;
};

// 3e. CredentialDepositor — deposits a user-chosen MRZ into every candidate
//     plugin that can consume it, through the plugin's own session-credential
//     keys, so the NEXT read on the SAME session resolves an MRZ-keyed
//     activation profile with zero changes to the LM activation walk.
//     Production: LmCredentialDepositor; Fake* / NullCredentialDepositor for
//     tests and wiring sites with no plugin registry.
class CredentialDepositor
{
public:
    virtual ~CredentialDepositor() = default;
    // @p parts is the parsed canonical MRZ payload; the plugin-facing keys take
    // the check-digit-STRIPPED trio (documentNumber / dateOfBirth /
    // dateOfExpiry), which the plugin re-pads and re-derives the MRZ
    // information from. @p candidates is the flow's identity-filtered list.
    // @return true iff at least one candidate accepted a deposit attempt.
    virtual bool depositMrz(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
                            const MrzParts& parts) = 0;
};

// Ready-made no-op depositor: accepts nothing. Wired by callers that have no
// plugin registry to resolve deposit targets from (bus-level tests, harnesses
// that never renegotiate), exactly as NullGroupSink is wired by callers with no
// Group signal to emit — the flow's reference stays well-formed and the
// renegotiation simply deposits nothing.
class NullCredentialDepositor final : public CredentialDepositor
{
public:
    bool depositMrz(LibreSCRS::SmartCard::CardSession&, const CandidateList&, const MrzParts&) override
    {
        return false;
    }
};

// 4. PrompterClientBase lives in its own header, so the split keeps the include
//    graph clean (Seams.h pulls a lot of LM headers, PrompterClientBase.h
//    pulls only PromptTypes.h).

// 5. OperationPhaseSink — receives wire-stable Phase integers as the flow
//    transitions through the wire-stable state machine. Production
//    instance is OperationBase (the Operation that hosts the flow); tests
//    use a recording fake to assert ordering.
class OperationPhaseSink
{
public:
    virtual ~OperationPhaseSink() = default;
    // Phase values match the OperationBase Phase enum on the wire.
    virtual void setPhase(std::uint32_t phase) noexcept = 0;
};

// 6. GroupSink — receives each field group, in read order, as
//    IdentityReadFlow produces it via the CardReader::read onGroup callback
//    above — progressive delivery strictly ahead of the flow's own one-shot
//    Result, which stays unchanged and remains the authoritative complete
//    set. Production instance: the hosting Operation (OperationBase
//    implements this by forwarding to its OperationChannel's emitGroup, the
//    same one-hop pattern setPhase already uses for OperationPhaseSink).
//    Tests use a recording fake to assert order.
class GroupSink
{
public:
    virtual ~GroupSink() = default;
    virtual void groupReady(const GroupSnapshot& group) noexcept = 0;
};

// Ready-made no-op GroupSink. GetPhotoOperation (both platform daemons) wires
// this INSTEAD of its own OperationBase (`*this`) even though a cache-miss
// GetPhoto also runs IdentityReadFlow: that operation's object exports
// Photo1, not Identity1, so it has no Group signal to emit at all — the gate
// against streaming into the wrong result interface lives at THIS wiring
// site (which sink a caller passes), never inside the flow or the channel.
// Tests with no group-observing path to drive use it too, exactly like
// IdentityReadFlowDeps::onCardType's default no-op.
class NullGroupSink final : public GroupSink
{
public:
    void groupReady(const GroupSnapshot&) noexcept override {}
};

} // namespace LibreSCRS::Agent::Operations
