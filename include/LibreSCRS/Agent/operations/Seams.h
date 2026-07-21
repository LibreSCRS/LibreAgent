// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
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
#include <memory>
#include <optional>
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
class CardReader
{
public:
    virtual ~CardReader() = default;
    // candidates: the capability-filtered, priority-ordered plugin list for this
    // operation (identity readers). The reader routes across them with lazy
    // fallback on the SAME passed session — never opens a new one.
    [[nodiscard]] virtual ReadOutcome read(LibreSCRS::SmartCard::CardSession& session, const CandidateList& candidates,
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

// 3c. Signer — produces an AdES signature over an in-memory document using a
//     key on the live card session, keeping SignFlow free of LM Signing types.
//     Production: LmSigner wraps the buffer-based SigningService::sign (driven
//     via the SigningEngineProvider snapshot); Fake* for tests.
//
//     The session is taken as a shared_ptr because the in-process signing path
//     adopts the live session through SessionPresence (a weak_ptr resolved
//     inside SigningService::sign): the agent's shared owner must outlive the
//     call so PACE-established secure messaging is reused, never re-established.
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

} // namespace LibreSCRS::Agent::Operations
