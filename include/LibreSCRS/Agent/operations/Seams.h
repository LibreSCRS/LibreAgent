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
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
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
