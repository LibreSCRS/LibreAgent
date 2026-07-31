// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/SignOptions.h>

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <memory>
#include <vector>

/// @file
/// @brief Typed live proxy for one agent-exported card, minting
///        `AgentOperation` objects for its asynchronous methods.

namespace LibreSCRS::AgentClient {

class AgentClient;
struct OperationRequest;

/// @brief Live proxy for one card the agent exports. Tracks the card's
///        capability set / pre-read-auth requirement / owning reader live;
///        the operation-minting methods start an agent operation and return
///        an `AgentOperation` bound to the matching typed result. Every
///        returned operation is non-null and parented to this card; a call
///        the agent refuses at entry (e.g. a missing capability) returns an
///        operation that finishes immediately with the mapped
///        `callError()` / `errorCode()`.
class LIBRESCRS_AGENTCLIENT_EXPORT AgentCard : public QObject
{
    Q_OBJECT
public:
    ~AgentCard() override;

    AgentCard(const AgentCard&) = delete;
    AgentCard& operator=(const AgentCard&) = delete;

    /// @brief Opaque card id — a cross-wire token; compare and pass back
    ///        as-is, never parse.
    [[nodiscard]] QString id() const;
    /// @brief Opaque id of the reader holding this card.
    [[nodiscard]] QString readerId() const;
    /// @brief The card's capability tokens (see AgentCapabilities.h for the
    ///        vocabulary and the `capabilityBits()` bridge to the pure
    ///        `uiStateFor()` / `resolveCardState()` resolvers).
    [[nodiscard]] QStringList capabilities() const;
    /// @brief The verbatim pre-read-auth wire token ("None" / "Can" /
    ///        "Mrz"), forwarded as-is for consumers that re-emit it;
    ///        decode via `preReadAuthFromToken()` (AgentCapabilities.h).
    [[nodiscard]] QString preReadAuth() const;
    /// @brief The card's type identifier — the SAME string GUI plugin
    ///        dispatch keys on (`CardData::cardType`). Empty until known: a
    ///        multi-candidate card stays empty until a read resolves it
    ///        authoritatively (see `cardTypeChanged()`); an unambiguous
    ///        single-candidate card may already carry it at insertion.
    [[nodiscard]] QString cardType() const;
    /// @brief The card's full ATR as uppercase hex, no separators. Known
    ///        from insertion onward; never changes for the card's lifetime.
    ///        Empty only against an agent predating this surface.
    [[nodiscard]] QString atrHex() const;

    /// @brief Start an identity read (typed result: `identityResult()`).
    [[nodiscard]] AgentOperation* readIdentity();
    /// @brief Start a photo fetch (typed result: `takePhotos()`). Gates on
    ///        the IdentityData capability agent-side.
    [[nodiscard]] AgentOperation* getPhoto();
    /// @brief Start a certificate read (typed result: `certificatesResult()`).
    [[nodiscard]] AgentOperation* readCertificates();
    /// @brief Start a lightweight token-info read (typed result: the SAME
    ///        `identityResult()` accessor `readIdentity()` uses — a single
    ///        "token" group with `label`/`serial_number`/`manufacturer`
    ///        fields; a plugin that does not support token info answers a
    ///        present-but-empty group, a SUCCESS, never an error). Gated on
    ///        the PKI capability agent-side, and locally (transport-neutral,
    ///        never reaching the wire) on the agent's `"token-info"` feature
    ///        token: an old agent predating this surface refuses entry with
    ///        `ErrorCode::CapabilityMissing`, identically on both transports.
    [[nodiscard]] AgentOperation* readTokenInfo();
    /// @brief Start signing @p document with the key behind @p certId (typed
    ///        results: `takeSignedArtifact()` + `signMeta()`). @p options
    ///        selects format/level/packaging; the enum vocabulary is encoded
    ///        to the wire internally.
    [[nodiscard]] AgentOperation* sign(const QString& certId, FdHandle document, const SignOptions& options);
    /// @brief Start signing EACH of @p docs with the key behind @p certId,
    ///        under ONE consent + credential prompt for the whole batch
    ///        (typed result: `takeBatchResults()`); a wrong/blocked
    ///        credential halts the remaining documents rather than
    ///        re-prompting per file. @p options selects format/level/
    ///        packaging shared by every document in the batch, exactly like
    ///        `sign()`'s own @p options.
    ///
    ///        Entry gates (transport-neutral, never reaching the wire):
    ///          - @p docs.size() outside [`kMinBatchDocuments`,
    ///            `kMaxBatchDocuments`] (SignOptions.h) refuses with
    ///            `CallError::InvalidArguments`;
    ///          - the agent's `"batch-sign"` feature token absent refuses
    ///            with `ErrorCode::CapabilityMissing`, identically to
    ///            `readTokenInfo()`'s gate;
    ///          - @p options carrying `tsaUrl`/`visualSignature` without the
    ///            matching `"tsa-url"`/`"visual-sign"` token refuses the
    ///            SAME way `sign()`'s own gate does.
    [[nodiscard]] AgentOperation* signBatch(const QString& certId, std::vector<BatchDocument> docs,
                                            const SignOptions& options);
    /// @brief Start a credential listing (typed result: `credentialsResult()`).
    [[nodiscard]] AgentOperation* listCredentials();
    /// @brief Start a PIN mutation on the credential @p pinId (from the most
    ///        recent listing of this card); typed result: `pinResult()`.
    ///
    ///        @p options carries the wire's only structural mutation option,
    ///        `activateKey` (see `ManagePinOptions`'s doc comment for the
    ///        closed vocabulary and why it has no `extra` pass-through). It
    ///        is sent ONLY alongside `PinVerb::ActivatePin`; every other verb
    ///        sends no options at all, regardless of @p options' value.
    [[nodiscard]] AgentOperation* managePin(const QString& pinId, PinVerb verb, const ManagePinOptions& options = {});
    /// @brief Start activating the pending signing key (typed result:
    ///        `pinResult()`).
    [[nodiscard]] AgentOperation* activateSigningKey();

Q_SIGNALS:
    /// @brief A tracked card property changed (capabilities, pre-read auth,
    ///        owning reader).
    void changed();
    /// @brief `cardType()` specifically flipped (typically empty -> known,
    ///        once a read resolves it authoritatively). Fired IN ADDITION to
    ///        `changed()`, never instead of it, so an existing generic
    ///        consumer keeps working unmodified.
    void cardTypeChanged();

private:
    friend class AgentClient; // constructs/primes registry entries

    AgentCard(TransportSeam* transport, const QString& id, QObject* parent);

    /// @brief Seed properties from a discovery snapshot map.
    void primeFrom(const QVariantMap& card1Props);

    /// @brief The one shared minting path behind every operation method: a
    ///        refused entry never returns nullptr — it mints an operation
    ///        that terminalizes with the mapped failure.
    [[nodiscard]] AgentOperation* startOperation(OperationRequest request);

    struct Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
