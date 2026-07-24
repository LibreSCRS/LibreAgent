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
    /// @brief The verbatim pre-read-auth wire token ("None" / "PaceCan" /
    ///        "BacMrz"), forwarded as-is for consumers that re-emit it;
    ///        decode via `preReadAuthFromToken()` (AgentCapabilities.h).
    [[nodiscard]] QString preReadAuth() const;

    /// @brief Start an identity read (typed result: `identityResult()`).
    [[nodiscard]] AgentOperation* readIdentity();
    /// @brief Start a photo fetch (typed result: `takePhotos()`). Gates on
    ///        the IdentityData capability agent-side.
    [[nodiscard]] AgentOperation* getPhoto();
    /// @brief Start a certificate read (typed result: `certificatesResult()`).
    [[nodiscard]] AgentOperation* readCertificates();
    /// @brief Start signing @p document with the key behind @p certId (typed
    ///        results: `takeSignedArtifact()` + `signMeta()`). @p options
    ///        selects format/level/packaging; the enum vocabulary is encoded
    ///        to the wire internally.
    [[nodiscard]] AgentOperation* sign(const QString& certId, FdHandle document, const SignOptions& options);
    /// @brief Start a credential listing (typed result: `credentialsResult()`).
    [[nodiscard]] AgentOperation* listCredentials();
    /// @brief Start a PIN mutation on the credential @p pinId (from the most
    ///        recent listing of this card); typed result: `pinResult()`.
    [[nodiscard]] AgentOperation* managePin(const QString& pinId, PinVerb verb);
    /// @brief Start activating the pending signing key (typed result:
    ///        `pinResult()`).
    [[nodiscard]] AgentOperation* activateSigningKey();

Q_SIGNALS:
    /// @brief A tracked card property changed (capabilities, pre-read auth,
    ///        owning reader).
    void changed();

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
