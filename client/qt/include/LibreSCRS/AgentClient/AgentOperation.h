// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/CallError.h>
#include <LibreSCRS/AgentClient/CredentialTypes.h>
#include <LibreSCRS/AgentClient/ErrorCode.h>
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/OperationPhase.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <memory>
#include <vector>

/// @file
/// @brief Drives one agent operation and its typed result, handling the
///        Finished/Result race and the late-subscriber result recovery
///        contract behind a transport-neutral surface.

namespace LibreSCRS::AgentClient {

class AgentCard;
class AgentClient;
class TransportSeam;
struct SeamError;

/// @brief One in-flight (or finished) agent operation, minted by an
///        `AgentCard` method or by `AgentClient::certificateDer()`.
///
/// Lifecycle: the minting call returns immediately; progress arrives via
/// `phaseChanged` and the terminal outcome via `finished()`. After `finished()`
/// the polled state (`status()` / `errorCode()` / `callError()`) and the typed
/// result getter matching the minting method are valid. The operation is
/// QObject-parented to the object that minted it, so it never outlives its
/// card/client; consumers that finish with it early may delete it sooner.
///
/// The lifted behavior this preserves: results are settled BEFORE `finished()`
/// fires (a lost/raced one-shot result signal is recovered from the agent's
/// retained payload where the contract provides one, and an unrecoverable
/// lost result surfaces as a loud CommunicationError instead of masquerading
/// as a silent empty success).
class LIBRESCRS_AGENTCLIENT_EXPORT AgentOperation : public QObject
{
    Q_OBJECT
public:
    ~AgentOperation() override;

    AgentOperation(const AgentOperation&) = delete;
    AgentOperation& operator=(const AgentOperation&) = delete;

    /// @brief Request cancellation. Fire-and-forget: the terminal outcome
    ///        still arrives via `finished()` (normally with a Cancelled
    ///        status), never synchronously here.
    void cancel();

    /// @brief True once the terminal outcome was observed (or recovered).
    [[nodiscard]] bool isFinished() const;
    /// @brief Terminal status; valid after `finished()` (Error before).
    [[nodiscard]] OperationStatus status() const;
    /// @brief Last observed phase (Created until the agent reports progress).
    [[nodiscard]] OperationPhase phase() const;
    /// @brief Last observed progress in [0.0, 1.0] (0.0 until reported).
    [[nodiscard]] double progress() const;

    /// @brief The agent's wire-frozen error taxonomy value for a failed
    ///        operation; None on success or when the failure never produced a
    ///        wire-level answer (see `callError()`).
    [[nodiscard]] ErrorCode errorCode() const;
    /// @brief The client-side call classification when the operation failed
    ///        WITHOUT a wire-level answer (agent unreachable, timeout,
    ///        transport break, request rejected at entry); None otherwise.
    [[nodiscard]] CallError callError() const;
    /// @brief Agent-authored i18n message key for the terminal outcome, or
    ///        empty (recovered terminals carry no message — map `errorCode()`).
    [[nodiscard]] QString messageKey() const;
    /// @brief Agent-authored English fallback message, or empty.
    [[nodiscard]] QString messageFallback() const;

    /// @brief Identity payload of a `readIdentity()` operation; each Field
    ///        carries its wire metadata in `Field::extra` (see IdentityRows.h
    ///        for the canonical keys). Empty otherwise.
    [[nodiscard]] QList<FieldGroup> identityResult() const;
    /// @brief Certificate payload of a `readCertificates()` operation.
    [[nodiscard]] QList<CertificateInfo> certificatesResult() const;
    /// @brief Photo payload of a `getPhoto()` operation — move-only sealed-fd
    ///        items the caller must read and close promptly (the agent retains
    ///        no copy). First call takes ownership; later calls return empty.
    [[nodiscard]] std::vector<PhotoItem> takePhotos();
    /// @brief Signed artifact of a `sign()` operation — a move-only sealed fd
    ///        the caller must stream out and close promptly. First call takes
    ///        ownership; later calls return an invalid handle.
    [[nodiscard]] FdHandle takeSignedArtifact();
    /// @brief Signature metadata of a `sign()` operation (format/level/...).
    [[nodiscard]] QVariantMap signMeta() const;
    /// @brief Mutation result of a `managePin()` / `activateSigningKey()`
    ///        attempt. Delivered for EVERY completed attempt — including the
    ///        soft-fail outcomes that finish Error — so `PinResult::outcome`
    ///        is meaningful even when `status()` is Error.
    [[nodiscard]] PinResult pinResult() const;
    /// @brief Records of a `listCredentials()` operation. Empty for a
    ///        mutation — an empty list is a legitimate result, not a missing
    ///        one.
    [[nodiscard]] CredentialList credentialsResult() const;
    /// @brief Raw DER of an `AgentClient::certificateDer()` operation.
    [[nodiscard]] QByteArray certificateDerResult() const;

Q_SIGNALS:
    void phaseChanged(LibreSCRS::AgentClient::OperationPhase phase, double progress);
    /// @brief The single terminal notification; fires exactly once. Poll
    ///        `status()` / `errorCode()` / `callError()` and the typed result
    ///        getters after it.
    void finished();

private:
    friend class AgentCard;   // mints card operations; entry-refusal terminals
    friend class AgentClient; // mints DER operations; agent-vanish/card-removed sweeps

    /// Internal operation kind — which typed result this operation binds.
    enum class Kind : unsigned char { Identity, Photo, Certificates, Sign, Credentials, CertificateDer };

    /// Transport-backed ctor: subscribes to the operation's signals and runs
    /// the lost-Finished recovery before returning.
    AgentOperation(TransportSeam* transport, const QString& operationId, Kind kind, QObject* parent);
    /// Local ctor (no agent-side operation object): an entry-refused call or a
    /// client-driven fetch (certificateDer). Starts unfinished and untracked.
    AgentOperation(Kind kind, QObject* parent);

    /// @brief Force a terminal outcome WITHOUT touching the transport, firing
    ///        `finished` once if it has not already fired. The AgentClient
    ///        calls this on every live operation when the agent vanishes or
    ///        the card is removed mid-flight — no terminal signal will ever
    ///        arrive, so without this sweep the consumer would hang forever.
    ///        Idempotent (a no-op once finished).
    void terminate(OperationStatus terminalStatus, ErrorCode code, CallError call, const QString& msgKey,
                   const QString& msgFallback);
    /// @brief Apply an entry-refusal / local-call failure as the terminal
    ///        outcome, QUEUING the `finished` emit so a consumer connecting
    ///        right after the minting call still receives it.
    void failEntry(const SeamError& error);
    /// @brief Issue the asynchronous DER fetch this operation reports on.
    void startCertificateDer(TransportSeam* transport, const QString& readerId, const QString& certId);

    /// @brief Resolve a terminal (status, errorCode) into the public
    ///        `finished()`. On a terminal with no result yet seen: recovers
    ///        the typed payload via the transport's recovery pull, or — when
    ///        the pull yields nothing usable — surfaces a loud
    ///        CommunicationError so a lost/late result never masquerades as a
    ///        silent empty success.
    void finalizeTerminal(OperationStatus terminalStatus, ErrorCode code, const QString& msgKey,
                          const QString& msgFallback);
    void emitFinishedOnce(OperationStatus terminalStatus, ErrorCode code, CallError call, const QString& msgKey,
                          const QString& msgFallback);
    void recoverIfAlreadyFinished();

    struct Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
