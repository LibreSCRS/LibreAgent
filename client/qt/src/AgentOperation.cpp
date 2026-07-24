// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentOperation.h>

#include "TransportSeam.h"

#include <QLoggingCategory>
#include <QMetaObject>

namespace LibreSCRS::AgentClient {

namespace {
Q_LOGGING_CATEGORY(lcAgentOp, "librescrs.agentclient.operation")
} // namespace

struct AgentOperation::Private final : public OperationListener, public TransportSeam::DerListener
{
    /// The seam kind behind a transport-backed operation. Never called for
    /// CertificateDer (a client-driven fetch with no seam operation object).
    [[nodiscard]] static OperationKind seamKindFor(Kind kind)
    {
        switch (kind) {
        case Kind::Identity:
            return OperationKind::Identity;
        case Kind::Photo:
            return OperationKind::Photo;
        case Kind::Certificates:
            return OperationKind::Certificates;
        case Kind::Sign:
            return OperationKind::Sign;
        case Kind::Credentials:
            return OperationKind::Credentials;
        case Kind::CertificateDer:
            break;
        }
        Q_ASSERT(false);
        return OperationKind::Identity; // unreachable for a valid transport-backed kind
    }

    AgentOperation* q;
    TransportSeam* transport = nullptr; // null for local (entry-refused) operations
    QString operationId;                // empty for local operations
    Kind kind;

    bool finishedEmitted = false;
    bool resultSeen = false;
    // True only while the ctor's lost-Finished recovery (or an entry-refusal
    // terminalization) runs — BEFORE the minting call returns the operation
    // and the consumer connects. In that window the terminal `finished` emit
    // must be QUEUED (a synchronous Q_EMIT would be lost). On every other
    // path (the live terminal signal, the death-sweep terminate()) the
    // consumer is already subscribed AND — for the death-sweep — the
    // operation is deleted synchronously right after, so the emit MUST be
    // synchronous or it is never delivered.
    bool inCtorRecovery = false;
    OperationStatus status = OperationStatus::Error;
    ErrorCode errorCode = ErrorCode::None;
    CallError callError = CallError::None;
    QString messageKey;
    QString messageFallback;

    OperationPhase phase = OperationPhase::Created;
    double progress = 0.0;

    QList<FieldGroup> identityResult;
    QList<CertificateInfo> certificatesResult;
    std::vector<PhotoItem> photos;
    FdHandle signedArtifact;
    QVariantMap signMeta;
    PinResult pinResult;
    CredentialList credentialsResult;
    QByteArray der;
    quint64 derToken = 0; // nonzero while a DER fetch is in flight

    Private(AgentOperation* owner, Kind operationKind) : q(owner), kind(operationKind) {}

    // ---- OperationListener --------------------------------------------------

    void onPhaseChanged(OperationPhase newPhase, double newProgress) override
    {
        phase = newPhase;
        progress = newProgress;
        Q_EMIT q->phaseChanged(newPhase, newProgress);
    }

    void onFinished(OperationStatus terminalStatus, ErrorCode code, const QString& msgKey,
                    const QString& msgFallback) override
    {
        q->finalizeTerminal(terminalStatus, code, msgKey, msgFallback);
    }

    void onResult(OperationPayload payload) override
    {
        // A live typed-Result delivery, only ever dispatched by the event loop
        // (never synchronously in the ctor — the ctor's recovery uses the
        // fetch pull below), so the payload is simply retained for the getters.
        // If this fires AFTER finalizeTerminal() already gave up and surfaced
        // a loud CommunicationError (resultSeen was false and the recovery
        // pull found nothing yet), it still overwrites the result getters
        // here — a raced live Result landing after its own terminal. The
        // lifted KDE client has the identical wrinkle; preserved deliberately
        // for parity rather than papered over.
        storePayload(std::move(payload));
        resultSeen = true;
    }

    // ---- DerListener --------------------------------------------------------

    void onCertificateDer(quint64 token, DerOutcome outcome) override
    {
        if (token != derToken) {
            return;
        }
        derToken = 0;
        if (outcome.error.isError()) {
            q->emitFinishedOnce(OperationStatus::Error, outcome.error.errorCode, outcome.error.callError, QString(),
                                outcome.error.message);
            return;
        }
        der = std::move(outcome.der);
        resultSeen = true;
        q->emitFinishedOnce(OperationStatus::Ok, ErrorCode::None, CallError::None, QString(), QString());
    }

    // ---- payload handling ---------------------------------------------------

    void storePayload(OperationPayload&& payload)
    {
        switch (payload.kind) {
        case OperationKind::Identity:
            identityResult = std::move(payload.identity);
            break;
        case OperationKind::Certificates:
            certificatesResult = std::move(payload.certificates);
            break;
        case OperationKind::Photo:
            photos = std::move(payload.photos);
            break;
        case OperationKind::Sign:
            signedArtifact = std::move(payload.signedArtifact);
            signMeta = std::move(payload.signMeta);
            break;
        case OperationKind::Credentials:
            pinResult = std::move(payload.pinResult);
            credentialsResult = std::move(payload.credentials);
            break;
        }
    }

    /// Late-subscriber recovery: one typed pull that re-serves the retained
    /// payload when the one-shot Result signal was lost/raced. Returns true
    /// when a usable payload was recovered. The per-kind emptiness policy is
    /// the lifted one: an empty inline payload (identity/certificates/photo)
    /// or an invalid signed-artifact fd is indistinguishable from a genuinely
    /// missing result, so it does NOT count as recovered — the caller falls
    /// through to the loud CommunicationError. A credentials reply counts by
    /// PRESENCE (an empty records list is a legitimate mutation result).
    [[nodiscard]] bool recoverResult()
    {
        std::optional<OperationPayload> payload = transport->fetchOperationResult(operationId, seamKindFor(kind));
        if (!payload) {
            return false;
        }
        switch (payload->kind) {
        case OperationKind::Identity:
            if (payload->identity.isEmpty()) {
                return false;
            }
            break;
        case OperationKind::Certificates:
            if (payload->certificates.isEmpty()) {
                return false;
            }
            break;
        case OperationKind::Photo:
            if (payload->photos.empty()) {
                return false;
            }
            break;
        case OperationKind::Sign:
            if (!payload->signedArtifact.valid()) {
                return false;
            }
            break;
        case OperationKind::Credentials:
            break; // reply presence is the signal — parse regardless
        }
        storePayload(std::move(*payload));
        resultSeen = true;
        return true;
    }
};

AgentOperation::AgentOperation(TransportSeam* transport, const QString& operationId, Kind kind, QObject* parent)
    : QObject(parent), d(std::make_unique<Private>(this, kind))
{
    d->transport = transport;
    d->operationId = operationId;

    // Subscriptions are installed BEFORE any recovery read so a result firing
    // between construction and the recovery probe is never missed (the lifted
    // connect-terminal-before-typed-result ordering lives in the transport).
    transport->subscribeOperation(operationId, Private::seamKindFor(kind), d.get());

    // Guard the recovery window: any terminal emit it triggers is queued so a
    // consumer connecting right after this ctor returns still receives it.
    d->inCtorRecovery = true;
    recoverIfAlreadyFinished();
    d->inCtorRecovery = false;
}

AgentOperation::AgentOperation(Kind kind, QObject* parent) : QObject(parent), d(std::make_unique<Private>(this, kind))
{}

AgentOperation::~AgentOperation()
{
    if (d->transport != nullptr && !d->operationId.isEmpty()) {
        d->transport->unsubscribeOperation(d->operationId, d.get());
    }
    if (d->transport != nullptr && d->derToken != 0) {
        d->transport->cancelCertificateDer(d->derToken, d.get());
    }
}

void AgentOperation::cancel()
{
    if (d->transport != nullptr && !d->operationId.isEmpty()) {
        d->transport->cancelOperation(d->operationId);
    }
}

bool AgentOperation::isFinished() const
{
    return d->finishedEmitted;
}

OperationStatus AgentOperation::status() const
{
    return d->status;
}

OperationPhase AgentOperation::phase() const
{
    return d->phase;
}

double AgentOperation::progress() const
{
    return d->progress;
}

ErrorCode AgentOperation::errorCode() const
{
    return d->errorCode;
}

CallError AgentOperation::callError() const
{
    return d->callError;
}

QString AgentOperation::messageKey() const
{
    return d->messageKey;
}

QString AgentOperation::messageFallback() const
{
    return d->messageFallback;
}

QList<FieldGroup> AgentOperation::identityResult() const
{
    return d->identityResult;
}

QList<CertificateInfo> AgentOperation::certificatesResult() const
{
    return d->certificatesResult;
}

std::vector<PhotoItem> AgentOperation::takePhotos()
{
    return std::move(d->photos);
}

FdHandle AgentOperation::takeSignedArtifact()
{
    return std::move(d->signedArtifact);
}

QVariantMap AgentOperation::signMeta() const
{
    return d->signMeta;
}

PinResult AgentOperation::pinResult() const
{
    return d->pinResult;
}

CredentialList AgentOperation::credentialsResult() const
{
    return d->credentialsResult;
}

QByteArray AgentOperation::certificateDerResult() const
{
    return d->der;
}

void AgentOperation::terminate(OperationStatus terminalStatus, ErrorCode code, CallError call, const QString& msgKey,
                               const QString& msgFallback)
{
    // Pure local terminalization — no transport call (the peer is gone).
    // emitFinishedOnce is idempotent, so a racing real terminal that already
    // fired wins and this is a no-op.
    emitFinishedOnce(terminalStatus, code, call, msgKey, msgFallback);
}

void AgentOperation::failEntry(const SeamError& error)
{
    // The minting call returns this operation to a consumer that has not
    // connected yet: queue the terminal emit exactly like the ctor recovery
    // window does.
    d->inCtorRecovery = true;
    emitFinishedOnce(OperationStatus::Error, error.errorCode, error.callError, QString(), error.message);
    d->inCtorRecovery = false;
}

void AgentOperation::startCertificateDer(TransportSeam* transport, const QString& readerId, const QString& certId)
{
    d->transport = transport;
    d->derToken = transport->requestCertificateDer(readerId, certId, d.get());
}

void AgentOperation::finalizeTerminal(OperationStatus terminalStatus, ErrorCode code, const QString& msgKey,
                                      const QString& msgFallback)
{
    // The credentials result diverges from the other typed results. Its Result
    // fires for EVERY completed attempt — the payload carries the per-attempt
    // outcome, so a soft-fail (invalidPin / blocked) legitimately finishes
    // Error WITH a result. Recover whenever we have not yet seen it,
    // REGARDLESS of Ok vs Error — placed BEFORE the generic `Ok` block so
    // non-Ok credentials terminals are recovered too. A non-Ok outcome is NOT
    // rewritten into a CommunicationError merely because status != Ok: the
    // loud fallback fires ONLY when there is genuinely no recoverable payload
    // (for BOTH Ok and Error). On a recovered/seen payload we emit the REAL
    // terminal (status, code).
    if (!d->resultSeen && d->kind == Kind::Credentials) {
        if (!d->recoverResult()) {
            qCWarning(lcAgentOp) << "credentials op" << d->operationId
                                 << "finished but its result was not delivered and the recovery pull returned "
                                    "nothing (lost/late signal, grace window elapsed, or an agent without the "
                                    "recovery method); surfacing as a communication error";
            emitFinishedOnce(OperationStatus::Error, ErrorCode::CommunicationError, CallError::None, msgKey,
                             msgFallback);
            return;
        }
        emitFinishedOnce(terminalStatus, code, CallError::None, msgKey, msgFallback);
        return;
    }
    if (terminalStatus == OperationStatus::Ok && !d->resultSeen) {
        // The typed result signal is a one-shot: if we finished Ok but never
        // saw it (subscribed late — a hot card session finishes faster than
        // our subscriptions install, or the signal was otherwise lost), every
        // typed interface offers a recovery pull that re-serves the retained
        // payload while the operation survives the agent's cleanup-grace
        // window. Try it before surfacing a communication error. Version-skew
        // safe: an agent WITHOUT the pull answers with an error reply, which
        // leaves the result unseen and drops us into the loud fallback below.
        if (!d->recoverResult()) {
            // The pull yielded nothing (no result / grace window elapsed / an
            // agent without it). Don't claim Ok with an empty payload the
            // caller cannot distinguish from a genuinely empty read. Fail
            // loudly so the caller can retry / report a communication fault.
            qCWarning(lcAgentOp) << "operation" << d->operationId
                                 << "finished Ok but its typed result was not delivered and the recovery pull "
                                    "returned no result (lost/late signal, grace window elapsed, or an agent "
                                    "without it); surfacing as a communication error";
            emitFinishedOnce(OperationStatus::Error, ErrorCode::CommunicationError, CallError::None, msgKey,
                             msgFallback);
            return;
        }
    }
    emitFinishedOnce(terminalStatus, code, CallError::None, msgKey, msgFallback);
}

void AgentOperation::emitFinishedOnce(OperationStatus terminalStatus, ErrorCode code, CallError call,
                                      const QString& msgKey, const QString& msgFallback)
{
    if (d->finishedEmitted) {
        return;
    }
    // Set the polled terminal state SYNCHRONOUSLY: isFinished()/status()/
    // errorCode()/callError() (+ the result members, already set by onResult /
    // the recovery pull) must be true the instant this returns, so the ctor's
    // synchronous recovery still reports a terminal operation.
    d->finishedEmitted = true;
    d->status = terminalStatus;
    d->errorCode = code;
    d->callError = call;
    d->messageKey = msgKey;
    d->messageFallback = msgFallback;

    // Defer the signal to a queued event-loop turn ONLY inside the ctor's
    // recovery / entry-refusal window (before the consumer connects — a
    // synchronous emit would be lost). On the live terminal path the consumer
    // is already subscribed; on the terminate() death-sweep the operation is
    // deleted synchronously right after, so the emit MUST be synchronous
    // there or it is never delivered (a queued event on a deleted QObject is
    // dropped).
    if (d->inCtorRecovery) {
        QMetaObject::invokeMethod(this, [this]() { Q_EMIT finished(); }, Qt::QueuedConnection);
    } else {
        Q_EMIT finished();
    }
}

void AgentOperation::recoverIfAlreadyFinished()
{
    // Read the terminal triple. If the operation already finished before our
    // subscriptions installed, synthesize the missed terminal + recover the
    // typed payload. One bounded pull — never an uncapped wait.
    const std::optional<TerminalSnapshot> snapshot = d->transport->fetchOperationState(d->operationId);
    if (!snapshot || !snapshot->completed) {
        return; // not finished yet (or the read failed) — the live signal drives us
    }
    // The terminal triple carries no message; clients map errorCode().
    finalizeTerminal(snapshot->status, snapshot->errorCode, QString(), QString());
}

} // namespace LibreSCRS::AgentClient
