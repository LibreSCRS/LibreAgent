// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "DBusTransport.h"

#include "AgentDBus.h"
#include "CappedCall.h"
#include "ErrorNameMap.h"

#include <LibreSCRS/AgentClient/ClientTimeouts.h>

#include <QDBusArgument>
#include <QDBusMessage>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QDBusServiceWatcher>
#include <QLoggingCategory>
#include <QVariant>

namespace {
Q_LOGGING_CATEGORY(lcTransport, "librescrs.agentclient.dbus")
} // namespace

namespace LibreSCRS::AgentClient {

namespace {

// a{oa{sa{sv}}} return of GetManagedObjects.
using ManagedObjectMap = QMap<QDBusObjectPath, AgentInterfaceProps>;

const char* propertiesIfaceFor(ObjectKind kind)
{
    return kind == ObjectKind::Reader ? kReaderIface : kCardIface;
}

const char* typedIfaceFor(OperationKind kind)
{
    switch (kind) {
    case OperationKind::Identity:
        return kIdentityIface;
    case OperationKind::Photo:
        return kPhotoIface;
    case OperationKind::Certificates:
        return kCertificatesIface;
    case OperationKind::Sign:
        return kSignIface;
    case OperationKind::Credentials:
        return kOperationCredentialsIface;
    }
    return kOperationIface; // unreachable for a valid enumerator
}

} // namespace

// ---- DBusPropertyWatch ----------------------------------------------------------

DBusPropertyWatch::DBusPropertyWatch(QString watchedObjectId, ObjectKind objectKind, PropertyListener* propertyListener,
                                     QObject* parent)
    : QObject(parent), objectId(std::move(watchedObjectId)), kind(objectKind), listener(propertyListener)
{}

void DBusPropertyWatch::onPropertiesChanged(const QString& iface, const QVariantMap& changed,
                                            const QStringList& invalidated)
{
    if (iface != QLatin1String(propertiesIfaceFor(kind))) {
        return;
    }
    // Scrub at the boundary: any object-path property (a reader's Card, a
    // card's Reader) crosses the seam as its plain id string.
    listener->onPropertiesChanged(scrubObjectPaths(changed), invalidated);
}

// ---- DBusOperationWatch ---------------------------------------------------------

DBusOperationWatch::DBusOperationWatch(QString watchedOperationId, OperationKind operationKind,
                                       OperationListener* operationListener, QObject* parent)
    : QObject(parent), operationId(std::move(watchedOperationId)), kind(operationKind), listener(operationListener)
{}

void DBusOperationWatch::onFinished(uint status, uint errorCode, const QString& msgKey, const QString& msgFallback)
{
    listener->onFinished(static_cast<OperationStatus>(status), static_cast<ErrorCode>(errorCode), msgKey, msgFallback);
}

void DBusOperationWatch::onPropertiesChanged(const QString& iface, const QVariantMap& changed,
                                             const QStringList& /*invalidated*/)
{
    if (iface != QLatin1String(kOperationIface)) {
        return;
    }
    if (changed.contains(QStringLiteral("Phase")) || changed.contains(QStringLiteral("Progress"))) {
        // Phase/Progress are read straight from the `changed` map (which may
        // carry only one of them); no per-tick property Get is needed.
        const QVariant phaseV = changed.value(QStringLiteral("Phase"));
        const QVariant progressV = changed.value(QStringLiteral("Progress"));
        const auto phase = static_cast<OperationPhase>(phaseV.isValid() ? phaseV.toUInt() : 0U);
        listener->onPhaseChanged(phase, progressV.isValid() ? progressV.toDouble() : 0.0);
    }
}

void DBusOperationWatch::onSignResult(const QDBusUnixFileDescriptor& fd, const QVariantMap& meta)
{
    OperationPayload payload;
    payload.kind = OperationKind::Sign;
    payload.signedArtifact = toFdHandle(fd); // dup'd into an owning handle
    payload.signMeta = meta;
    listener->onResult(std::move(payload));
}

void DBusOperationWatch::onIdentityResult(IdentityFieldsWire fields)
{
    OperationPayload payload;
    payload.kind = OperationKind::Identity;
    payload.identity = toFieldGroups(fields);
    listener->onResult(std::move(payload));
}

void DBusOperationWatch::onCertificatesResult(CertListWire certificates)
{
    OperationPayload payload;
    payload.kind = OperationKind::Certificates;
    payload.certificates = toCertificateInfos(certificates);
    listener->onResult(std::move(payload));
}

void DBusOperationWatch::onPhotoResult(PhotoMapWire photos)
{
    OperationPayload payload;
    payload.kind = OperationKind::Photo;
    payload.photos = toPhotoItems(photos);
    listener->onResult(std::move(payload));
}

void DBusOperationWatch::onCredentialsResult(QVariantMap result, CredentialRecordsWire records)
{
    OperationPayload payload;
    payload.kind = OperationKind::Credentials;
    payload.pinResult = PinResult::fromVariantMap(result);
    payload.credentials = toCredentialList(records);
    listener->onResult(std::move(payload));
}

// ---- DBusTransport --------------------------------------------------------------

DBusTransport::DBusTransport() : DBusTransport(QDBusConnection::sessionBus(), QLatin1String(kService)) {}

DBusTransport::DBusTransport(const QDBusConnection& connection, const QString& service)
    : m_connection(connection), m_service(service)
{
    ensureDBusMetatypes();

    m_watcher = new QDBusServiceWatcher(
        m_service, m_connection,
        QDBusServiceWatcher::WatchForRegistration | QDBusServiceWatcher::WatchForUnregistration, this);
    connect(m_watcher, &QDBusServiceWatcher::serviceRegistered, this, &DBusTransport::onServiceRegistered);
    connect(m_watcher, &QDBusServiceWatcher::serviceUnregistered, this, &DBusTransport::onServiceUnregistered);

    m_connection.connect(m_service, QLatin1String(kRootPath), QLatin1String(kObjectManagerIface),
                         QStringLiteral("InterfacesAdded"), this,
                         SLOT(onInterfacesAdded(QDBusObjectPath, LibreSCRS::AgentClient::AgentInterfaceProps)));
    m_connection.connect(m_service, QLatin1String(kRootPath), QLatin1String(kObjectManagerIface),
                         QStringLiteral("InterfacesRemoved"), this,
                         SLOT(onInterfacesRemoved(QDBusObjectPath, QStringList)));
}

DBusTransport::~DBusTransport() = default;

void DBusTransport::setRegistryListener(RegistryListener* listener)
{
    m_registry = listener;
}

bool DBusTransport::nameHasOwner()
{
    // Ask the bus daemon via a capped NameHasOwner instead of
    // connection.interface()->isServiceRegistered() — the latter blocks
    // UNCAPPED (~25 s default), long enough to feel like a stuck discovery
    // hang and to freeze a running outer loop the whole time. cappedCall
    // bounds it to the handshake budget and keeps that loop responsive.
    QDBusMessage call =
        QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                                       QStringLiteral("org.freedesktop.DBus"), QStringLiteral("NameHasOwner"));
    call.setArguments(QList<QVariant>{m_service});
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    return reply.type() == QDBusMessage::ReplyMessage && !reply.arguments().isEmpty() &&
           reply.arguments().constFirst().toBool();
}

bool DBusTransport::probeAvailability()
{
    return nameHasOwner();
}

bool DBusTransport::agentInstalled()
{
    if (nameHasOwner()) {
        return true;
    }
    // Not running — but a D-Bus-activatable agent still counts as installed:
    // the bus daemon can start it on demand.
    QDBusMessage call =
        QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                                       QStringLiteral("org.freedesktop.DBus"), QStringLiteral("ListActivatableNames"));
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        return false;
    }
    return reply.arguments().constFirst().toStringList().contains(m_service);
}

std::optional<RegistrySnapshot> DBusTransport::fetchRegistry()
{
    QDBusMessage call = QDBusMessage::createMethodCall(
        m_service, QLatin1String(kRootPath), QLatin1String(kObjectManagerIface), QStringLiteral("GetManagedObjects"));
    // Event-loop-safe capped call rather than QDBus::Block, so a running outer
    // loop stays responsive and the wait is bounded even with no loop at all.
    // On a wedged/absent agent this returns an error reply at ~the handshake
    // budget and discovery yields nothing new — the caller reconciles, never
    // hangs.
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        return std::nullopt;
    }

    ManagedObjectMap managed;
    const QDBusArgument arg = reply.arguments().constFirst().value<QDBusArgument>();
    arg >> managed;

    RegistrySnapshot snapshot;
    for (auto it = managed.constBegin(); it != managed.constEnd(); ++it) {
        const QString id = it.key().path();
        const AgentInterfaceProps& ifaces = it.value();
        if (ifaces.contains(QLatin1String(kCardIface))) {
            snapshot.cards.append({id, scrubObjectPaths(ifaces.value(QLatin1String(kCardIface)))});
        }
        if (ifaces.contains(QLatin1String(kReaderIface))) {
            snapshot.readers.append({id, scrubObjectPaths(ifaces.value(QLatin1String(kReaderIface)))});
        }
    }
    return snapshot;
}

void DBusTransport::subscribeProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener)
{
    auto* watch = new DBusPropertyWatch(objectId, kind, listener, this);
    m_propertyWatches.insert(listener, watch);
    m_connection.connect(m_service, objectId, QLatin1String(kPropertiesIface), QStringLiteral("PropertiesChanged"),
                         watch, SLOT(onPropertiesChanged(QString, QVariantMap, QStringList)));
}

void DBusTransport::unsubscribeProperties(const QString& objectId, PropertyListener* listener)
{
    Q_UNUSED(objectId)
    // Deleting the receiver drops its match rule and, with it, any pending
    // requestProperties delivery (the fetch lambda re-checks this hash).
    delete m_propertyWatches.take(listener);
}

quint64 DBusTransport::requestProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener)
{
    const quint64 token = ++m_nextToken;
    // Non-blocking, capped low-level Properties.GetAll — NOT a QDBusInterface,
    // whose ctor would issue a synchronous, uncapped Introspect() round-trip.
    // This runs off a PropertiesChanged burst on the consumer's (often
    // main/GUI) thread, so even a capped blocking call could stall the UI for
    // seconds per burst against a slow/wedged agent; asyncCall + watcher
    // returns immediately instead. The watcher's finished() is delivered
    // through this thread's event loop, so the reply lands on the listener's
    // thread.
    QDBusMessage call =
        QDBusMessage::createMethodCall(m_service, objectId, QLatin1String(kPropertiesIface), QStringLiteral("GetAll"));
    call.setArguments(QList<QVariant>{QLatin1String(propertiesIfaceFor(kind))});
    auto* watcher = new QDBusPendingCallWatcher(m_connection.asyncCall(call, kDefaultCallTimeoutMs), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this, token, objectId, listener](QDBusPendingCallWatcher* w) {
                w->deleteLater();
                // Deliver only into a live subscription for the SAME object —
                // a dead/rebound listener never sees a stale reply.
                DBusPropertyWatch* watch = m_propertyWatches.value(listener, nullptr);
                if (watch == nullptr || watch->objectId != objectId) {
                    return;
                }
                const QDBusMessage reply = w->reply();
                if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
                    listener->onPropertiesFetched(token, std::nullopt);
                    return;
                }
                listener->onPropertiesFetched(token,
                                              scrubObjectPaths(demarshalVariantMap(reply.arguments().constFirst())));
            });
    return token;
}

StartOutcome DBusTransport::startOperation(const QString& cardId, OperationRequest request)
{
    const char* iface = kCardIface;
    QString method;
    QList<QVariant> args;
    switch (request.method) {
    case OperationRequest::Method::ReadIdentity:
        method = QStringLiteral("ReadIdentity");
        break;
    case OperationRequest::Method::GetPhoto:
        method = QStringLiteral("GetPhoto");
        break;
    case OperationRequest::Method::ReadCertificates:
        method = QStringLiteral("ReadCertificates");
        break;
    case OperationRequest::Method::Sign:
        method = QStringLiteral("Sign");
        args << request.certId;
        // QDBusUnixFileDescriptor keeps its own duplicate; the request's
        // handle stays owned by the request and closes with it.
        args << QVariant::fromValue(QDBusUnixFileDescriptor(request.document.get()));
        args << request.options;
        break;
    case OperationRequest::Method::ListCredentials:
        iface = kCredentialsIface;
        method = QStringLiteral("ListCredentials");
        break;
    case OperationRequest::Method::ManagePin:
        iface = kCredentialsIface;
        method = QStringLiteral("ManagePin");
        args << request.pinId << request.verb << request.options;
        break;
    case OperationRequest::Method::ActivateSigningKey:
        iface = kCredentialsIface;
        method = QStringLiteral("ActivateSigningKey");
        break;
    }

    QDBusMessage call = QDBusMessage::createMethodCall(m_service, cardId, QLatin1String(iface), method);
    if (!args.isEmpty()) {
        call.setArguments(args);
    }
    // Deliberately synchronous, bounded by the default call budget. Method
    // entry replies immediately in the agent design — it mints the operation
    // object and returns its id; the long card work happens on that operation
    // and arrives via its signals. The public contract returns the
    // AgentOperation synchronously, the call sites are explicit user actions
    // (not background property bursts), and a capped block avoids the
    // reentrancy a nested wait would allow mid-start. Worst case against a
    // wedged agent: one bounded stall, then a failed-entry outcome.
    const QDBusMessage reply = m_connection.call(call, QDBus::Block, kDefaultCallTimeoutMs);
    StartOutcome outcome;
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        // Method threw at entry (e.g. a missing capability). The agent's error
        // name/message is the ONLY record of why — never swallow it.
        qCWarning(lcTransport).noquote() << method << "refused for" << cardId << ':' << reply.errorName()
                                         << reply.errorMessage();
        outcome.error = mapDBusErrorName(reply.errorName(), reply.errorMessage());
        return outcome;
    }
    const QString opPath = qvariant_cast<QDBusObjectPath>(reply.arguments().constFirst()).path();
    if (opPath.isEmpty()) {
        outcome.error.callError = CallError::ProtocolError;
        outcome.error.message = QStringLiteral("method entry returned no operation path");
        return outcome;
    }
    outcome.operationId = opPath;
    return outcome;
}

void DBusTransport::subscribeOperation(const QString& operationId, OperationKind kind, OperationListener* listener)
{
    auto* watch = new DBusOperationWatch(operationId, kind, listener, this);
    m_operationWatches.insert(listener, watch);

    // Operation1.Finished(u status, u errorCode, s msgKey, s msgFallback) —
    // connected FIRST, then Phase/Progress, then the typed Result, preserving
    // the lifted connect ordering.
    m_connection.connect(m_service, operationId, QLatin1String(kOperationIface), QStringLiteral("Finished"), watch,
                         SLOT(onFinished(uint, uint, QString, QString)));
    m_connection.connect(m_service, operationId, QLatin1String(kPropertiesIface), QStringLiteral("PropertiesChanged"),
                         watch, SLOT(onPropertiesChanged(QString, QVariantMap, QStringList)));

    switch (kind) {
    case OperationKind::Sign:
        m_connection.connect(m_service, operationId, QLatin1String(kSignIface), QStringLiteral("Result"), watch,
                             SLOT(onSignResult(QDBusUnixFileDescriptor, QVariantMap)));
        break;
    case OperationKind::Identity:
        // a{sa{s(sssv)}} demarshaled into the registered IdentityFieldsWire.
        m_connection.connect(m_service, operationId, QLatin1String(kIdentityIface), QStringLiteral("Result"), watch,
                             SLOT(onIdentityResult(LibreSCRS::AgentClient::IdentityFieldsWire)));
        break;
    case OperationKind::Certificates:
        // a(sba{sa{s(ssv)}}uasasu) demarshaled into the registered CertListWire.
        m_connection.connect(m_service, operationId, QLatin1String(kCertificatesIface), QStringLiteral("Result"), watch,
                             SLOT(onCertificatesResult(LibreSCRS::AgentClient::CertListWire)));
        break;
    case OperationKind::Photo:
        // a{sh} (sealed-memfd photo map) demarshaled into the registered PhotoMapWire.
        m_connection.connect(m_service, operationId, QLatin1String(kPhotoIface), QStringLiteral("Result"), watch,
                             SLOT(onPhotoResult(LibreSCRS::AgentClient::PhotoMapWire)));
        break;
    case OperationKind::Credentials:
        // (a{sv} result, aa{sv} records) — the two-out-arg credentials Result.
        m_connection.connect(m_service, operationId, QLatin1String(kOperationCredentialsIface),
                             QStringLiteral("Result"), watch,
                             SLOT(onCredentialsResult(QVariantMap, LibreSCRS::AgentClient::CredentialRecordsWire)));
        break;
    }
}

void DBusTransport::unsubscribeOperation(const QString& operationId, OperationListener* listener)
{
    Q_UNUSED(operationId)
    delete m_operationWatches.take(listener);
}

std::optional<TerminalSnapshot> DBusTransport::fetchOperationState(const QString& operationId)
{
    // ONE capped low-level Properties.GetAll — not a QDBusInterface (blocking
    // introspection round-trip) plus per-property uncapped Gets (each waiting
    // out the ~25 s default D-Bus timeout on a wedged agent).
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, operationId, QLatin1String(kPropertiesIface),
                                                       QStringLiteral("GetAll"));
    call.setArguments(QList<QVariant>{QLatin1String(kOperationIface)});
    const QDBusMessage reply = m_connection.call(call, QDBus::Block, kDefaultCallTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        return std::nullopt; // read failed or timed out — the live signal drives us
    }

    const QVariantMap props = demarshalVariantMap(reply.arguments().constFirst());
    TerminalSnapshot snapshot;
    snapshot.completed = props.value(QStringLiteral("Completed")).toBool();
    const QVariant statusV = props.value(QStringLiteral("Status"));
    const QVariant errorV = props.value(QStringLiteral("ErrorCode"));
    snapshot.status = static_cast<OperationStatus>(statusV.isValid() ? statusV.toUInt() : 2U);
    snapshot.errorCode = static_cast<ErrorCode>(errorV.isValid() ? errorV.toUInt() : 0U);
    return snapshot;
}

std::optional<OperationPayload> DBusTransport::fetchOperationResult(const QString& operationId, OperationKind kind)
{
    // The typed GetResult recovery pull: a direct method call with a capped
    // timeout — avoids QDBusInterface's blocking introspection round-trip and
    // never lets a wedged agent stall the (often main) thread waiting out the
    // multi-second default D-Bus timeout. A non-reply (Error.NoResult, grace
    // window elapsed, UnknownMethod version skew, or timeout) yields nullopt
    // so the operation layer falls through to its loud CommunicationError.
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, operationId, QLatin1String(typedIfaceFor(kind)),
                                                       QStringLiteral("GetResult"));
    const QDBusMessage reply = m_connection.call(call, QDBus::Block, kDefaultCallTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        return std::nullopt;
    }
    const QList<QVariant> args = reply.arguments();

    OperationPayload payload;
    payload.kind = kind;

    switch (kind) {
    case OperationKind::Sign: {
        if (args.size() < 2) {
            return std::nullopt;
        }
        // Positional extraction matching the frozen Sign1 out-arg order
        // (h signedArtifact, a{sv} meta).
        QDBusUnixFileDescriptor fd = qvariant_cast<QDBusUnixFileDescriptor>(args.at(0));
        QVariantMap meta = demarshalVariantMap(args.at(1));
        // Defensive fallback: if a future binding ever reorders the out-args,
        // locate the fd by type. (The wire order is frozen; this should never
        // fire.)
        if (!fd.isValid() && args.at(1).metaType().id() == qMetaTypeId<QDBusUnixFileDescriptor>()) {
            fd = qvariant_cast<QDBusUnixFileDescriptor>(args.at(1));
            meta = demarshalVariantMap(args.at(0));
        }
        payload.signedArtifact = toFdHandle(fd);
        payload.signMeta = meta;
        return payload;
    }
    case OperationKind::Credentials: {
        // The credentials GetResult returns the SAME two-out-arg shape as its
        // Result signal — (a{sv} result, aa{sv} records).
        if (args.size() < 2) {
            return std::nullopt;
        }
        payload.pinResult = PinResult::fromVariantMap(demarshalVariantMap(args.at(0)));
        CredentialRecordsWire records;
        const QVariant& recordsArg = args.at(1);
        if (recordsArg.metaType().id() == qMetaTypeId<QDBusArgument>()) {
            recordsArg.value<QDBusArgument>() >> records;
        }
        payload.credentials = toCredentialList(records);
        return payload;
    }
    case OperationKind::Identity: {
        if (args.isEmpty()) {
            return std::nullopt;
        }
        IdentityFieldsWire fields;
        const QVariant& arg = args.at(0);
        if (arg.metaType().id() == qMetaTypeId<QDBusArgument>()) {
            arg.value<QDBusArgument>() >> fields;
        }
        payload.identity = toFieldGroups(fields);
        return payload;
    }
    case OperationKind::Certificates: {
        if (args.isEmpty()) {
            return std::nullopt;
        }
        CertListWire certs;
        const QVariant& arg = args.at(0);
        if (arg.metaType().id() == qMetaTypeId<QDBusArgument>()) {
            arg.value<QDBusArgument>() >> certs;
        }
        payload.certificates = toCertificateInfos(certs);
        return payload;
    }
    case OperationKind::Photo: {
        if (args.isEmpty()) {
            return std::nullopt;
        }
        PhotoMapWire photos;
        const QVariant& arg = args.at(0);
        if (arg.metaType().id() == qMetaTypeId<QDBusArgument>()) {
            arg.value<QDBusArgument>() >> photos;
        }
        payload.photos = toPhotoItems(photos);
        return payload;
    }
    }
    return std::nullopt; // unreachable for a valid enumerator
}

void DBusTransport::cancelOperation(const QString& operationId)
{
    // Fire-and-forget the Cancel via a low-level method call. A QDBusInterface
    // would block on a synchronous Introspect() before the asyncCall — a
    // multi-second GUI freeze on a wedged agent precisely when the user
    // clicked Cancel to escape it.
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, operationId, QLatin1String(kOperationIface),
                                                       QStringLiteral("Cancel"));
    m_connection.asyncCall(call);
}

quint64 DBusTransport::requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener)
{
    const quint64 token = ++m_nextToken;
    m_derListeners.insert(listener);

    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath), QLatin1String(kPkcs11Iface),
                                                       QStringLiteral("CertDer"));
    call.setArguments(QList<QVariant>{QVariant::fromValue(QDBusObjectPath(readerId)), certId});

    // Asynchronous, bounded by the default call budget: this is a real
    // public-data fetch, not a registry read, and the reply lands through the
    // event loop so a wedged agent can never stall the caller.
    auto* watcher = new QDBusPendingCallWatcher(m_connection.asyncCall(call, kDefaultCallTimeoutMs), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, token, listener](QDBusPendingCallWatcher* w) {
        w->deleteLater();
        if (!m_derListeners.remove(listener)) {
            return; // cancelled — the operation is gone
        }
        DerOutcome outcome;
        const QDBusMessage reply = w->reply();
        if (reply.type() != QDBusMessage::ReplyMessage) {
            outcome.error = reply.errorName().isEmpty()
                                ? mapAgentErrorShortName(QStringLiteral("CommunicationError"), reply.errorMessage())
                                : mapDBusErrorName(reply.errorName(), reply.errorMessage());
        } else if (reply.arguments().isEmpty()) {
            outcome.error = mapAgentErrorShortName(QStringLiteral("CommunicationError"), QStringLiteral("empty reply"));
        } else {
            outcome.der = reply.arguments().constFirst().toByteArray(); // 'ay' -> QByteArray
        }
        listener->onCertificateDer(token, std::move(outcome));
    });
    return token;
}

void DBusTransport::cancelCertificateDer(DerListener* listener)
{
    m_derListeners.remove(listener);
}

void DBusTransport::onServiceRegistered(const QString& /*service*/)
{
    if (m_registry != nullptr) {
        m_registry->onServiceRegistered();
    }
}

void DBusTransport::onServiceUnregistered(const QString& /*service*/)
{
    if (m_registry != nullptr) {
        m_registry->onServiceUnregistered();
    }
}

void DBusTransport::onInterfacesAdded(const QDBusObjectPath& path, const AgentInterfaceProps& interfacesAndProperties)
{
    if (m_registry == nullptr) {
        return;
    }
    const QString id = path.path();
    // The card before the reader, so a reader's card reference resolves
    // immediately (the lifted ordering).
    if (interfacesAndProperties.contains(QLatin1String(kCardIface))) {
        m_registry->onCardAdded(id, scrubObjectPaths(interfacesAndProperties.value(QLatin1String(kCardIface))));
    }
    if (interfacesAndProperties.contains(QLatin1String(kReaderIface))) {
        m_registry->onReaderAdded(id, scrubObjectPaths(interfacesAndProperties.value(QLatin1String(kReaderIface))));
    }
}

void DBusTransport::onInterfacesRemoved(const QDBusObjectPath& path, const QStringList& interfaces)
{
    if (m_registry == nullptr) {
        return;
    }
    const QString id = path.path();
    if (interfaces.contains(QLatin1String(kCardIface))) {
        m_registry->onCardRemoved(id);
    }
    if (interfaces.contains(QLatin1String(kReaderIface))) {
        m_registry->onReaderRemoved(id);
    }
}

} // namespace LibreSCRS::AgentClient
