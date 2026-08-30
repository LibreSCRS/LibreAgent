// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "DBusTransport.h"

#include "../ConfigKeys.h"
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

#include <fcntl.h> // F_DUPFD_CLOEXEC (appearanceFont's per-call dup)

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

/// The `a(sbb) TslSources` property value as it arrives inside a `v` — a
/// QDBusArgument that still has to be demarshaled — flattened to the
/// canonical three-entry rows `configSnapshot()` promises. Anything else
/// (an agent serving a shape this build does not expect) yields an EMPTY
/// list rather than a half-decoded one: the caller's contract is "rows in
/// this shape or nothing", never "sometimes something else".
QVariant demarshalTslSources(const QVariant& raw)
{
    if (raw.metaType().id() != qMetaTypeId<QDBusArgument>()) {
        return QVariantList();
    }
    TslSourcesWire wire;
    raw.value<QDBusArgument>() >> wire;
    QVariantList rows;
    rows.reserve(wire.size());
    for (const TslSourceWire& source : std::as_const(wire)) {
        rows.append(tslSourceRow(source.url, source.isLotl, source.eager));
    }
    return rows;
}

/// The `a(sb) CscaSources` property value, the same way — the country-signing
/// twin of the function above, and the same all-or-nothing posture. Rows are
/// TWO cells here, not three: there is no isLotl to carry (see Marshal.h's
/// CscaSourceWire).
QVariant demarshalCscaSources(const QVariant& raw)
{
    if (raw.metaType().id() != qMetaTypeId<QDBusArgument>()) {
        return QVariantList();
    }
    CscaSourcesWire wire;
    raw.value<QDBusArgument>() >> wire;
    QVariantList rows;
    rows.reserve(wire.size());
    for (const CscaSourceWire& source : std::as_const(wire)) {
        rows.append(cscaSourceRow(source.uri, source.eager));
    }
    return rows;
}

/// One Config1 property value, out of the `v` it arrived in and into the
/// canonical client vocabulary. Only the two struct-array properties need
/// work: every other key is `s` or `as`, which QtDBus has already demarshaled
/// into a QString / QStringList by the time it reaches here.
QVariant demarshalConfigValue(const QString& key, const QVariant& raw)
{
    if (key == kConfigTslSources) {
        return demarshalTslSources(raw);
    }
    if (key == kConfigCscaSources) {
        return demarshalCscaSources(raw);
    }
    return raw;
}

/// The per-key marshal table for `Config1.SetValue`: the property's declared
/// D-Bus type, spelled here because the caller hands us a QVariant and the
/// agent type-checks what arrives. `s` for the three plain-text settings and
/// the read-only paths, `as` for TsaUrls, `a(sbb)` for TslSources, `a(sb)` for
/// CscaSources.
///
/// A KNOWN key with no arm of its own does not fail, it DEGRADES: the
/// `isKnownConfigKey` fallthrough stringifies whatever arrived, so a
/// list-valued setting would cross the wire as an empty `s` and the caller
/// would be told the write succeeded. Every settable key whose value is not a
/// string needs its own arm above for that reason.
///
/// An UNKNOWN key falls through with the caller's value wrapped as-is. That
/// is deliberate rather than a local refusal: on this wire every key
/// marshals, the agent owns the vocabulary, and letting it answer
/// `UnknownConfigKey` keeps one authority for what a key is instead of two
/// that can disagree.
QDBusVariant marshalConfigValue(const QString& key, const QVariant& value)
{
    if (key == kConfigTsaUrls) {
        return QDBusVariant(value.toStringList());
    }
    if (key == kConfigTslSources) {
        TslSourcesWire wire;
        const QVariantList rows = value.toList();
        wire.reserve(rows.size());
        for (const QVariant& row : rows) {
            const QVariantList cells = row.toList();
            if (cells.size() != 3) {
                continue; // not a [url, isLotl, eager] row — see the API doc
            }
            wire.append(TslSourceWire{cells.at(0).toString(), cells.at(1).toBool(), cells.at(2).toBool()});
        }
        return QDBusVariant(QVariant::fromValue(wire));
    }
    if (key == kConfigCscaSources) {
        CscaSourcesWire wire;
        const QVariantList rows = value.toList();
        wire.reserve(rows.size());
        for (const QVariant& row : rows) {
            const QVariantList cells = row.toList();
            if (cells.size() != 2) {
                continue; // not a [uri, eager] row — see the API doc
            }
            wire.append(CscaSourceWire{cells.at(0).toString(), cells.at(1).toBool()});
        }
        return QDBusVariant(QVariant::fromValue(wire));
    }
    if (isKnownConfigKey(key)) {
        return QDBusVariant(value.toString()); // every remaining Config1 key is `s`
    }
    return QDBusVariant(value);
}

/// A Config1 mutation's reply as the public named outcome: disengaged on
/// success, else the enumerator.
///
/// `mapDBusErrorName` engages `syncError` for exactly the agent-namespace
/// names, which is the distinction that matters here — a bus-daemon failure
/// (ServiceUnknown, NoReply, the capped call's synthesized timeout) named
/// nothing about the WRITE, so it collapses to CommunicationError: the write
/// never arrived, and that is the retryable class.
std::optional<SyncError> configOutcome(const QDBusMessage& reply)
{
    if (reply.type() == QDBusMessage::ReplyMessage) {
        return std::nullopt;
    }
    const SeamError error = mapDBusErrorName(reply.errorName(), reply.errorMessage());
    return error.syncError.value_or(SyncError::CommunicationError);
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
    case OperationKind::BatchSign:
        return kSignBatchIface;
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

void DBusOperationWatch::onSignBatchResult(SignBatchRowsWire rows)
{
    OperationPayload payload;
    payload.kind = OperationKind::BatchSign;
    payload.batchRows = toBatchSignRows(rows);
    listener->onResult(std::move(payload));
}

void DBusOperationWatch::onIdentityResult(IdentityFieldsWire fields)
{
    OperationPayload payload;
    payload.kind = OperationKind::Identity;
    payload.identity = toFieldGroups(fields);
    listener->onResult(std::move(payload));
}

void DBusOperationWatch::onIdentityGroup(QString groupKey, IdentityFieldGroupWire fields)
{
    listener->onGroupReady(toFieldGroup(groupKey, fields));
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
    // Config1.Changed rides the same root object. Subscribed unconditionally
    // at construction, exactly like the ObjectManager signals above and for
    // the same reason: a match rule installed only once a consumer first
    // reads the settings would miss every change until then, and an agent
    // without the interface simply never emits it.
    m_connection.connect(m_service, QLatin1String(kRootPath), QLatin1String(kConfigIface), QStringLiteral("Changed"),
                         this, SLOT(onConfigChanged(QString)));
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
    const bool hasOwner = nameHasOwner();
    if (hasOwner && !m_managerPropertiesFetched) {
        // The ctor's initial probe is never preceded by a serviceRegistered
        // signal (the watcher only reports FUTURE transitions), so this is
        // the seed path for an agent already running at construction time.
        refreshManagerProperties();
        m_managerPropertiesFetched = true;
    }
    return hasOwner;
}

void DBusTransport::refreshManagerProperties()
{
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath),
                                                       QLatin1String(kPropertiesIface), QStringLiteral("GetAll"));
    call.setArguments(QList<QVariant>{QLatin1String(kManagerIface)});
    // Bounded exactly like every other discovery-path property read. An agent
    // predating either property (or Manager1 entirely) answers with a D-Bus
    // error or an incomplete map — both degrade to the empty values below,
    // never surfaced as a failure: absence is expected, not a fault.
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    m_features.clear();
    m_agentVersion.clear();
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        return;
    }
    const QVariantMap props = demarshalVariantMap(reply.arguments().constFirst());
    m_features = props.value(QStringLiteral("Features")).toStringList();
    m_agentVersion = props.value(QStringLiteral("Version")).toString();
}

QStringList DBusTransport::features() const
{
    return m_features;
}

QString DBusTransport::agentVersion() const
{
    return m_agentVersion;
}

void DBusTransport::refreshConfig()
{
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath),
                                                       QLatin1String(kPropertiesIface), QStringLiteral("GetAll"));
    call.setArguments(QList<QVariant>{QLatin1String(kConfigIface)});
    // ONE GetAll for the whole set, bounded like every other discovery-path
    // property read. An agent without Config1 answers a D-Bus error, which
    // degrades to the empty map below — absence is expected, not a fault.
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    m_config.clear();
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        return;
    }
    const QVariantMap props = demarshalVariantMap(reply.arguments().constFirst());
    for (auto it = props.constBegin(); it != props.constEnd(); ++it) {
        m_config.insert(it.key(), demarshalConfigValue(it.key(), it.value()));
    }
}

void DBusTransport::refreshConfigKey(const QString& key)
{
    if (!m_configFetched) {
        return; // nothing cached yet — the first configSnapshot() reads it all
    }
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath),
                                                       QLatin1String(kPropertiesIface), QStringLiteral("Get"));
    call.setArguments(QList<QVariant>{QLatin1String(kConfigIface), key});
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty()) {
        // Keep whatever was cached: a failed re-read makes the entry stale,
        // which is strictly better than dropping a key a consumer is
        // rendering. The next full snapshot after a reconnect fixes it.
        return;
    }
    m_config.insert(key,
                    demarshalConfigValue(key, qvariant_cast<QDBusVariant>(reply.arguments().constFirst()).variant()));
}

QVariantMap DBusTransport::configSnapshot()
{
    if (!m_configFetched) {
        // "Once per connect", lazily — see the seam's own doc comment for why
        // this one is not primed beside Features/Version. A failed fetch is
        // not retried before the next connect (onServiceRegistered clears the
        // flag), mirroring appearanceFont()'s posture.
        m_configFetched = true;
        refreshConfig();
    }
    return m_config;
}

std::optional<SyncError> DBusTransport::setConfig(const QString& key, const QVariant& value)
{
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath), QLatin1String(kConfigIface),
                                                       QStringLiteral("SetValue"));
    call.setArguments(QList<QVariant>{key, QVariant::fromValue(marshalConfigValue(key, value))});
    // No local refusal on this wire: every key marshals, and the agent owns
    // both the vocabulary and the authorization decision (its polkit tiers
    // are not knowable here). Bounded like the property reads above — a
    // settings write is a cheap round-trip with no card work behind it.
    return configOutcome(cappedCall(m_connection, call, kHandshakeTimeoutMs));
}

std::optional<SyncError> DBusTransport::resetConfig(const QString& key)
{
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath), QLatin1String(kConfigIface),
                                                       QStringLiteral("Reset"));
    call.setArguments(QList<QVariant>{key});
    return configOutcome(cappedCall(m_connection, call, kHandshakeTimeoutMs));
}

void DBusTransport::onConfigChanged(const QString& key)
{
    // Changed carries ONLY the key (the value could have raced anyway), so
    // the freshness debt is the transport's: re-read, THEN announce. A
    // consumer reading configSnapshot() from its slot therefore always sees
    // the new value, and never has to run its own asynchronous re-read that
    // would race the next change.
    refreshConfigKey(key);
    if (m_registry != nullptr) {
        m_registry->onConfigChanged(key);
    }
}

std::optional<LayoutResult> DBusTransport::layoutVisualSignature(const QString& text, QRectF box)
{
    QDBusMessage call = QDBusMessage::createMethodCall(
        m_service, QLatin1String(kRootPath), QLatin1String(kManagerIface), QStringLiteral("LayoutVisualSignature"));
    call.setArguments(QList<QVariant>{text, box.x(), box.y(), box.width(), box.height()});
    // Bounded like every other cheap, card-independent synchronous round-trip
    // (kHandshakeTimeoutMs — see ClientTimeouts.h's own budget-class doc).
    const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().size() < 4) {
        return std::nullopt;
    }
    LayoutResult out;
    out.fontSize = reply.arguments().at(0).toDouble();
    out.lineHeight = reply.arguments().at(1).toDouble();
    out.lines = reply.arguments().at(2).toStringList();
    out.clipped = reply.arguments().at(3).toBool();
    return out;
}

FdHandle DBusTransport::appearanceFont()
{
    if (!m_appearanceFontFetched) {
        // "Once per connect", exactly like refreshFeatures(): a failure here
        // degrades to an invalid cached handle rather than being retried
        // sooner than the next reconnect (onServiceUnregistered resets the
        // flag below).
        m_appearanceFontFetched = true;
        QDBusMessage call = QDBusMessage::createMethodCall(
            m_service, QLatin1String(kRootPath), QLatin1String(kManagerIface), QStringLiteral("GetAppearanceFont"));
        const QDBusMessage reply = cappedCall(m_connection, call, kHandshakeTimeoutMs);
        if (reply.type() == QDBusMessage::ReplyMessage && !reply.arguments().isEmpty()) {
            m_appearanceFont = toFdHandle(qvariant_cast<QDBusUnixFileDescriptor>(reply.arguments().constFirst()));
        }
    }
    if (!m_appearanceFont.valid()) {
        return {};
    }
    // Dup a fresh handle per call: the cache keeps sole ownership of
    // m_appearanceFont's descriptor for the connection's lifetime, mirroring
    // toFdHandle's own O_CLOEXEC-dup posture for every other fd this
    // transport hands out.
    return FdHandle{::fcntl(m_appearanceFont.get(), F_DUPFD_CLOEXEC, 0)};
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
    case OperationRequest::Method::ReadTokenInfo:
        method = QStringLiteral("ReadTokenInfo");
        break;
    case OperationRequest::Method::Sign:
        method = QStringLiteral("Sign");
        args << request.certId;
        // QDBusUnixFileDescriptor keeps its own duplicate; the request's
        // handle stays owned by the request and closes with it.
        args << QVariant::fromValue(QDBusUnixFileDescriptor(request.document.get()));
        args << request.options;
        break;
    case OperationRequest::Method::SignBatch: {
        method = QStringLiteral("SignBatch");
        // Frozen arg order: (a(sh) documents, s certId, a{sv} options) — the
        // documents array comes FIRST, unlike Sign's (certId, fd, options).
        BatchDocumentsWire docs;
        docs.reserve(static_cast<qsizetype>(request.documents.size()));
        for (const BatchDocument& doc : request.documents) {
            // QDBusUnixFileDescriptor dups; the request's handles stay owned
            // by the request and close with it, same as Sign's document above.
            docs.append(BatchDocumentWire{doc.displayName, QDBusUnixFileDescriptor(doc.fd.get())});
        }
        args << QVariant::fromValue(docs);
        args << request.certId;
        args << request.options;
        break;
    }
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
    case OperationKind::BatchSign:
        // a(sha{sv}u) demarshaled into the registered SignBatchRowsWire.
        m_connection.connect(m_service, operationId, QLatin1String(kSignBatchIface), QStringLiteral("Result"), watch,
                             SLOT(onSignBatchResult(LibreSCRS::AgentClient::SignBatchRowsWire)));
        break;
    case OperationKind::Identity:
        // a{sa{s(sssv)}} demarshaled into the registered IdentityFieldsWire.
        m_connection.connect(m_service, operationId, QLatin1String(kIdentityIface), QStringLiteral("Result"), watch,
                             SLOT(onIdentityResult(LibreSCRS::AgentClient::IdentityFieldsWire)));
        // Progressive per-group delivery (Group(s groupKey, a{s(sssv)}
        // fields)), strictly ahead of the Result above for the SAME op.
        // Connected unconditionally -- the client does not gate its OWN
        // subscription on the "identity-stream" feature token (unlike a
        // request-side gate): an agent that does not advertise the token
        // simply never emits this signal, so subscribing costs nothing extra
        // against an older agent.
        m_connection.connect(m_service, operationId, QLatin1String(kIdentityIface), QStringLiteral("Group"), watch,
                             SLOT(onIdentityGroup(QString, LibreSCRS::AgentClient::IdentityFieldGroupWire)));
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
    case OperationKind::BatchSign: {
        if (args.isEmpty()) {
            return std::nullopt;
        }
        SignBatchRowsWire rows;
        const QVariant& arg = args.at(0);
        if (arg.metaType().id() == qMetaTypeId<QDBusArgument>()) {
            arg.value<QDBusArgument>() >> rows;
        }
        payload.batchRows = toBatchSignRows(rows);
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

void DBusTransport::warmCertificates(const QString& cardId)
{
    if (m_warmingCards.contains(cardId)) {
        // The seam's debounce: an entry call for this card is still on the
        // wire, and a warm is idempotent card work — stacking a second one
        // would ask the agent to redo the read it is already doing.
        return;
    }

    // Unlike startOperation's deliberate bounded block — whose contract is to
    // return the minted operation synchronously — a warm has no consumer for
    // the operation, so the entry call goes out asynchronously and the reply
    // is never read. The reply carries the operation path; nobody wants it,
    // and an entry error (a card with no certificates, a missing capability)
    // is dropped on purpose. The agent reaps the operation it minted along
    // with the card, so dropping the path strands nothing on this wire.
    QDBusMessage call = QDBusMessage::createMethodCall(m_service, cardId, QLatin1String(kCardIface),
                                                       QStringLiteral("ReadCertificates"));
    auto* watcher = new QDBusPendingCallWatcher(m_connection.asyncCall(call, kDefaultCallTimeoutMs), this);
    m_warmingCards.insert(cardId);
    // Bound to `this` as the context object, so a transport torn down with a
    // warm still in flight cannot have this run against a dead m_warmingCards.
    // The watcher is parented to `this` for the same reason. Qt delivers
    // `finished` through the event loop even for a call that completed before
    // the watcher existed, so the guard is always cleared exactly once.
    QObject::connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, cardId](QDBusPendingCallWatcher* self) {
        m_warmingCards.remove(cardId);
        self->deleteLater();
    });
}

quint64 DBusTransport::requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener)
{
    const quint64 token = m_derListeners.add(listener);

    QDBusMessage call = QDBusMessage::createMethodCall(m_service, QLatin1String(kRootPath), QLatin1String(kPkcs11Iface),
                                                       QStringLiteral("CertDer"));
    call.setArguments(QList<QVariant>{QVariant::fromValue(QDBusObjectPath(readerId)), certId});

    // Asynchronous, bounded by the default call budget: this is a real
    // public-data fetch, not a registry read, and the reply lands through the
    // event loop so a wedged agent can never stall the caller.
    //
    // The lambda captures ONLY the token, never the listener pointer: a
    // cancelled op's Private and a freshly minted op's Private can share the
    // same heap address, so removing/delivering by pointer identity would let
    // this stale reply silently steal (and drop forever) a DIFFERENT, still-
    // live registration that happens to reuse the same pointer. Looking the
    // listener up through the token-keyed registry instead means two
    // registrations sharing a pointer still occupy two distinct slots.
    auto* watcher = new QDBusPendingCallWatcher(m_connection.asyncCall(call, kDefaultCallTimeoutMs), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, token](QDBusPendingCallWatcher* w) {
        w->deleteLater();
        DerListener* target = m_derListeners.takeIfPresent(token);
        if (target == nullptr) {
            return; // cancelled (or already delivered) — the operation is gone
        }
        DerOutcome outcome;
        const QDBusMessage reply = w->reply();
        if (reply.type() != QDBusMessage::ReplyMessage) {
            // A non-reply with NO error name is not the peer refusing us — it is
            // the exchange itself failing locally, so it carries no wire name to
            // report. With one, the name is the peer's and classifies normally.
            outcome.error = reply.errorName().isEmpty() ? localExchangeFailure(reply.errorMessage())
                                                        : mapDBusErrorName(reply.errorName(), reply.errorMessage());
        } else if (reply.arguments().isEmpty()) {
            // A well-formed reply with no body: the agent answered, but not with
            // anything this request's contract allows. Same reasoning — the
            // client diagnosed this, the agent named nothing.
            outcome.error = localExchangeFailure(QStringLiteral("empty reply"));
        } else {
            outcome.der = reply.arguments().constFirst().toByteArray(); // 'ay' -> QByteArray
        }
        target->onCertificateDer(token, std::move(outcome));
    });
    return token;
}

void DBusTransport::cancelCertificateDer(quint64 token, DerListener* listener)
{
    Q_UNUSED(listener) // the registration is keyed strictly by token; kept for interface symmetry
    m_derListeners.cancel(token);
}

void DBusTransport::onServiceRegistered(const QString& /*service*/)
{
    if (!m_managerPropertiesFetched) {
        refreshManagerProperties();
        m_managerPropertiesFetched = true;
    }
    // The settings are NOT fetched here — they are lazy (see refreshConfig).
    // Only the guard is released, so the next read goes to the newly present
    // agent. This matters for the client constructed while the agent was
    // down: its first configSnapshot() failed and latched the flag, and
    // without this line that failure would outlive the agent's arrival.
    m_configFetched = false;
    m_config.clear();
    if (m_registry != nullptr) {
        m_registry->onServiceRegistered();
    }
}

void DBusTransport::onServiceUnregistered(const QString& /*service*/)
{
    // The agent (and with it, whatever it advertised) is gone: forget the
    // cached list and version so neither survives past a real death nor a
    // different-generation agent that re-registers with a different set —
    // the next registration re-seeds both via onServiceRegistered() above.
    m_managerPropertiesFetched = false;
    m_features.clear();
    m_agentVersion.clear();
    // Same "forget on death, re-fetch on the next connect" posture for
    // the cached appearance-font fd — a different-generation agent could
    // serve a different font, and a dead one's fd must never be handed out.
    m_appearanceFontFetched = false;
    m_appearanceFont = FdHandle{};
    // Ditto the settings snapshot: it described THAT agent's configuration,
    // and a client rendering a dead agent's TSA list as the live one is the
    // same lie the empty-when-absent rule prevents for the version above.
    m_configFetched = false;
    m_config.clear();
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
