// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The QtDBus implementation of TransportSeam:
// the lifted client's proven D-Bus machinery (service watcher + ObjectManager
// discovery, capped discovery calls, bounded method-entry blocks, per-object
// PropertiesChanged tracking, per-operation Finished/Result subscription with
// the GetResult recovery pulls), with every QtDBus type scrubbed at this
// boundary — QDBusObjectPath -> opaque QString id, QDBusUnixFileDescriptor ->
// FdHandle, error-name strings -> SeamError (ErrorNameMap).
#include "../DerListenerRegistry.h"
#include "../TransportSeam.h"

#include "Marshal.h"

#include <QDBusConnection>
#include <QDBusObjectPath>
#include <QDBusUnixFileDescriptor>
#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVariantMap>

class QDBusServiceWatcher;

namespace LibreSCRS::AgentClient {

class DBusTransport;

/// One live PropertiesChanged subscription: a dedicated receiver per
/// subscribed object (mirroring the lifted per-proxy connection), so deleting
/// it on unsubscribe atomically drops the match rule with it.
class DBusPropertyWatch : public QObject
{
    Q_OBJECT
public:
    DBusPropertyWatch(QString objectId, ObjectKind objectKind, PropertyListener* propertyListener, QObject* parent);

    QString objectId;
    ObjectKind kind;
    PropertyListener* listener;

public Q_SLOTS:
    void onPropertiesChanged(const QString& iface, const QVariantMap& changed, const QStringList& invalidated);
};

/// One live operation subscription: Finished + Phase/Progress + the typed
/// Result signal of the operation's kind, forwarded scrubbed.
class DBusOperationWatch : public QObject
{
    Q_OBJECT
public:
    DBusOperationWatch(QString operationId, OperationKind operationKind, OperationListener* operationListener,
                       QObject* parent);

    QString operationId;
    OperationKind kind;
    OperationListener* listener;

public Q_SLOTS:
    void onFinished(uint status, uint errorCode, const QString& msgKey, const QString& msgFallback);
    void onPropertiesChanged(const QString& iface, const QVariantMap& changed, const QStringList& invalidated);
    void onSignResult(const QDBusUnixFileDescriptor& fd, const QVariantMap& meta);
    void onSignBatchResult(LibreSCRS::AgentClient::SignBatchRowsWire rows);
    void onIdentityResult(LibreSCRS::AgentClient::IdentityFieldsWire fields);
    // Progressive delivery: Operation.Identity1.Group(groupKey, fields).
    // Connected ONLY for OperationKind::Identity (see subscribeOperation) --
    // never for a GetPhoto/Sign/Certificates/Credentials op, whose object
    // never exports the Identity1 interface at all, so this signal simply
    // cannot arrive for them.
    void onIdentityGroup(QString groupKey, LibreSCRS::AgentClient::IdentityFieldGroupWire fields);
    void onCertificatesResult(LibreSCRS::AgentClient::CertListWire certificates);
    void onPhotoResult(LibreSCRS::AgentClient::PhotoMapWire photos);
    void onCredentialsResult(QVariantMap result, LibreSCRS::AgentClient::CredentialRecordsWire records);
};

class DBusTransport : public QObject, public TransportSeam
{
    Q_OBJECT
public:
    /// Production: the session bus + the agent's well-known name.
    DBusTransport();
    /// Any bus + service — the D-Bus integration suites bind this to a
    /// private test bus (via ClientTestAccess), replacing the lifted client's
    /// deleted connection-injection ctor.
    DBusTransport(const QDBusConnection& connection, const QString& service);
    ~DBusTransport() override;

    // TransportSeam
    void setRegistryListener(RegistryListener* listener) override;
    [[nodiscard]] bool probeAvailability() override;
    [[nodiscard]] bool agentInstalled() override;
    [[nodiscard]] std::optional<RegistrySnapshot> fetchRegistry() override;
    [[nodiscard]] QStringList features() const override;
    [[nodiscard]] std::optional<LayoutResult> layoutVisualSignature(const QString& text, QRectF box) override;
    [[nodiscard]] FdHandle appearanceFont() override;
    void subscribeProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener) override;
    void unsubscribeProperties(const QString& objectId, PropertyListener* listener) override;
    quint64 requestProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener) override;
    [[nodiscard]] StartOutcome startOperation(const QString& cardId, OperationRequest request) override;
    void subscribeOperation(const QString& operationId, OperationKind kind, OperationListener* listener) override;
    void unsubscribeOperation(const QString& operationId, OperationListener* listener) override;
    [[nodiscard]] std::optional<TerminalSnapshot> fetchOperationState(const QString& operationId) override;
    [[nodiscard]] std::optional<OperationPayload> fetchOperationResult(const QString& operationId,
                                                                       OperationKind kind) override;
    void cancelOperation(const QString& operationId) override;
    void warmCertificates(const QString& cardId) override;
    quint64 requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener) override;
    void cancelCertificateDer(quint64 token, DerListener* listener) override;

private Q_SLOTS:
    void onServiceRegistered(const QString& service);
    void onServiceUnregistered(const QString& service);
    void onInterfacesAdded(const QDBusObjectPath& path,
                           const LibreSCRS::AgentClient::AgentInterfaceProps& interfacesAndProperties);
    void onInterfacesRemoved(const QDBusObjectPath& path, const QStringList& interfaces);

private:
    /// Bounded NameHasOwner probe against the bus daemon (never the uncapped
    /// isServiceRegistered helper, which can block ~25 s against a wedged
    /// daemon and would freeze a running outer loop the whole time).
    [[nodiscard]] bool nameHasOwner();
    /// Re-read `Manager1.Features` (a bounded `Properties.GetAll` on the root
    /// path) into `m_features`, tolerating an agent that lacks the property —
    /// or Manager1 entirely — by leaving `m_features` empty. Called at most
    /// once per connect (guarded by `m_featuresFetched`), from `probeAvailability()`
    /// and `onServiceRegistered()` alike, so whichever path first observes the
    /// agent reachable seeds it.
    void refreshFeatures();

    QDBusConnection m_connection;
    QString m_service;
    QDBusServiceWatcher* m_watcher = nullptr;
    // Cards with a warm-certificates entry call still on the wire — the seam's
    // debounce contract (see TransportSeam::warmCertificates). Keyed by card
    // id and cleared by the entry call's own reply, so the guard can never
    // outlive the call it guards.
    QSet<QString> m_warmingCards;
    RegistryListener* m_registry = nullptr;
    QHash<PropertyListener*, DBusPropertyWatch*> m_propertyWatches;
    QHash<OperationListener*, DBusOperationWatch*> m_operationWatches;
    DerListenerRegistry m_derListeners;
    quint64 m_nextToken = 0; // requestProperties only — DER tokens live in m_derListeners
    QStringList m_features;
    bool m_featuresFetched = false; // reset on onServiceUnregistered — "once per connect"
    // The sealed appearance-font fd, cached per connection exactly like
    // m_features (fetched at most once per connect, reset on
    // onServiceUnregistered so a reconnect re-fetches rather than serving a
    // stale fd from a dead connection).
    FdHandle m_appearanceFont;
    bool m_appearanceFontFetched = false;
};

} // namespace LibreSCRS::AgentClient
