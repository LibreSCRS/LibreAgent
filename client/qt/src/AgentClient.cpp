// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentClient.h>

#include <LibreSCRS/AgentClient/AgentOperation.h>

#include "ClientTestAccess.h"
#include "TransportSeam.h"

#if defined(Q_OS_LINUX)
#include "dbus/DBusTransport.h"
#endif

#include <QHash>
#include <QSet>

#include <algorithm>
#include <utility>

namespace LibreSCRS::AgentClient {

namespace {

/// The production transport for this platform: D-Bus on Linux; none elsewhere
/// yet (the socket transport lands in a later task). A transport-less client
/// is inert but well-behaved: never available, nothing installed, empty
/// registry.
std::unique_ptr<TransportSeam> createDefaultTransport()
{
#if defined(Q_OS_LINUX)
    return std::make_unique<DBusTransport>();
#else
    return nullptr;
#endif
}

} // namespace

struct AgentClient::Private final : public RegistryListener
{
    AgentClient* q;
    std::unique_ptr<TransportSeam> transport;
    bool available = false;
    QHash<QString, AgentReader*> readers;
    QHash<QString, AgentCard*> cards;

    Private(AgentClient* owner, std::unique_ptr<TransportSeam> t) : q(owner), transport(std::move(t)) {}

    // ---- RegistryListener ----------------------------------------------------
    void onServiceRegistered() override
    {
        q->onServiceRegistered();
    }
    void onServiceUnregistered() override
    {
        q->onServiceUnregistered();
    }
    void onReaderAdded(const QString& readerId, const QVariantMap& properties) override
    {
        q->addReader(readerId, properties);
        Q_EMIT q->readersChanged();
    }
    void onCardAdded(const QString& cardId, const QVariantMap& properties) override
    {
        q->addCard(cardId, properties);
        Q_EMIT q->cardChanged(cardId);
    }
    void onReaderRemoved(const QString& readerId) override
    {
        if (readers.contains(readerId)) {
            q->removeReader(readerId);
            Q_EMIT q->readersChanged();
        }
    }
    void onCardRemoved(const QString& cardId) override
    {
        if (cards.contains(cardId)) {
            q->removeCard(cardId);
        }
    }
};

AgentClient::AgentClient(QObject* parent) : AgentClient(createDefaultTransport(), parent) {}

AgentClient::AgentClient(std::unique_ptr<TransportSeam> transport, QObject* parent)
    : QObject(parent), d(std::make_unique<Private>(this, std::move(transport)))
{
    if (!d->transport) {
        return;
    }
    d->transport->setRegistryListener(d.get());
    // If the agent is already reachable, populate now — a bounded probe, so a
    // wedged bus/agent can only stall construction for the handshake budget.
    if (d->transport->probeAvailability()) {
        d->available = true;
        repopulate();
    }
}

AgentClient::~AgentClient()
{
    // Children (operations, then readers/cards) unsubscribe from the transport
    // in their dtors, but the QObject base dtor would destroy them only AFTER
    // `d` (and with it the transport) is gone. Delete them here, while the
    // transport is still alive. Operations first: deleting a card would
    // delete its parented operations anyway, but doing it explicitly keeps
    // one order for card-parented and client-parented (DER) operations alike.
    const QList<AgentOperation*> operations = findChildren<AgentOperation*>();
    for (AgentOperation* operation : operations) {
        delete operation;
    }
    clearRegistry();
}

bool AgentClient::isAvailable() const
{
    return d->available;
}

bool AgentClient::agentInstalled() const
{
    return d->transport && d->transport->agentInstalled();
}

void AgentClient::refreshDiscovery()
{
    if (!d->transport) {
        Q_EMIT readersChanged();
        return;
    }
    // Re-probe with the SAME bounded probe the ctor uses rather than trusting
    // the cached flag: a liveness notification can be missed, so a manual
    // refresh must reconcile availability from the transport itself before
    // deciding what to do.
    if (d->transport->probeAvailability()) {
        const bool wasAvailable = d->available;
        d->available = true;
        // Re-run discovery: picks up any card the agent has since exported
        // whose add notification we never received (the deferred-publish
        // window, or a genuinely dropped signal).
        repopulate(); // emits readersChanged()
        if (!wasAvailable) {
            Q_EMIT availabilityChanged(true);
        }
        return;
    }

    // The agent is not reachable. If we still thought it was, terminalize like
    // a live unregistration would: drop the registry and report unavailable.
    if (d->available) {
        onServiceUnregistered();
    } else {
        // Already-unavailable -> still let consumers recompute (e.g. re-detect
        // whether the agent is now installed) via a roster refresh.
        Q_EMIT readersChanged();
    }
}

QList<AgentReader*> AgentClient::readers() const
{
    // Deterministic: sort reader ids, never rely on hash iteration order.
    QList<QString> ids = d->readers.keys();
    std::sort(ids.begin(), ids.end());
    QList<AgentReader*> ordered;
    ordered.reserve(ids.size());
    for (const QString& id : std::as_const(ids)) {
        if (AgentReader* trackedReader = d->readers.value(id, nullptr)) {
            ordered.append(trackedReader);
        }
    }
    return ordered;
}

AgentReader* AgentClient::reader(const QString& readerId) const
{
    return d->readers.value(readerId, nullptr);
}

AgentCard* AgentClient::card(const QString& cardId) const
{
    return d->cards.value(cardId, nullptr);
}

AgentOperation* AgentClient::certificateDer(const QString& readerId, const QString& certId)
{
    auto* operation = new AgentOperation(AgentOperation::Kind::CertificateDer, this);
    if (!d->transport || !d->available) {
        SeamError error;
        error.callError = CallError::AgentUnavailable;
        error.message = QStringLiteral("The card agent is not reachable.");
        operation->failEntry(error);
        return operation;
    }
    operation->startCertificateDer(d->transport.get(), readerId, certId);
    return operation;
}

void AgentClient::onServiceRegistered()
{
    if (d->available) {
        return;
    }
    d->available = true;
    repopulate();
    Q_EMIT availabilityChanged(true);
}

void AgentClient::onServiceUnregistered()
{
    if (!d->available) {
        return;
    }
    d->available = false;

    // Agent-death terminalization: the agent is gone, so no terminal signal
    // will ever arrive for any in-flight operation. Before tearing down the
    // card registry (which would silently destroy the AgentOperations,
    // auto-disconnecting their consumers WITHOUT firing finished — a consumer
    // that hangs forever), walk every live operation and terminalize it
    // loudly so each consumer's finished slot fires exactly once.
    //
    // Card operations are QObject-parented to their AgentCard (parented to
    // this client) and DER operations directly to this client, so
    // findChildren reaches them all. We snapshot the list first: terminate()
    // may re-enter (a consumer's finished slot could touch the client), and
    // terminate() itself is idempotent.
    const QList<AgentOperation*> live = findChildren<AgentOperation*>();
    for (AgentOperation* operation : live) {
        operation->terminate(OperationStatus::Cancelled, ErrorCode::CommunicationError, CallError::AgentUnavailable,
                             QString(), QStringLiteral("The card agent stopped responding."));
    }

    clearRegistry();
    Q_EMIT availabilityChanged(false);
    Q_EMIT readersChanged();
}

void AgentClient::clearRegistry()
{
    qDeleteAll(d->readers);
    d->readers.clear();
    qDeleteAll(d->cards);
    d->cards.clear();
}

void AgentClient::repopulate()
{
    const std::optional<RegistrySnapshot> snapshot = d->transport->fetchRegistry();
    if (!snapshot) {
        // Discovery failed (wedged/absent agent). RECONCILE, not rebuild:
        // leave the current registry untouched rather than nuking it — a
        // failed re-scan must not churn live objects (initial discovery
        // starts from an empty registry anyway). Still notify so consumers
        // recompute.
        Q_EMIT readersChanged();
        return;
    }

    QSet<QString> liveCardIds;
    for (const RegistryObject& object : snapshot->cards) {
        liveCardIds.insert(object.id);
    }
    QSet<QString> liveReaderIds;
    for (const RegistryObject& object : snapshot->readers) {
        liveReaderIds.insert(object.id);
    }

    // RECONCILE against the reported tree instead of clear-and-rebuild. Drop
    // only objects the agent no longer reports (removeCard terminalizes a
    // going-away card's in-flight ops, so a refresh mid-op never leaks one),
    // and add/update the rest IN PLACE: addCard/addReader primeFrom() an
    // existing id, so an UNCHANGED object keeps its identity (same pointer).
    // A consumer bound to it is then not forced to re-read an identical card
    // — the collateral flicker a refresh on one widget would inflict on all
    // the others.
    const QList<QString> knownCards = d->cards.keys();
    for (const QString& id : knownCards) {
        if (!liveCardIds.contains(id)) {
            removeCard(id); // terminalize + delete + cardChanged
        }
    }
    const QList<QString> knownReaders = d->readers.keys();
    for (const QString& id : knownReaders) {
        if (!liveReaderIds.contains(id)) {
            removeReader(id);
        }
    }

    // Cards first so a reader's card reference resolves immediately.
    for (const RegistryObject& object : snapshot->cards) {
        addCard(object.id, object.properties);
    }
    for (const RegistryObject& object : snapshot->readers) {
        addReader(object.id, object.properties);
    }

    Q_EMIT readersChanged();
}

void AgentClient::addReader(const QString& readerId, const QVariantMap& props)
{
    if (AgentReader* existing = d->readers.value(readerId, nullptr)) {
        // Re-add for an id we already track (the agent re-announcing an object
        // with changed props): UPDATE the live proxy from the new payload
        // rather than dropping it on the floor, so a state change is never
        // silently lost. primeFrom applies the subset present in `props`.
        existing->primeFrom(props);
        return;
    }
    auto* trackedReader = new AgentReader(d->transport.get(), this, readerId, this);
    trackedReader->primeFrom(props);
    connect(trackedReader, &AgentReader::changed, this, [this, readerId]() { Q_EMIT cardChanged(readerId); });
    d->readers.insert(readerId, trackedReader);
}

void AgentClient::addCard(const QString& cardId, const QVariantMap& props)
{
    if (AgentCard* existing = d->cards.value(cardId, nullptr)) {
        // Re-add for an already-tracked id: prime the existing card from the
        // new props so a changed capability set upgrades in place (otherwise
        // a stale card would never reflect the agent's re-announced state).
        existing->primeFrom(props);
        return;
    }
    auto* trackedCard = new AgentCard(d->transport.get(), cardId, this);
    trackedCard->primeFrom(props);
    d->cards.insert(cardId, trackedCard);
}

void AgentClient::removeCard(const QString& cardId)
{
    AgentCard* trackedCard = d->cards.take(cardId);
    if (trackedCard == nullptr) {
        return;
    }
    // The card is going away (a live removal notification, or a reconcile
    // that finds it gone from a fresh snapshot): no terminal signal will
    // arrive for any op in flight on it. Deleting the card would destroy its
    // QObject-parented operations, auto-disconnecting their consumers WITHOUT
    // firing finished — a consumer would hang forever. Mirror the
    // agent-death sweep: terminalize every live op first (idempotent via
    // emitFinishedOnce).
    const QList<AgentOperation*> live = trackedCard->findChildren<AgentOperation*>();
    for (AgentOperation* operation : live) {
        operation->terminate(OperationStatus::Cancelled, ErrorCode::CardRemoved, CallError::None, QString(),
                             QStringLiteral("The smart card was removed."));
    }
    delete trackedCard;
    Q_EMIT cardChanged(cardId);
}

void AgentClient::removeReader(const QString& readerId)
{
    delete d->readers.take(readerId);
}

// ---- ClientTestAccess -------------------------------------------------------

AgentClient* ClientTestAccess::create(std::unique_ptr<TransportSeam> transport, QObject* parent)
{
    return new AgentClient(std::move(transport), parent);
}

} // namespace LibreSCRS::AgentClient
