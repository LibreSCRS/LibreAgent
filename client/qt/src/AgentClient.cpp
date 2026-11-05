// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentClient.h>

#include <LibreSCRS/AgentClient/AgentOperation.h>

#if defined(LIBREAGENT_CLIENT_TESTING)
#include "ClientTestAccess.h"
#endif
#include "TransportSeam.h"

#if defined(Q_OS_LINUX)
#include "dbus/DBusTransport.h"
#elif defined(Q_OS_MACOS)
#include "socket/MacAgentHost.h"
#include "socket/SocketTransport.h"
#endif

#include <QHash>
#include <QLoggingCategory>
#include <QScopeGuard>
#include <QSet>

#include <algorithm>
#include <utility>

namespace LibreSCRS::AgentClient {

namespace {
Q_LOGGING_CATEGORY(lcAgentClient, "librescrs.agentclient.client")

/// The production transport for this platform: D-Bus on Linux, the App-Group
/// socket on macOS. A platform with neither gets a transport-less client, which
/// is inert but well-behaved: never available, nothing installed, empty
/// registry.
std::unique_ptr<TransportSeam> createDefaultTransport()
{
#if defined(LIBREAGENT_CLIENT_TESTING)
    // The testing archive's one seam: a transport ClientTestAccess::create()
    // handed over for the client it is constructing (nullptr included, for a
    // transport-less client). The shipped library is built without it.
    if (std::optional<std::unique_ptr<TransportSeam>> injected = takeInjectedTransport()) {
        return std::move(*injected);
    }
#endif
#if defined(Q_OS_LINUX)
    return std::make_unique<DBusTransport>();
#elif defined(Q_OS_MACOS)
    return std::make_unique<SocketTransport>();
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

    /// The one gate every agent-addressed call goes through: an agent that is
    /// installed but stopped is started here, and nowhere else. True when the
    /// agent is reachable afterwards.
    bool ensureAgent()
    {
        if (available) {
            return true;
        }
        if (!transport) {
            return false;
        }
        if (startOnce() == AgentStartResult::Running) {
            q->onServiceRegistered();
        }
        return available;
    }
    AgentStartResult lastStart = AgentStartResult::NotInstalled;
    AgentState state = AgentState::Missing;
    /// A start is in flight: its wait runs a local event loop, and a second
    /// click or a timer can call back in from there.
    bool starting = false;
    /// A gesture asked for from the event loop is queued or running; until it
    /// ends, asking again asks for nothing more.
    bool startLaterPending = false;
    bool refreshLaterPending = false;

    /// The transport's start, one at a time. A call made while one is in
    /// flight sends nothing and learns nothing: it answers `Requested`, since
    /// the start it would have asked for is already asked for, and the one in
    /// flight reports what came of it.
    AgentStartResult startOnce()
    {
        if (starting) {
            return AgentStartResult::Requested;
        }
        starting = true;
        // Cleared however the start ends: a start that threw is not in flight.
        const auto done = qScopeGuard([this] { starting = false; });
        const AgentStartResult result = transport->startAgent();
        learnFrom(result);
        return result;
    }

    /// What a start attempt taught about the agent.
    void learnFrom(AgentStartResult result)
    {
        lastStart = result;
        switch (result) {
        case AgentStartResult::Running:
            state = AgentState::Ready;
            break;
        case AgentStartResult::Requested:
        case AgentStartResult::Failed:
            state = AgentState::Stopped;
            break;
        case AgentStartResult::NotInstalled:
        case AgentStartResult::NotInApplications:
            state = AgentState::Missing;
            break;
        }
    }

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
    void onConfigChanged(const QString& key) override
    {
        // Nothing to reconcile here: the transport refreshed its snapshot
        // before calling, so this is a pure re-broadcast — a slot reading
        // configSnapshot() sees the new value.
        Q_EMIT q->configChanged(key);
    }
};

AgentClient::AgentClient(QObject* parent)
    : QObject(parent), d(std::make_unique<Private>(this, createDefaultTransport()))
{
    if (!d->transport) {
        return;
    }
    d->transport->setRegistryListener(d.get());
    // If the agent is already reachable, populate now — a bounded probe, so a
    // wedged bus/agent can only stall construction for the handshake budget.
    if (d->transport->probeAvailability()) {
        d->available = true;
        d->state = AgentState::Ready;
        repopulate();
        return;
    }
    // Learned once here and kept current from then on, so the getters a view
    // calls while it repaints never reach the bus (agentState()).
    d->state = d->transport->agentInstalled() ? AgentState::Stopped : AgentState::Missing;
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

AgentState AgentClient::agentState() const
{
    return d->state;
}

QString AgentClient::installHelpUrl(const QLocale& locale)
{
    const bool serbian = locale.language() == QLocale::Serbian;
#if defined(Q_OS_MACOS)
    // On macOS the agent comes with the LibreMac host app.
    return serbian ? QStringLiteral("https://librescrs.github.io/sr/user-guide/install-libremac/")
                   : QStringLiteral("https://librescrs.github.io/user-guide/install-libremac/");
#else
    return serbian ? QStringLiteral("https://librescrs.github.io/sr/user-guide/install-agent/")
                   : QStringLiteral("https://librescrs.github.io/user-guide/install-agent/");
#endif
}

QStringList AgentClient::features() const
{
    return d->transport ? d->transport->features() : QStringList();
}

bool AgentClient::hasFeature(const QString& token) const
{
    return features().contains(token);
}

QString AgentClient::agentVersion() const
{
    // Same shape as features() above, and for the same reason: the seam owns
    // both the capture and the forget-on-loss, so there is nothing to gate
    // here — a transport-less client reads empty, which is exactly what an
    // unreachable agent reads.
    return d->transport ? d->transport->agentVersion() : QString();
}

QVariantMap AgentClient::configSnapshot() const
{
    // An unreachable agent reads empty, exactly like features()/agentVersion();
    // a stopped one is started first, like every other agent-addressed call.
    return d->ensureAgent() ? d->transport->configSnapshot() : QVariantMap();
}

std::optional<SyncError> AgentClient::setConfigValue(const QString& key, const QVariant& value)
{
    if (!d->ensureAgent()) {
        // A write cannot be "refused" by an agent that was never reached, and
        // the caller's whole reason for a named error is to tell the two
        // apart: this is the never-arrived class, the retryable one.
        return SyncError::CommunicationError;
    }
    return d->transport->setConfig(key, value);
}

std::optional<SyncError> AgentClient::resetConfigValue(const QString& key)
{
    if (!d->ensureAgent()) {
        return SyncError::CommunicationError;
    }
    return d->transport->resetConfig(key);
}

std::expected<CscaAnchorState, SyncError> AgentClient::importCscaMasterList(int masterListFd)
{
    if (!d->ensureAgent()) {
        return std::unexpected(SyncError::CommunicationError);
    }
    // No local validation of the descriptor here, deliberately. Whether it is
    // a regular file, readable, or within the size bound is the AGENT's
    // decision — it is the process that reads it, under its own limits — and a
    // second opinion computed here could only either agree (dead code) or
    // disagree (a refusal the agent never made, in the agent's vocabulary).
    return d->transport->importCscaMasterList(masterListFd);
}

std::optional<LayoutResult> AgentClient::layoutVisualSignature(const QString& text, QRectF box) const
{
    // Transport-neutral local refusal, mirroring AgentCard::startOperation's
    // tsaUrl/visualSignature gate — WITHOUT ever dialing the wire. There is
    // no AgentOperation here to fail entry on, so the refusal shape is
    // simply "no result", exactly like hasFeature() itself degrades an
    // absent agent to an empty features() list rather than an error.
    if (!d->ensureAgent() || !hasFeature(QStringLiteral("layout-preview"))) {
        return std::nullopt;
    }
    return d->transport->layoutVisualSignature(text, box);
}

FdHandle AgentClient::appearanceFont() const
{
    if (!d->ensureAgent() || !hasFeature(QStringLiteral("layout-preview"))) {
        return {};
    }
    return d->transport->appearanceFont();
}

void AgentClient::refreshDiscovery()
{
    if (!d->transport) {
        Q_EMIT readersChanged();
        return;
    }
    // Re-probe rather than trusting the cached flag: a liveness notification
    // can be missed, so a manual refresh must reconcile availability from the
    // transport itself before deciding what to do. This is a gesture, so the
    // probe is the starting one: an installed agent that is not running is
    // brought up here, which is what a "try again" control is for.
    const AgentStartResult started = d->startOnce();
    if (started == AgentStartResult::Requested && d->starting) {
        // Called back from inside a start in flight, which ends with its own
        // availability change or roster refresh.
        return;
    }
    if (started == AgentStartResult::Running) {
        if (!d->available) {
            // Just became reachable: the same path a registration takes, so a
            // settings snapshot taken while it was down is read again too.
            onServiceRegistered();
            return;
        }
        // Re-run discovery: picks up any card the agent has since exported
        // whose add notification we never received (the deferred-publish
        // window, or a genuinely dropped signal).
        repopulate(); // emits readersChanged()
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

AgentStartResult AgentClient::requestAgentStart()
{
    if (d->ensureAgent()) {
        return AgentStartResult::Running;
    }
    if (d->starting) {
        // Re-entered while a start is in flight: that start is the answer.
        return AgentStartResult::Requested;
    }
#if defined(Q_OS_MACOS)
    // The macOS agent is a launchd job its host app registers, so "start" is
    // launching that app and kicking the job; it answers later, not here.
    if (d->transport) {
        d->learnFrom(startMacAgentHost());
        return d->lastStart;
    }
#endif
    return d->transport ? d->lastStart : AgentStartResult::NotInstalled;
}

void AgentClient::requestAgentStartLater()
{
    if (d->startLaterPending) {
        return;
    }
    d->startLaterPending = true;
    // Queued on this client, so the caller's frame -- the clicked handler of a
    // control the agent's arrival may destroy -- is gone before the start
    // waits; dropped with the client if it goes first.
    QMetaObject::invokeMethod(
        this,
        [this] {
            AgentStartResult result = AgentStartResult::Failed;
            {
                const auto done = qScopeGuard([this] { d->startLaterPending = false; });
                result = requestAgentStart();
            }
            Q_EMIT agentStartFinished(result);
        },
        Qt::QueuedConnection);
}

void AgentClient::refreshDiscoveryLater()
{
    if (d->refreshLaterPending) {
        return;
    }
    d->refreshLaterPending = true;
    QMetaObject::invokeMethod(
        this,
        [this] {
            const auto done = qScopeGuard([this] { d->refreshLaterPending = false; });
            refreshDiscovery();
        },
        Qt::QueuedConnection);
}

AgentOperation* AgentClient::certificateDer(const QString& readerId, const QString& certId)
{
    auto* operation = new AgentOperation(AgentOperation::Kind::CertificateDer, this);
    if (!d->ensureAgent()) {
        SeamError error;
        error.callError = CallError::AgentUnavailable;
        error.message = QStringLiteral("The card agent is not reachable.");
        // The agent's error name/message is the only prose record of why — a
        // local refusal never reached the wire, so log the same fields
        // AgentCard::startOperation logs for its own entry-refusal path.
        qCWarning(lcAgentClient).noquote()
            << "certificateDer refused for" << readerId << certId << ':' << error.message;
        operation->failEntry(error);
        return operation;
    }
    operation->startCertificateDer(d->transport.get(), readerId, certId);
    return operation;
}

void AgentClient::onServiceRegistered()
{
    d->state = AgentState::Ready;
    if (d->available) {
        return;
    }
    d->available = true;
    repopulate();
    Q_EMIT availabilityChanged(true);
    // A consumer holding a settings snapshot took it while the agent was not
    // reachable, so it is empty: tell it to read again.
    Q_EMIT configChanged(QString());
}

void AgentClient::onServiceUnregistered()
{
    if (!d->available) {
        return;
    }
    d->available = false;
    // It ran, so it is installed; whether it still is, the next refresh says.
    d->state = AgentState::Stopped;

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

} // namespace LibreSCRS::AgentClient
