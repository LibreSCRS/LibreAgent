// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end corpus over the REAL SocketTransport + a FakeSocketAgent on a
// temp AF_UNIX path — the socket mirror of the D-Bus integration corpus
// (availability incl. the HelloAck version/feature capture, discovery from
// GetState + live events, identity, photo fd content-hash, certificates,
// sign fd in/out + meta, credentials list/manage/re-list, cancel, the
// op-stall contract, and lost-result recovery through the GetSignResult
// window) PLUS the socket-specific cases: feature-token gating, agent close
// mid-operation, the non-canonical-frame fail-closed policy, and
// AgentQuiesced availability semantics.
//
// The fake lives on a worker thread with its own event loop (the same
// two-thread arrangement the D-Bus suites' Harness uses, for the same
// reason): the transport under test answers its bounded synchronous calls
// with a deadline poll that deliberately runs no event loop, so an
// in-process peer must be served from another thread.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/ClientTimeouts.h>
#include <LibreSCRS/AgentClient/IdentityRows.h>

#include "ClientTestAccess.h"
#include "fakes/FakeSocketAgent.h"
#include "socket/MemfdSource.h"
#include "socket/SocketPath.h"
#include "socket/SocketTransport.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDeadlineTimer>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QMetaObject>
#include <QTemporaryDir>
#include <QThread>
#include <QVariant>

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <optional>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {

/// Spin the main-thread event loop until @p pred is true or timeout.
template <typename Pred>
bool waitFor(Pred pred, int timeoutMs = 4000)
{
    QDeadlineTimer deadline(timeoutMs);
    while (!pred() && !deadline.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(1);
    }
    return pred();
}

/// Run @p fn on @p target's thread and block until it returns.
template <typename Fn>
void runOnThread(QObject* target, Fn&& fn)
{
    QMetaObject::invokeMethod(target, std::forward<Fn>(fn), Qt::BlockingQueuedConnection);
}

/// Owns the worker thread hosting the FakeSocketAgent, plus the temp socket
/// path. Scripting/capture calls are marshaled onto the fake's thread — the
/// same discipline as the D-Bus suites' Harness.
class SocketHarness
{
public:
    explicit SocketHarness(FakeSocketAgent::Config config)
        // An explicit short /tmp template: AF_UNIX sun_path is ~107 bytes and
        // the ambient TMPDIR can be arbitrarily deep.
        : m_dir(QStringLiteral("/tmp/laqt-sock-XXXXXX"))
    {
        EXPECT_TRUE(m_dir.isValid());
        m_path = m_dir.path() + QStringLiteral("/agent.sock");
        config.socketPath = m_path;

        m_thread = new QThread();
        m_thread->start();
        m_context = new QObject();
        m_context->moveToThread(m_thread);

        bool listening = false;
        runOnThread(m_context, [this, &config, &listening]() {
            m_agent = std::make_unique<FakeSocketAgent>(config);
            listening = m_agent->listening();
        });
        EXPECT_TRUE(listening) << "could not bind " << m_path.toStdString();
    }

    ~SocketHarness()
    {
        runOnThread(m_context, [this]() { m_agent.reset(); });
        m_context->deleteLater();
        m_thread->quit();
        m_thread->wait();
        delete m_thread;
    }

    [[nodiscard]] QString path() const
    {
        return m_path;
    }

    void stopListening()
    {
        runOnThread(m_context, [this]() { m_agent->stopListening(); });
    }
    void relisten()
    {
        runOnThread(m_context, [this]() { m_agent->relisten(); });
    }
    void closeAllConnections()
    {
        runOnThread(m_context, [this]() { m_agent->closeAllConnections(); });
    }
    [[nodiscard]] int connectionCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->connectionCount(); });
        return out;
    }
    void setCardPresent(bool present)
    {
        runOnThread(m_context, [this, present]() { m_agent->setCardPresent(present); });
    }
    void emitCardCapabilitiesChanged(quint32 capabilities)
    {
        runOnThread(m_context, [this, capabilities]() { m_agent->emitCardCapabilitiesChanged(capabilities); });
    }
    void sendAgentQuiesced(quint32 reason)
    {
        runOnThread(m_context, [this, reason]() { m_agent->sendAgentQuiesced(reason); });
    }
    void sendNonCanonicalFrame()
    {
        runOnThread(m_context, [this]() { m_agent->sendNonCanonicalFrame(); });
    }
    void setNonCanonicalAfterStateReply()
    {
        runOnThread(m_context, [this]() { m_agent->config().nonCanonicalAfterStateReply = true; });
    }
    [[nodiscard]] int operationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->operationCount(); });
        return out;
    }
    [[nodiscard]] int cancelledOperationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->cancelledOperationCount(); });
        return out;
    }
    [[nodiscard]] int listCredentialsCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->listCredentialsCount(); });
        return out;
    }
    [[nodiscard]] int getSignResultCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->getSignResultCount(); });
        return out;
    }
    [[nodiscard]] int getConfigCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->getConfigCount(); });
        return out;
    }
    [[nodiscard]] int configMutationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->configMutationCount(); });
        return out;
    }
    [[nodiscard]] QVariant configValue(const QString& key)
    {
        QVariant out;
        runOnThread(m_context, [this, &key, &out]() { out = m_agent->configValue(key); });
        return out;
    }
    void emitConfigChanged(const QString& key)
    {
        runOnThread(m_context, [this, &key]() { m_agent->emitConfigChanged(key); });
    }
    [[nodiscard]] QString lastSignCertId()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignCertId(); });
        return out;
    }
    [[nodiscard]] QByteArray lastSignInputBytes()
    {
        QByteArray out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignInputBytes(); });
        return out;
    }
    [[nodiscard]] QVariantMap lastSignOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignOptions(); });
        return out;
    }
    [[nodiscard]] QString lastSignBatchCertId()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchCertId(); });
        return out;
    }
    [[nodiscard]] QVariantMap lastSignBatchOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchOptions(); });
        return out;
    }
    [[nodiscard]] QStringList lastSignBatchDisplayNames()
    {
        QStringList out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchDisplayNames(); });
        return out;
    }
    [[nodiscard]] QList<QByteArray> lastSignBatchDocumentBytes()
    {
        QList<QByteArray> out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchDocumentBytes(); });
        return out;
    }
    [[nodiscard]] QString lastCertDerReader()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastCertDerReader(); });
        return out;
    }
    [[nodiscard]] QString lastCertDerCertId()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastCertDerCertId(); });
        return out;
    }
    [[nodiscard]] std::optional<bool> lastManagePinActivateKey()
    {
        std::optional<bool> out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastManagePinActivateKey(); });
        return out;
    }
    [[nodiscard]] QVariantMap lastManagePinOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastManagePinOptions(); });
        return out;
    }

private:
    QTemporaryDir m_dir;
    QString m_path;
    QThread* m_thread = nullptr;
    QObject* m_context = nullptr;
    std::unique_ptr<FakeSocketAgent> m_agent;
};

/// Build a production AgentClient over a real SocketTransport bound to the
/// harness's socket. @p transportOut (optional) observes the transport the
/// client took ownership of — for HelloAck-capture assertions.
std::unique_ptr<AgentClient> makeClient(SocketHarness& harness, SocketTransport** transportOut = nullptr)
{
    auto transport = std::make_unique<SocketTransport>(harness.path());
    if (transportOut != nullptr) {
        *transportOut = transport.get();
    }
    return std::unique_ptr<AgentClient>(ClientTestAccess::create(std::move(transport)));
}

constexpr const char* kCardId = "card/0";
constexpr const char* kReaderId = "reader/0";

} // namespace

// ---- socket path resolution ---------------------------------------------------

TEST(SocketIntegration, SocketPathResolutionOrder)
{
    const QByteArray saved = qgetenv(kAgentSocketEnvVar);
    qputenv(kAgentSocketEnvVar, "/tmp/laqt-resolution-test.sock");
    EXPECT_EQ(resolveAgentSocketPath(), QStringLiteral("/tmp/laqt-resolution-test.sock"));
    qunsetenv(kAgentSocketEnvVar);
#if !defined(Q_OS_DARWIN)
    // No production default on this platform — tests always set the override.
    EXPECT_TRUE(resolveAgentSocketPath().isEmpty());
#endif
    if (!saved.isEmpty()) {
        qputenv(kAgentSocketEnvVar, saved);
    }
}

// ---- availability: handshake capture, vanish, reappear -------------------------

TEST(SocketIntegration, AvailabilityHandshakeFeatureTokensAndReappear)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.agentVersion = QStringLiteral("9.9-socket-fake");
    SocketHarness h(cfg);

    SocketTransport* transport = nullptr;
    auto client = makeClient(h, &transport);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_TRUE(client->agentInstalled());
    ASSERT_EQ(client->readers().size(), 1);

    // The HelloAck capture: agent version + feature tokens.
    ASSERT_NE(transport, nullptr);
    EXPECT_TRUE(transport->isConnected());
    EXPECT_EQ(transport->agentVersion(), QStringLiteral("9.9-socket-fake"));
    EXPECT_TRUE(transport->hasFeature(QLatin1StringView("credentials")));
    // The PUBLIC AgentClient surface (not just the transport-internal one)
    // must see the identical HelloAck-captured set.
    EXPECT_TRUE(client->features().contains(QStringLiteral("credentials")));
    EXPECT_TRUE(client->hasFeature(QStringLiteral("credentials")));

    bool sawUnavailable = false;
    bool sawAvailable = false;
    QObject::connect(client.get(), &AgentClient::availabilityChanged, client.get(),
                     [&](bool available) { (available ? sawAvailable : sawUnavailable) = true; });

    // Vanish: the agent process dies — its connections close AND the bound
    // socket disappears from disk.
    h.closeAllConnections();
    h.stopListening();
    ASSERT_TRUE(waitFor([&]() { return sawUnavailable; }));
    EXPECT_FALSE(client->isAvailable());
    EXPECT_TRUE(client->readers().isEmpty());
    EXPECT_FALSE(client->agentInstalled()) << "the unbound socket path must read as not-installed";

    // Reappear: the agent re-binds; there is no bus daemon to push a
    // registration, so the reconcile probe (refreshDiscovery) reconnects.
    h.relisten();
    client->refreshDiscovery();
    EXPECT_TRUE(sawAvailable);
    EXPECT_TRUE(client->isAvailable());
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 1; }))
        << "re-appearance must re-run discovery, not just flip the flag";
    EXPECT_NE(client->card(QLatin1String(kCardId)), nullptr);
}

// An unrecognised EXTRA feature token (one this client build does not name) is
// the CDDL-sanctioned forward-compatibility case: it must surface through the
// public API unfiltered rather than being dropped, and hasFeature() resolves
// exactly the scripted set.
TEST(SocketIntegration, FeaturesIncludeUnknownExtraToken)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("a-future-token-this-build-does-not-name")};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    const QStringList features = client->features();
    EXPECT_EQ(features.size(), 2);
    EXPECT_TRUE(client->hasFeature(QStringLiteral("credentials")));
    EXPECT_TRUE(client->hasFeature(QStringLiteral("a-future-token-this-build-does-not-name")));
    EXPECT_FALSE(client->hasFeature(QStringLiteral("nonexistent-token")));
}

// ---- agent version: the HelloAck agentVer, on the PUBLIC surface -----------
//
// AvailabilityHandshakeFeatureTokensAndReappear above already asserts the
// transport-internal capture (transport->agentVersion()); this pins the
// public AgentClient surface the GUI consumers read, plus the other half of
// its contract — EMPTY once the connection is gone, so a dead agent's version
// is never rendered as if it were live. The D-Bus twin is
// DBusIntegrationTest's AgentVersion* pair; TransportParityTest's own pair
// proves the two wires converge.
TEST(SocketIntegration, AgentVersionFromHelloAckAndEmptyOnceGone)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.agentVersion = QStringLiteral("9.9-socket-fake");
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(client->agentVersion(), QStringLiteral("9.9-socket-fake"));

    // The agent dies: its connections close AND the bound socket disappears.
    h.closeAllConnections();
    h.stopListening();
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(client->agentVersion().isEmpty());

    // The reconnect's own HelloAck re-seeds it.
    h.relisten();
    client->refreshDiscovery();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(client->agentVersion(), QStringLiteral("9.9-socket-fake"));
}

// ---- Config1 over the socket wire ---------------------------------------------
//
// The same client contract DBusIntegrationTest's Config* cases pin, over a
// wire with two structural differences the D-Bus side does not have:
//
//   * `set-config`'s grammar takes a `settable-config-key` ONLY, so a
//     non-settable (or unknown) key cannot be ENCODED at all. The transport
//     therefore refuses it locally, before building a frame — and the
//     mutation counter proves it never dialed the wire, the same way
//     layoutCallCount() proves the layout-preview gate does not.
//     `reset-config` is deliberately different: its argument is the FULL
//     `config-key` set, so a read-only key IS encodable there and the agent
//     is the one that names the refusal.
//   * a config value is typed `any`, not D-Bus's declared `a(sbb)`, so the
//     canonical TslSources row shape is the CLIENT's guarantee rather than
//     the wire's.

TEST(SocketIntegration, ConfigSnapshotCarriesTypedEntriesFromGetConfig)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    const QVariantMap config = client->configSnapshot();
    EXPECT_EQ(config.value(QStringLiteral("DefaultLevel")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(config.value(QStringLiteral("TsaUrls")).toStringList(),
              QStringList{QStringLiteral("https://tsa.example.invalid/tsr")});
    EXPECT_EQ(config.value(QStringLiteral("PluginDir")).toString(), QStringLiteral("/usr/lib/librescrs/plugins"));

    const QVariantList tslSources = config.value(QStringLiteral("TslSources")).toList();
    ASSERT_EQ(tslSources.size(), 1);
    const QVariantList row = tslSources.first().toList();
    ASSERT_EQ(row.size(), 3);
    EXPECT_EQ(row.at(0).toString(), QStringLiteral("https://example.invalid/tl.xml"));
    EXPECT_FALSE(row.at(1).toBool());
    EXPECT_TRUE(row.at(2).toBool());

    // Cached per connection: a second read must not re-dial GetConfig.
    EXPECT_EQ(client->configSnapshot(), config);
    EXPECT_EQ(h.getConfigCount(), 1);
}

// The `any`-typed value, served in the OTHER lawful encoding this wire admits
// (an array of maps rather than of three-entry arrays). The client normalizes
// both onto one shape — the whole reason `configSnapshot()` can promise a
// consumer anything at all here.
TEST(SocketIntegration, TslSourcesNormalizeFromTheMapEncodingToo)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.tslSourcesAsMaps = true;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    const QVariantList tslSources = client->configSnapshot().value(QStringLiteral("TslSources")).toList();
    ASSERT_EQ(tslSources.size(), 1);
    const QVariantList row = tslSources.first().toList();
    ASSERT_EQ(row.size(), 3) << "the map encoding must normalize to the SAME three-entry row";
    EXPECT_EQ(row.at(0).toString(), QStringLiteral("https://example.invalid/tl.xml"));
    EXPECT_FALSE(row.at(1).toBool());
    EXPECT_TRUE(row.at(2).toBool());
}

TEST(SocketIntegration, SetConfigRoundTripsAndSignalsConfigChanged)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_FALSE(client->configSnapshot().isEmpty());

    QStringList announced;
    QString seenFromSlot;
    QObject::connect(client.get(), &AgentClient::configChanged, client.get(), [&](const QString& key) {
        announced.append(key);
        seenFromSlot = client->configSnapshot().value(key).toString();
    });

    EXPECT_EQ(client->setConfigValue(QStringLiteral("DefaultReason"), QStringLiteral("approval")), std::nullopt);
    ASSERT_TRUE(waitFor([&]() { return !announced.isEmpty(); }));
    EXPECT_EQ(announced.constFirst(), QStringLiteral("DefaultReason"));
    // The ConfigChanged event carries only the key, so the transport owes the
    // re-read BEFORE it announces — a slot reading the snapshot sees the new
    // value, never the one the cache held when the event arrived.
    EXPECT_EQ(seenFromSlot, QStringLiteral("approval"));
    EXPECT_EQ(h.configValue(QStringLiteral("DefaultReason")).toString(), QStringLiteral("approval"));
}

TEST(SocketIntegration, SetConfigRefusesANonSettableOrUnknownKeyLocally)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    const std::optional<SyncError> readOnly =
        client->setConfigValue(QStringLiteral("PluginDir"), QStringLiteral("/tmp/x"));
    ASSERT_TRUE(readOnly.has_value());
    EXPECT_EQ(*readOnly, SyncError::ReadOnlyConfig);

    const std::optional<SyncError> unknown = client->setConfigValue(QStringLiteral("NoSuchKey"), QStringLiteral("x"));
    ASSERT_TRUE(unknown.has_value());
    EXPECT_EQ(*unknown, SyncError::UnknownConfigKey);

    EXPECT_EQ(h.configMutationCount(), 0)
        << "a key this wire's set-config grammar cannot encode must be refused before any frame is built";
}

// Reset's own grammar admits the full config-key set, so the read-only
// verdict comes from the AGENT here — the one config verb where the two wires
// agree on the mechanism as well as the outcome.
TEST(SocketIntegration, ResetConfigForAReadOnlyKeyReachesTheAgentAndIsRefused)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    const std::optional<SyncError> readOnly = client->resetConfigValue(QStringLiteral("PluginDir"));
    ASSERT_TRUE(readOnly.has_value());
    EXPECT_EQ(*readOnly, SyncError::ReadOnlyConfig);
    EXPECT_EQ(h.configMutationCount(), 1) << "reset-config CAN encode a read-only key, so it is sent";

    // An unknown key is outside `config-key` entirely and stays local.
    const std::optional<SyncError> unknown = client->resetConfigValue(QStringLiteral("NoSuchKey"));
    ASSERT_TRUE(unknown.has_value());
    EXPECT_EQ(*unknown, SyncError::UnknownConfigKey);
    EXPECT_EQ(h.configMutationCount(), 1);
}

// The snapshot describes the CONNECTED agent, so it must not survive the
// connection — and the next connect must re-read rather than serve the dead
// one's settings.
TEST(SocketIntegration, ConfigSnapshotEmptiesOnConnectionLossAndReSeeds)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_FALSE(client->configSnapshot().isEmpty());

    h.closeAllConnections();
    h.stopListening();
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(client->configSnapshot().isEmpty());

    h.relisten();
    client->refreshDiscovery();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(client->configSnapshot().value(QStringLiteral("DefaultLevel")).toString(), QStringLiteral("b-t"));
}

// ---- reader/card discovery from GetState ---------------------------------------

TEST(SocketIntegration, ReaderAndCardDiscovery)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData | Cap::Pki;
    cfg.preReadAuth = QStringLiteral("Can");
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    ASSERT_EQ(client->readers().size(), 1);
    AgentReader* reader = client->readers().constFirst();
    EXPECT_EQ(reader->id(), QLatin1String(kReaderId));
    EXPECT_EQ(reader->name(), QStringLiteral("Fake"));
    EXPECT_TRUE(reader->hasCard());
    EXPECT_EQ(reader->cardId(), QLatin1String(kCardId));

    AgentCard* card = reader->card();
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card, client->card(QLatin1String(kCardId)));
    EXPECT_EQ(card->readerId(), QLatin1String(kReaderId));
    EXPECT_EQ(card->preReadAuth(), QStringLiteral("Can"));
    EXPECT_EQ(uiStateFor(capabilityBits(card->capabilities())), UiState::Hybrid);
}

// ---- discovery follows live events ----------------------------------------------

TEST(SocketIntegration, LiveCardInsertPropertyChangeAndRemove)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.hasCard = false;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(client->readers().size(), 1);
    AgentReader* reader = client->readers().constFirst();
    EXPECT_FALSE(reader->hasCard());
    EXPECT_EQ(client->card(QLatin1String(kCardId)), nullptr);

    // Insert: CardAdded (card first) + the reader's PropertyChanged.
    h.setCardPresent(true);
    ASSERT_TRUE(waitFor([&]() { return reader->hasCard() && client->card(QLatin1String(kCardId)) != nullptr; }));
    EXPECT_EQ(reader->card(), client->card(QLatin1String(kCardId)));

    // A live capability change ships the FULL new value (no invalidation on
    // this wire) and applies without any fetch round-trip.
    h.emitCardCapabilitiesChanged(Cap::Pki | Cap::PinManagement);
    ASSERT_TRUE(waitFor([&]() {
        AgentCard* card = client->card(QLatin1String(kCardId));
        return card != nullptr && card->capabilities().contains(QStringLiteral("PinManagement"));
    }));

    // Remove: CardRemoved + the reader letting go.
    h.setCardPresent(false);
    ASSERT_TRUE(waitFor([&]() { return !reader->hasCard() && client->card(QLatin1String(kCardId)) == nullptr; }));
}

// ---- a wedged GetState stays bounded ---------------------------------------------

TEST(SocketIntegration, WedgedGetStateIsBoundedAndLeavesClientAvailable)
{
    FakeSocketAgent::Config cfg;
    cfg.wedgeGetState = true;
    SocketHarness h(cfg);

    QElapsedTimer timer;
    timer.start();
    auto client = makeClient(h);
    const qint64 elapsed = timer.elapsed();

    // The handshake answered (available), discovery timed out bounded at the
    // handshake budget and reconciled to an empty registry — no hang.
    EXPECT_TRUE(client->isAvailable());
    EXPECT_TRUE(client->readers().isEmpty());
    EXPECT_LT(elapsed, kDefaultCallTimeoutMs) << "discovery against a wedged agent must time out at ~1s, not hang";
}

// ---- identity ---------------------------------------------------------------------

TEST(SocketIntegration, IdentityReadDeliversGroupedFields)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 15;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // Through the public structural flattener: the wire metadata
    // (labelKey/labelFallback/type) must ride Field::extra under the
    // canonical keys, exactly as on the D-Bus transport.
    const QList<IdentityRow> rows = flattenIdentityFields(op->identityResult());
    const auto givenName = std::find_if(
        rows.cbegin(), rows.cend(), [](const IdentityRow& r) { return r.fieldKey == QStringLiteral("given_name"); });
    ASSERT_NE(givenName, rows.cend());
    EXPECT_EQ(givenName->groupKey, QStringLiteral("personal"));
    EXPECT_EQ(givenName->value, QStringLiteral("Ana"));
    EXPECT_EQ(givenName->labelKey, QStringLiteral("label_given_name"));
    EXPECT_EQ(givenName->labelFallback, QStringLiteral("Given name"));
}

// ReadTokenInfo rides the SAME Identity1-shaped op-result-ready arm as
// ReadIdentity — the FakeSocketAgent scripts a DISTINCT "token" group
// (label/serial_number/manufacturer), proving the client demarshals it
// correctly through the identical wire shape.
TEST(SocketIntegration, ReadTokenInfoDeliversTokenGroup)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    cfg.operationDelayMs = 15;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<FieldGroup> groups = op->identityResult();
    ASSERT_EQ(groups.size(), 1);
    EXPECT_EQ(groups.front().key, QStringLiteral("token"));
    const QList<Field>& fields = groups.front().fields;
    EXPECT_TRUE(
        std::any_of(fields.cbegin(), fields.cend(), [](const Field& f) { return f.key == QStringLiteral("label"); }));
    EXPECT_TRUE(std::any_of(fields.cbegin(), fields.cend(),
                            [](const Field& f) { return f.key == QStringLiteral("serial_number"); }));
    EXPECT_TRUE(std::any_of(fields.cbegin(), fields.cend(),
                            [](const Field& f) { return f.key == QStringLiteral("manufacturer"); }));
}

// The spec's empty-group resilience: an unsupported/best-effort-miss plugin
// answers a present-but-EMPTY "token" group — a SUCCESS, never an error.
TEST(SocketIntegration, ReadTokenInfoEmptyGroupIsStillSuccess)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    cfg.operationDelayMs = 15;
    cfg.tokenInfoEmpty = true;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->errorCode(), ErrorCode::None);
    EXPECT_TRUE(op->identityResult().isEmpty());
}

// Capability-refused entry: without the PKI bit, ReadTokenInfo throws
// UnsupportedOnThisCard at method entry (no Operation minted) — the fake
// enforces the real gate for real.
TEST(SocketIntegration, ReadTokenInfoRequiresPkiCapability)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData; // NO Pki
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr) << "a ReadTokenInfo that errors at entry mints a FAILED operation, never nullptr";
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
}

// Feature-gated entry: an agent predating the "token-info" surface has no
// such HelloAck token, so the client refuses locally rather than sending a
// request tag the agent would fail closed on (dropping the whole
// connection). The gate itself is transport-neutral (AgentCard::
// startOperation, not a socket-only special case any more) — this test's
// own socket-specific angle is the white-box SocketTransport::hasFeature()
// check plus proving the wire never sees the request on THIS transport; the
// D-Bus counterpart is DBusIntegrationTest's
// MissingTokenInfoFeatureRefusesLocally, and TransportParityTest.cpp's
// MissingTokenInfoFeatureRefusesIdenticallyAcrossTransports proves the two
// converge.
TEST(SocketIntegration, MissingTokenInfoFeatureTokenRefusesLocally)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "token-info"
    SocketHarness h(cfg);

    SocketTransport* transport = nullptr;
    auto client = makeClient(h, &transport);
    ASSERT_NE(transport, nullptr);
    EXPECT_FALSE(transport->hasFeature(QLatin1StringView("token-info")));
    EXPECT_FALSE(client->hasFeature(QStringLiteral("token-info")));

    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    // The gate is mandatory: the request must never have reached the wire (a
    // pre-contract agent would fail it closed and drop the WHOLE connection).
    EXPECT_EQ(h.operationCount(), 0);
    EXPECT_TRUE(client->isAvailable()) << "the local refusal must not cost the session";
}

// ---- photo: SCM_RIGHTS fd in-bound, content hash ------------------------------------

TEST(SocketIntegration, PhotoFdRoundTripContentHash)
{
    QByteArray photoBytes = QByteArrayLiteral("\x89PNG\r\n\x1a\n");
    for (int i = 0; i < 256; ++i) {
        photoBytes.append(static_cast<char>(i));
    }
    const QByteArray expectedHash = QCryptographicHash::hash(photoBytes, QCryptographicHash::Sha256);

    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 15;
    cfg.photoBytes = photoBytes;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    std::vector<PhotoItem> photos = op->takePhotos();
    ASSERT_EQ(photos.size(), 1u);
    EXPECT_EQ(photos[0].key, QStringLiteral("personal:photo"));
    ASSERT_TRUE(photos[0].fd.valid());

    const QByteArray received = readFdAll(photos[0].fd.get());
    EXPECT_EQ(received, photoBytes);
    EXPECT_EQ(QCryptographicHash::hash(received, QCryptographicHash::Sha256), expectedHash)
        << "the received FdHandle's content hash must match the agent-side bytes exactly";
}

// ---- certificates ---------------------------------------------------------------------

TEST(SocketIntegration, CertificatesEndToEnd)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    FakeSocketCert fc;
    fc.certId = QStringLiteral("cert-socket-1");
    fc.signingCapable = true;
    fc.subjectCn = QStringLiteral("Socket Signer");
    fc.issuerCn = QStringLiteral("Socket CA");
    fc.notBefore = QStringLiteral("2021-06-01T00:00:00Z");
    fc.notAfter = QStringLiteral("2031-06-01T00:00:00Z");
    fc.trustStatus = 0U; // Trusted
    cfg.certScript = {fc};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    const CertificateInfo& c = certs.constFirst();
    EXPECT_EQ(c.id, QStringLiteral("cert-socket-1"));
    EXPECT_TRUE(c.signingCapable);
    EXPECT_EQ(c.subject, QStringLiteral("Socket Signer"));
    EXPECT_EQ(c.issuer, QStringLiteral("Socket CA"));
    EXPECT_EQ(c.notBefore, QDateTime::fromString(QStringLiteral("2021-06-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.notAfter, QDateTime::fromString(QStringLiteral("2031-06-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.trust, TrustStatus::Trusted);
}

// The certificate warm is a DELIBERATE no-op on this wire, and this is the
// test that says so out loud, so a future reader finds a decision rather than
// an absence. The reasoning lives at SocketTransport::warmCertificates: a warm
// makes the agent mint a server-side operation whose id arrives only in a
// reply the warm discards, and this wire -- unlike the D-Bus one, where the
// agent reaps that operation with the card -- has no verb that lets go of an
// operation without cancelling the very read the warm exists to perform. So
// nothing is sent, and nothing is stranded.
//
// A warm is best-effort by contract, so the only consequence is that the next
// real read is cold -- which is asserted here too: the no-op must be a no-op,
// not a wedge. Calling it must leave the connection, the client and the next
// readCertificates() completely unaffected.
TEST(SocketIntegration, WarmCertificatesIsADeliberateNoOpAndDisturbsNothing)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    FakeSocketCert fc;
    fc.certId = QStringLiteral("cert-socket-warm");
    fc.signingCapable = true;
    cfg.certScript = {fc};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);
    ASSERT_EQ(h.operationCount(), 0);
    const int connectionsBefore = h.connectionCount();

    card->warmCertificates();
    card->warmCertificates();
    (void)waitFor([]() { return false; }, 250); // give any frame every chance to arrive

    EXPECT_EQ(h.operationCount(), 0) << "a warm must not reach this wire at all";
    EXPECT_TRUE(card->children().isEmpty());
    EXPECT_EQ(h.connectionCount(), connectionsBefore) << "a warm must not disturb the connection";
    EXPECT_TRUE(client->isAvailable());

    // The cold read the skipped warm leaves behind still works, unchanged --
    // which is exactly why the no-op costs no consumer anything.
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    ASSERT_EQ(op->certificatesResult().size(), 1);
    EXPECT_EQ(op->certificatesResult().constFirst().id, QStringLiteral("cert-socket-warm"));
    EXPECT_EQ(h.operationCount(), 1) << "only the real read reached the wire";
}

// Mirrors the D-Bus transport's own trust-verdict mapping tests
// (AgentCardTest.cpp) on the socket transport: 5=Revoked maps to the
// client's Revoked case, 6=OfflineUnverified and any value this build does
// not recognise both collapse to Unknown, and the "security" fields-group
// tokens land in CertificateInfo::securityStatus.
TEST(SocketIntegration, TrustStatusAndSecurityTokensMapAcrossTheVocabulary)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    FakeSocketCert revoked;
    revoked.certId = QStringLiteral("revoked-cert");
    revoked.trustStatus = 5U;
    revoked.securityStatus = QStringList{QStringLiteral("revoked")};
    FakeSocketCert offline;
    offline.certId = QStringLiteral("offline-cert");
    offline.trustStatus = 6U;
    offline.securityStatus = QStringList{QStringLiteral("offline-unverified")};
    FakeSocketCert future;
    future.certId = QStringLiteral("future-cert");
    future.trustStatus = 42U; // not yet defined by any agent build
    cfg.certScript = {revoked, offline, future};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 3);
    EXPECT_EQ(certs[0].trust, TrustStatus::Revoked);
    EXPECT_EQ(certs[0].securityStatus, (QStringList{QStringLiteral("revoked")}));
    EXPECT_EQ(certs[1].trust, TrustStatus::Unknown);
    EXPECT_EQ(certs[1].securityStatus, (QStringList{QStringLiteral("offline-unverified")}));
    EXPECT_EQ(certs[2].trust, TrustStatus::Unknown);
    EXPECT_TRUE(certs[2].securityStatus.isEmpty());
}

// ---- sign: typed options -> the CLOSED sign-opts map, fd in, artifact fd + meta out --

TEST(SocketIntegration, SignTypedOptionsToWireAndArtifactBack)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    // tsaUrl is gated on the "tsa-url" feature token (AgentCard::
    // startOperation) — script it so this exercises the wire encoding, not
    // the client's local refusal.
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("tsa-url")};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    const QByteArray document = QByteArrayLiteral("the bytes SocketIntegrationTest signs");
    SignOptions options;
    options.format = SignatureFormat::XAdES;
    options.level = SignatureLevel::BT;
    options.packaging = Packaging::Detached;
    // tsaUrl now HAS a sign-opts field on this wire — the pinned
    // asymmetry (this comment used to say the transport must drop it) is
    // retired; both transports forward it identically.
    options.tsaUrl = QStringLiteral("https://tsa.example/socket");
    options.extra.insert(QStringLiteral("reason"), QStringLiteral("integration-suite"));

    AgentOperation* op = card->sign(QStringLiteral("cert-for-sign"), makeMemfdDocument(document), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // fd in: the fake read the document synchronously inside the Sign handler.
    EXPECT_EQ(h.lastSignCertId(), QStringLiteral("cert-for-sign"));
    EXPECT_EQ(h.lastSignInputBytes(), document);

    const QVariantMap wireOptions = h.lastSignOptions();
    EXPECT_EQ(wireOptions.value(QStringLiteral("format")).toString(), QStringLiteral("xades"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("level")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("packaging")).toString(), QStringLiteral("detached"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("reason")).toString(), QStringLiteral("integration-suite"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("tsaUrl")).toString(), QStringLiteral("https://tsa.example/socket"))
        << "tsaUrl now crosses the socket wire";

    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid());
    EXPECT_EQ(readFdAll(artifact.get()), QByteArrayLiteral("FAKE-SOCKET-ARTIFACT"));
    EXPECT_EQ(op->signMeta().value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    EXPECT_TRUE(op->signMeta().value(QStringLiteral("tsaUsed")).toBool());
}

TEST(SocketIntegration, AutoLevelIsSentAsTheAutoSentinel)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->sign(QStringLiteral("cert-for-sign"),
                                    makeMemfdDocument(QByteArrayLiteral("deferred-level")), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // Asserted on the EMITTED value, not on the sign outcome: an empty string
    // would also be accepted by today's frontend, so only the bytes
    // distinguish the contractual sentinel from the tolerated accident.
    EXPECT_EQ(h.lastSignOptions().value(QStringLiteral("level")).toString(), QStringLiteral("auto"));
}

// ---- batch signing: happy path, mid-batch halt, in-order delivery, gates --------------

TEST(SocketIntegration, SignBatchHappyPathSignsEveryDocumentUnderOneConsent)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("first.pdf"), makeMemfdDocument(QByteArrayLiteral("doc one bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("second.pdf"), makeMemfdDocument(QByteArrayLiteral("doc two bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("third.pdf"), makeMemfdDocument(QByteArrayLiteral("doc three bytes"))});

    SignOptions options;
    options.format = SignatureFormat::PAdES;
    options.level = SignatureLevel::BB;

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->errorCode(), ErrorCode::None);

    EXPECT_EQ(h.lastSignBatchCertId(), QStringLiteral("cert-for-batch"));
    EXPECT_EQ(h.lastSignBatchDisplayNames(),
              (QStringList{QStringLiteral("first.pdf"), QStringLiteral("second.pdf"), QStringLiteral("third.pdf")}));
    const QList<QByteArray> receivedDocs = h.lastSignBatchDocumentBytes();
    ASSERT_EQ(receivedDocs.size(), 3);
    EXPECT_EQ(receivedDocs.at(0), QByteArrayLiteral("doc one bytes"));
    EXPECT_EQ(receivedDocs.at(1), QByteArrayLiteral("doc two bytes"));
    EXPECT_EQ(receivedDocs.at(2), QByteArrayLiteral("doc three bytes"));

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 3U);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        EXPECT_EQ(rows[i].error, ErrorCode::None);
        ASSERT_TRUE(rows[i].artifact.valid());
        EXPECT_EQ(readFdAll(rows[i].artifact.get()), QByteArrayLiteral("FAKE-SOCKET-ARTIFACT"));
    }
    EXPECT_EQ(rows[0].displayName, QStringLiteral("first.pdf"));
    EXPECT_EQ(rows[1].displayName, QStringLiteral("second.pdf"));
    EXPECT_EQ(rows[2].displayName, QStringLiteral("third.pdf"));
    EXPECT_TRUE(op->takeBatchResults().empty()) << "second call must return nothing — ownership taken once";
}

TEST(SocketIntegration, SignBatchMidBatchHaltPreservesEarlierRowsAndZeroesLaterOnes)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    cfg.batchHaltAtIndex = 2;
    cfg.batchHaltErrorCode = static_cast<quint32>(ErrorCode::CredentialWrong);
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    for (int i = 0; i < 4; ++i) {
        docs.push_back(BatchDocument{QStringLiteral("doc-%1.pdf").arg(i), makeMemfdDocument(QByteArrayLiteral("b"))});
    }

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok) << "successCount > 0 (rows 0-1 signed) keeps the aggregate Ok";

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 4U);
    for (int i = 0; i < 2; ++i) {
        EXPECT_EQ(rows[static_cast<std::size_t>(i)].error, ErrorCode::None) << "row " << i;
        ASSERT_TRUE(rows[static_cast<std::size_t>(i)].artifact.valid()) << "row " << i;
        EXPECT_FALSE(readFdAll(rows[static_cast<std::size_t>(i)].artifact.get()).isEmpty()) << "row " << i;
    }
    for (int i = 2; i < 4; ++i) {
        EXPECT_EQ(rows[static_cast<std::size_t>(i)].error, ErrorCode::CredentialWrong) << "row " << i;
        ASSERT_TRUE(rows[static_cast<std::size_t>(i)].artifact.valid()) << "row " << i << " — never invalid";
        EXPECT_TRUE(readFdAll(rows[static_cast<std::size_t>(i)].artifact.get()).isEmpty()) << "row " << i;
    }
}

// The socket wire's unicast-FIFO delivery invariant (see the CDDL's
// op-result-ready comment) covers SignBatch exactly like every non-Sign kind
// — there is no GetSignBatchResult pull route on this wire, by design; a
// result written before the client even subscribes still arrives, in order.
TEST(SocketIntegration, SignBatchResultWrittenBeforeEntryReturnsIsDeliveredInOrder)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    cfg.raceResultBeforeReturn = true;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("x.pdf"), makeMemfdDocument(QByteArrayLiteral("race doc bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("y.pdf"), makeMemfdDocument(QByteArrayLiteral("race doc bytes 2"))});

    AgentOperation* op = card->signBatch(QStringLiteral("certid"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 2U) << "the raced result event must not be lost";
    for (const BatchSignRow& row : rows) {
        ASSERT_TRUE(row.artifact.valid());
        EXPECT_EQ(readFdAll(row.artifact.get()), QByteArrayLiteral("FAKE-SOCKET-ARTIFACT"));
    }
}

// ---- batch signing: entry gates (never reach the wire) --------------------------------

TEST(SocketIntegration, MissingBatchSignFeatureRefusesLocally)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "batch-sign"
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("batch-sign")));

    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("a.pdf"), makeMemfdDocument(QByteArrayLiteral("b"))});

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    EXPECT_EQ(h.operationCount(), 0) << "the gate must refuse before SignBatch ever reaches the wire";
}

// signBatch shares Sign's own tsaUrl/visualSignature feature-token gate (the
// SAME code path in AgentCard::startOperation, not a parallel copy) — proven
// directly against signBatch here rather than assumed from Sign's own test.
TEST(SocketIntegration, SignBatchWithTsaUrlOrVisualSignatureWithoutTheirFeatureTokensRefusesLocally)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")}; // no tsa-url / visual-sign
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> tsaDocs;
    tsaDocs.push_back(BatchDocument{QStringLiteral("a.pdf"), makeMemfdDocument(QByteArrayLiteral("bytes"))});
    SignOptions tsaOptions;
    tsaOptions.tsaUrl = QStringLiteral("https://tsa.example/gated-batch");
    AgentOperation* tsaOp = card->signBatch(QStringLiteral("cert-for-batch"), std::move(tsaDocs), tsaOptions);
    ASSERT_NE(tsaOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return tsaOp->isFinished(); }));
    EXPECT_EQ(tsaOp->status(), OperationStatus::Error);
    EXPECT_EQ(tsaOp->errorCode(), ErrorCode::CapabilityMissing);

    std::vector<BatchDocument> visualDocs;
    visualDocs.push_back(BatchDocument{QStringLiteral("b.pdf"), makeMemfdDocument(QByteArrayLiteral("bytes"))});
    SignOptions visualOptions;
    visualOptions.visualSignature =
        QVariantMap{{QStringLiteral("page"), 0},      {QStringLiteral("x"), 0.0},
                    {QStringLiteral("y"), 0.0},       {QStringLiteral("width"), 100.0},
                    {QStringLiteral("height"), 50.0}, {QStringLiteral("text"), QStringLiteral("Signed")}};
    AgentOperation* visualOp = card->signBatch(QStringLiteral("cert-for-batch"), std::move(visualDocs), visualOptions);
    ASSERT_NE(visualOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return visualOp->isFinished(); }));
    EXPECT_EQ(visualOp->status(), OperationStatus::Error);
    EXPECT_EQ(visualOp->errorCode(), ErrorCode::CapabilityMissing);

    EXPECT_EQ(h.operationCount(), 0) << "both refusals must fire before SignBatch ever reaches the wire";
}

TEST(SocketIntegration, SignBatchDocumentCountOutsideBoundsRefusesLocally)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* emptyOp = card->signBatch(QStringLiteral("cert-for-batch"), {}, SignOptions{});
    ASSERT_NE(emptyOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return emptyOp->isFinished(); }));
    EXPECT_EQ(emptyOp->status(), OperationStatus::Error);
    EXPECT_EQ(emptyOp->callError(), CallError::InvalidArguments);

    std::vector<BatchDocument> tooMany;
    for (int i = 0; i < 13; ++i) {
        tooMany.push_back(
            BatchDocument{QStringLiteral("doc-%1.pdf").arg(i), makeMemfdDocument(QByteArrayLiteral("b"))});
    }
    AgentOperation* tooManyOp = card->signBatch(QStringLiteral("cert-for-batch"), std::move(tooMany), SignOptions{});
    ASSERT_NE(tooManyOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return tooManyOp->isFinished(); }));
    EXPECT_EQ(tooManyOp->status(), OperationStatus::Error);
    EXPECT_EQ(tooManyOp->callError(), CallError::InvalidArguments);

    EXPECT_EQ(h.operationCount(), 0) << "both refusals must fire before SignBatch ever reaches the wire";
}

// ---- method-entry refusal: err-info name -> ErrorCode --------------------------------

TEST(SocketIntegration, MethodEntryRefusalMapsErrorName)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.failMethodEntry = true; // UnsupportedOnThisCard at entry, no op minted
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    EXPECT_EQ(h.operationCount(), 0) << "no operation may be minted for a refused entry";
}

// ---- credentials: list / manage / mandatory re-list -----------------------------------

TEST(SocketIntegration, CredentialsListManagePinVerbThenRequiresReList)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.operationDelayMs = 15;
    FakeSocketCredRecord record;
    record.id = QStringLiteral("user:0x86");
    record.label = QStringLiteral("User PIN");
    record.canChange = true;
    cfg.credRecords = {record};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    // 1) list.
    AgentOperation* listOp = card->listCredentials();
    ASSERT_NE(listOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return listOp->isFinished(); }));
    EXPECT_EQ(listOp->status(), OperationStatus::Ok);
    ASSERT_EQ(listOp->credentialsResult().size(), 1);
    EXPECT_EQ(listOp->credentialsResult().constFirst().id, QStringLiteral("user:0x86"));
    EXPECT_TRUE(listOp->credentialsResult().constFirst().canChange);

    // 2) manage(PinVerb::Change) on the listed id.
    AgentOperation* manageOp = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(manageOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return manageOp->isFinished(); }));
    EXPECT_EQ(manageOp->status(), OperationStatus::Ok);
    EXPECT_EQ(manageOp->pinResult().outcome, CredentialOutcome::Ok);

    // 3) the mutation dropped the listing cache: an immediate second manage on
    // the SAME id is refused (UnknownCredential -> InvalidArguments) until a
    // fresh listing.
    AgentOperation* refused = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(refused, nullptr);
    ASSERT_TRUE(waitFor([&]() { return refused->isFinished(); }));
    EXPECT_EQ(refused->callError(), CallError::InvalidArguments);

    AgentOperation* relistOp = card->listCredentials();
    ASSERT_NE(relistOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return relistOp->isFinished(); }));
    EXPECT_EQ(relistOp->status(), OperationStatus::Ok);

    AgentOperation* manageAgain = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(manageAgain, nullptr);
    ASSERT_TRUE(waitFor([&]() { return manageAgain->isFinished(); }));
    EXPECT_EQ(manageAgain->status(), OperationStatus::Ok) << "the re-list must restore mutability";
}

// The wire's one structural ManagePin option, activateKey, actually reaches
// the SOCKET wire -- and only for ActivatePin. FakeSocketAgent decodes the
// REAL wire (Wire::parseRequest over CBOR), so this proves the extraction at
// SocketTransport.cpp (request.options.constFind("activateKey")) round-trips
// through actual wire encoding -- something neither SeamMappingTest.cpp (one
// layer up: proves only what the CLIENT emits, before any transport touches
// it) nor AgentCardTest.cpp/the D-Bus FakeAgent (a different transport
// entirely) can prove.
TEST(SocketIntegration, ManagePinActivatePinForwardsActivateKeyOverTheSocketWire)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    FakeSocketCredRecord record;
    record.id = QStringLiteral("sign:0x87");
    record.kind = QStringLiteral("sign");
    cfg.credRecords = {record};
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    // 1) list, then activate with activateKey=true.
    AgentOperation* listOp = card->listCredentials();
    ASSERT_NE(listOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return listOp->isFinished(); }));

    AgentOperation* activateOp =
        card->managePin(QStringLiteral("sign:0x87"), PinVerb::ActivatePin, ManagePinOptions{true});
    ASSERT_NE(activateOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return activateOp->isFinished(); }));
    EXPECT_EQ(activateOp->status(), OperationStatus::Ok);
    const std::optional<bool> afterActivate = h.lastManagePinActivateKey();
    ASSERT_TRUE(afterActivate.has_value()) << "activateKey must reach the socket wire for ActivatePin";
    EXPECT_TRUE(*afterActivate);

    // 2) re-list (the mutation above dropped the listing cache), then Change
    // on the SAME id: activateKey must NOT be present on the wire at all for
    // this verb -- absence, not a present false, is what a Change mutation
    // carries, even though the client's ManagePinOptions default is false.
    AgentOperation* relistOp = card->listCredentials();
    ASSERT_NE(relistOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return relistOp->isFinished(); }));

    AgentOperation* changeOp = card->managePin(QStringLiteral("sign:0x87"), PinVerb::Change);
    ASSERT_NE(changeOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return changeOp->isFinished(); }));
    EXPECT_EQ(changeOp->status(), OperationStatus::Ok);
    EXPECT_FALSE(h.lastManagePinActivateKey().has_value())
        << "Change must not carry activateKey on the socket wire at all";
}

// ---- HelloAck feature-token gate --------------------------------------------------------

TEST(SocketIntegration, MissingCredentialsFeatureTokenRefusesLocally)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.features = {}; // an agent predating the credential request family
    SocketHarness h(cfg);

    SocketTransport* transport = nullptr;
    auto client = makeClient(h, &transport);
    ASSERT_NE(transport, nullptr);
    EXPECT_FALSE(transport->hasFeature(QLatin1StringView("credentials")));
    // The public surface degrades identically: empty, no error.
    EXPECT_TRUE(client->features().isEmpty());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("credentials")));

    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->listCredentials();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    // The gate is mandatory: the request must never have reached the wire (a
    // pre-contract agent would fail it closed and drop the WHOLE connection).
    EXPECT_EQ(h.listCredentialsCount(), 0);
    EXPECT_TRUE(client->isAvailable()) << "the local refusal must not cost the session";
}

// ---- cancel ------------------------------------------------------------------------------

TEST(SocketIntegration, CancelStopsAnInFlightOperation)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // never fires on its own within the test
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    const int cancelledBefore = h.cancelledOperationCount();
    op->cancel();

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Cancelled);
    EXPECT_GT(h.cancelledOperationCount(), cancelledBefore) << "CancelOp must reach the agent-side operation";
}

// ---- op-stall: no internal watchdog (the same contract the D-Bus suite pins) -------------

TEST(SocketIntegration, OpStallHasNoInternalWatchdogCancelIsTheEscapeValve)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // the agent never finishes this op on its own
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    // Well past every call-level budget but nowhere near
    // kLongOperationTimeoutMs: nothing may auto-fail the op.
    QDeadlineTimer settle(kDefaultCallTimeoutMs * 2);
    while (!settle.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(1);
    }
    EXPECT_FALSE(op->isFinished())
        << "no internal watchdog exists — a caller must enforce kLongOperationTimeoutMs itself";

    op->cancel();
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Cancelled);
}

// ---- FIFO delivery: result racing the op-started reply is never lost ----------------------
//
// The socket analogue of the D-Bus lost-Result recovery: the fake writes
// OpResultReady + OpFinished into the stream BEFORE the client even parses
// the op-started reply. On this wire nothing needs a recovery pull — frames
// arriving during the bounded entry call are queued in order and delivered
// once the operation's subscription (installed synchronously after the
// reply) is in place. The observable difference from D-Bus: the terminal
// lands on the next event-loop turn, not synchronously in the ctor.
TEST(SocketIntegration, ResultWrittenBeforeEntryReturnsIsDeliveredInOrder)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.raceResultBeforeReturn = true;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    const QByteArray document = QByteArrayLiteral("pre-subscription-race-document");
    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument(document), SignOptions{});
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid()) << "the raced result event must not be lost";
    EXPECT_EQ(readFdAll(artifact.get()), QByteArrayLiteral("FAKE-SOCKET-ARTIFACT"));
    EXPECT_EQ(h.getSignResultCount(), 0) << "in-order delivery needs no recovery pull";
}

// ---- lost-Result recovery through the Sign-only GetSignResult window ----------------------

TEST(SocketIntegration, SignLostResultRecoveredViaGetSignResult)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.signRecoverable = true; // the result event is suppressed, the payload retained
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid()) << "GetSignResult must recover the artifact the event never delivered";
    EXPECT_EQ(readFdAll(artifact.get()), QByteArrayLiteral("FAKE-SOCKET-ARTIFACT"));
    EXPECT_GE(h.getSignResultCount(), 1) << "recovery must actually go through the wire pull";
}

TEST(SocketIntegration, SignSuppressedResultWithNoRecoveryFailsLoud)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.suppressResult = true; // no result event AND GetSignResult refuses
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError)
        << "an Ok terminal with no recoverable payload must fail loudly, never claim an empty Ok";
}

// ---- socket-specific: the agent closes mid-operation --------------------------------------

TEST(SocketIntegration, AgentCloseMidOperationFailsInFlightOps)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    bool finishedSeen = false;
    CallError finishedCallError = CallError::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        finishedSeen = true;
        finishedCallError = op->callError();
    });

    h.closeAllConnections();
    ASSERT_TRUE(waitFor([&]() { return finishedSeen; }));
    EXPECT_EQ(finishedCallError, CallError::AgentUnavailable)
        << "half-close must terminalize in-flight operations as agent-unavailable";
    EXPECT_FALSE(client->isAvailable());
}

// ---- socket-specific: non-canonical frame fails the connection closed ---------------------

TEST(SocketIntegration, NonCanonicalFrameFailsClosed)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    SocketTransport* transport = nullptr;
    auto client = makeClient(h, &transport);
    ASSERT_TRUE(client->isAvailable());

    h.sendNonCanonicalFrame();
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }))
        << "a non-canonical frame must drop the connection (fail closed)";
    EXPECT_FALSE(transport->isConnected());
    ASSERT_TRUE(waitFor([&]() { return h.connectionCount() == 0; }));

    // The drop is per-connection, not per-process: a reconcile reconnects.
    client->refreshDiscovery();
    EXPECT_TRUE(client->isAvailable());
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 1; }));
}

// ---- socket-specific: AgentQuiesced availability semantics --------------------------------

TEST(SocketIntegration, AgentQuiescedIsUnavailableUntilReprobe)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    // An in-flight op: quiescing must terminalize it like an agent death.
    // The terminal state is captured in the finished slot — the registry
    // teardown that follows deletes the card and, with it, this operation.
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);
    bool finishedSeen = false;
    CallError finishedCallError = CallError::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        finishedSeen = true;
        finishedCallError = op->callError();
    });

    h.sendAgentQuiesced(1); // ScreenLocked
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(finishedSeen);
    EXPECT_EQ(finishedCallError, CallError::AgentUnavailable);
    EXPECT_TRUE(client->readers().isEmpty());
    EXPECT_EQ(h.connectionCount(), 1) << "quiesce is availability semantics — the connection stays open";

    // The re-probe (a bounded GetState round-trip on the SAME connection)
    // reports the agent back once it answers again.
    client->refreshDiscovery();
    EXPECT_TRUE(client->isAvailable());
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 1; }));
    EXPECT_EQ(h.connectionCount(), 1) << "recovery must not have needed a reconnect";
}

// ---- public-data DER fetch ------------------------------------------------------------------

TEST(SocketIntegration, CertificateDerFetchDeliversBytes)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.certDerBytes = QByteArrayLiteral("\x30\x03\x02\x01\x2a");
    SocketHarness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    AgentOperation* op = client->certificateDer(QLatin1String(kReaderId), QStringLiteral("cert-der-1"));
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->certificateDerResult(), cfg.certDerBytes);
    EXPECT_EQ(h.lastCertDerReader(), QLatin1String(kReaderId));
    EXPECT_EQ(h.lastCertDerCertId(), QStringLiteral("cert-der-1"));
}

TEST(SocketIntegration, CertificateDerKeyNotFoundMapsErrorCode)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.certDerKeyNotFound = true;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentOperation* op = client->certificateDer(QLatin1String(kReaderId), QStringLiteral("missing"));
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::KeyNotFound);
}

// ---- transport-level: requestProperties answers through the event loop ----------------------

namespace {

struct RecordingPropertyListener final : PropertyListener
{
    int changedCount = 0;
    bool fetchedSeen = false;
    quint64 fetchedToken = 0;
    std::optional<QVariantMap> fetched;

    void onPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated) override
    {
        Q_UNUSED(changed)
        Q_UNUSED(invalidated)
        ++changedCount;
    }
    void onPropertiesFetched(quint64 token, const std::optional<QVariantMap>& properties) override
    {
        fetchedSeen = true;
        fetchedToken = token;
        fetched = properties;
    }
};

struct RecordingRegistryListener final : RegistryListener
{
    int registeredCount = 0;
    int unregisteredCount = 0;

    void onServiceRegistered() override
    {
        ++registeredCount;
    }
    void onServiceUnregistered() override
    {
        ++unregisteredCount;
    }
    void onReaderAdded(const QString& readerId, const QVariantMap& properties) override
    {
        Q_UNUSED(readerId)
        Q_UNUSED(properties)
    }
    void onCardAdded(const QString& cardId, const QVariantMap& properties) override
    {
        Q_UNUSED(cardId)
        Q_UNUSED(properties)
    }
    void onReaderRemoved(const QString& readerId) override
    {
        Q_UNUSED(readerId)
    }
    void onCardRemoved(const QString& cardId) override
    {
        Q_UNUSED(cardId)
    }
    void onConfigChanged(const QString& key) override
    {
        Q_UNUSED(key)
    }
};

} // namespace

TEST(SocketIntegration, RequestPropertiesFetchesTheObjectSnapshot)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki | Cap::PinManagement;
    cfg.preReadAuth = QStringLiteral("Can");
    SocketHarness h(cfg);

    SocketTransport transport(h.path());
    ASSERT_TRUE(transport.probeAvailability());

    RecordingPropertyListener listener;
    transport.subscribeProperties(QLatin1String(kCardId), ObjectKind::Card, &listener);
    const quint64 token = transport.requestProperties(QLatin1String(kCardId), ObjectKind::Card, &listener);
    ASSERT_NE(token, 0u);
    EXPECT_FALSE(listener.fetchedSeen) << "the reply must arrive asynchronously, never out of the call";

    ASSERT_TRUE(waitFor([&]() { return listener.fetchedSeen; }));
    EXPECT_EQ(listener.fetchedToken, token);
    ASSERT_TRUE(listener.fetched.has_value());
    EXPECT_EQ(listener.fetched->value(QStringLiteral("Capabilities")).toUInt(), Cap::Pki | Cap::PinManagement);
    EXPECT_EQ(listener.fetched->value(QStringLiteral("PreReadAuthMethod")).toString(), QStringLiteral("Can"));
    EXPECT_EQ(listener.fetched->value(QStringLiteral("Reader")).toString(), QLatin1String(kReaderId));

    transport.unsubscribeProperties(QLatin1String(kCardId), &listener);
}

// ---- write-after-peer-close: EPIPE -> failed call, drop delivery stays queued -------

// The agent dies and the client's next seam call discovers it through the
// failing WRITE (not the read-EOF pump). Two contracts pinned at once:
//   - the failing send must surface as a failed call (EPIPE ->
//     CallError::AgentUnavailable), NOT as a process-killing SIGPIPE —
//     without MSG_NOSIGNAL on the send this whole test binary dies here;
//   - ConnectionLost delivery is QUEUED, never inline from inside the
//     consumer's own seam call: an inline onServiceUnregistered would tear
//     down the registry (deleting the very AgentCard the call is running
//     on) mid-call — a consumer use-after-free.
TEST(SocketIntegration, WriteAfterAgentDeathFailsCallWithoutInlineUnregistration)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(QLatin1String(kCardId));
    ASSERT_NE(card, nullptr);

    int sequence = 0;
    int unavailableAt = 0;
    QObject::connect(client.get(), &AgentClient::availabilityChanged, client.get(), [&](bool available) {
        if (!available && unavailableAt == 0) {
            unavailableAt = ++sequence;
        }
    });

    // The agent dies. Deliberately NO event processing between here and the
    // next seam call, so the death is discovered by the write itself.
    h.closeAllConnections();

    AgentOperation* op = card->readIdentity();
    const int callReturnedAt = ++sequence;

    // All asserted BEFORE any event processing: the op (parented to the
    // card) is deleted by the queued availability teardown on the next turn.
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    EXPECT_TRUE(op->isFinished()) << "an entry-refused op is terminal the instant the minting call returns";
    EXPECT_EQ(op->callError(), CallError::AgentUnavailable);
    EXPECT_EQ(unavailableAt, 0) << "the availability push must not be delivered inside the seam call";
    EXPECT_TRUE(client->isAvailable()) << "registry teardown inside the consumer's own call stack is the UAF";

    ASSERT_TRUE(waitFor([&]() { return unavailableAt != 0; }));
    EXPECT_GT(unavailableAt, callReturnedAt) << "ConnectionLost must land on a later event-loop turn";
    EXPECT_FALSE(client->isAvailable());
    EXPECT_EQ(client->card(QLatin1String(kCardId)), nullptr) << "the teardown (on its own turn) clears the registry";
}

// ---- stale ConnectionLost across a same-stack reconnect ------------------------------

// A drop discovered mid-call defers ConnectionLost; if the consumer
// reconnects in the SAME stack (probe -> fresh handshake) before that
// deferred notice drains, the stale notice must not be announced against the
// fresh connection — while the DEAD connection's in-flight async requests
// must still be answered with their failure outcomes.
TEST(SocketIntegration, StaleConnectionLostAfterSynchronousReconnectIsNotAnnounced)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    SocketTransport transport(h.path());
    RecordingRegistryListener registry;
    transport.setRegistryListener(&registry);
    ASSERT_TRUE(transport.probeAvailability());

    // An async request in flight on the doomed connection.
    RecordingPropertyListener props;
    transport.subscribeProperties(QLatin1String(kCardId), ObjectKind::Card, &props);
    const quint64 token = transport.requestProperties(QLatin1String(kCardId), ObjectKind::Card, &props);
    ASSERT_NE(token, 0u);

    // The agent's end closes; the next sync call discovers the death (failed
    // send) and defers ConnectionLost. The fake still listens, so an
    // immediate same-stack probe reconnects BEFORE the deferred notice
    // drains.
    h.closeAllConnections();
    EXPECT_FALSE(transport.fetchRegistry().has_value());
    EXPECT_FALSE(transport.isConnected());
    ASSERT_TRUE(transport.probeAvailability()) << "the same-stack reconnect must succeed";
    EXPECT_TRUE(transport.isConnected());

    // Drain the deferred notice: the old connection's in-flight request is
    // terminalized...
    ASSERT_TRUE(waitFor([&]() { return props.fetchedSeen; }));
    EXPECT_EQ(props.fetchedToken, token);
    EXPECT_FALSE(props.fetched.has_value());
    // ...but the stale ConnectionLost must NOT clear the fresh connection.
    EXPECT_EQ(registry.unregisteredCount, 0) << "a stale ConnectionLost fired against the reconnected transport";
    const std::optional<RegistrySnapshot> snapshot = transport.fetchRegistry();
    ASSERT_TRUE(snapshot.has_value()) << "the fresh connection must survive the stale notice";
    EXPECT_EQ(snapshot->readers.size(), 1);
    transport.unsubscribeProperties(QLatin1String(kCardId), &props);
}

// ---- an awaited reply followed by a malformed frame in ONE batch ----------------------

// The received success must be preserved (the call succeeds) while the
// malformed trailer still costs the connection (fail closed) — announced on
// the next event-loop turn, exactly like every other drop.
TEST(SocketIntegration, AwaitedReplyThenMalformedFrameInSameBatchPreservesTheReply)
{
    FakeSocketAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    SocketHarness h(cfg);

    SocketTransport transport(h.path());
    RecordingRegistryListener registry;
    transport.setRegistryListener(&registry);
    ASSERT_TRUE(transport.probeAvailability());

    h.setNonCanonicalAfterStateReply();
    const std::optional<RegistrySnapshot> snapshot = transport.fetchRegistry();
    ASSERT_TRUE(snapshot.has_value()) << "a reply already received must not be clobbered by the malformed trailer";
    EXPECT_EQ(snapshot->readers.size(), 1);

    // The fail-closed policy is untouched: the connection is gone, announced
    // on the next turn.
    EXPECT_FALSE(transport.isConnected());
    ASSERT_TRUE(waitFor([&]() { return registry.unregisteredCount == 1; }));
}
