// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "FakeAgent.h"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDeadlineTimer>
#include <QEventLoop>
#include <QMetaObject>
#include <QObject>
#include <QString>
#include <QThread>
#include <gtest/gtest.h>
#include <memory>

/// @file
/// @brief Two-connection D-Bus harness for the FakeAgent tests. The FakeAgent
///        (server connection) lives on its OWN thread with its own event loop
///        so the client's synchronous `QDBus::Block` calls (the production
///        call mode) can be served without a single-thread deadlock, while
///        keeping the client object under test on the main thread. Server
///        mutations are marshaled to the worker thread with a functor
///        invokeMethod (no extra moc types needed).
///
/// This harness only stands up the FakeAgent + the two bus connections; it
/// does NOT construct a client. Each test builds its own `DBusTransport`
/// bound to `client()`/`service()` (the transport's test constructor) and
/// hands it to `ClientTestAccess::create()`.

namespace LibreSCRS::AgentClient::Fakes {

/// @brief Spin the main-thread event loop until @p pred is true or timeout.
template <typename Pred>
inline bool waitFor(Pred pred, int timeoutMs = 4000)
{
    QDeadlineTimer deadline(timeoutMs);
    while (!pred() && !deadline.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(1);
    }
    return pred();
}

/// @brief Run @p fn on @p target's thread and block until it returns.
template <typename Fn>
inline void runOnThread(QObject* target, Fn&& fn)
{
    QMetaObject::invokeMethod(target, std::forward<Fn>(fn), Qt::BlockingQueuedConnection);
}

/// @brief Owns the server thread + the main-thread client connection. The
///        FakeAgent + its server connection are created and dispatched on the
///        worker thread (a plain QObject context object lives there).
class Harness
{
public:
    explicit Harness(FakeAgent::Config config)
    {
        static int counter = 0;
        const QString tag = QStringLiteral("laqt-fake-%1-%2").arg(QCoreApplication::applicationPid()).arg(counter++);
        m_serverConnName = QStringLiteral("server-%1").arg(tag);
        m_clientName = QStringLiteral("client-%1").arg(tag);
        config.service = QStringLiteral("org.librescrs.Agent.Test.%1").arg(tag);
        m_service = config.service;
        m_config = config;

        m_thread = new QThread();
        m_thread->start();
        m_context = new QObject();
        m_context->moveToThread(m_thread);

        bool named = false;
        runOnThread(m_context, [this, &named]() {
            m_server = std::make_unique<QDBusConnection>(
                QDBusConnection::connectToBus(QDBusConnection::SessionBus, m_serverConnName));
            m_agent = std::make_unique<FakeAgent>(*m_server, m_config);
            named = m_server->registerService(m_service);
        });
        EXPECT_TRUE(named) << "could not claim " << m_service.toStdString() << " (run under dbus-run-session?)";

        m_client =
            std::make_unique<QDBusConnection>(QDBusConnection::connectToBus(QDBusConnection::SessionBus, m_clientName));
    }

    ~Harness()
    {
        runOnThread(m_context, [this]() {
            m_agent.reset();
            if (m_server) {
                m_server->unregisterService(m_service);
            }
            m_server.reset();
            QDBusConnection::disconnectFromBus(m_serverConnName);
        });
        m_context->deleteLater();
        m_thread->quit();
        m_thread->wait();
        delete m_thread;
        QDBusConnection::disconnectFromBus(m_clientName);
    }

    [[nodiscard]] QDBusConnection& client()
    {
        return *m_client;
    }
    [[nodiscard]] QString service() const
    {
        return m_service;
    }
    [[nodiscard]] QString cardPath() const
    {
        return QStringLiteral("/org/librescrs/Agent/card/0");
    }
    [[nodiscard]] QString readerPath() const
    {
        return QStringLiteral("/org/librescrs/Agent/reader/0");
    }

    /// @brief The Card1 / Reader1 property map the agent would hand a proxy via
    ///        GetManagedObjects, for a test that wants to prime a value
    ///        directly, mirroring how discovery seeds a fresh registry entry.
    ///        Read off the server thread, where the FakeAgent lives.
    [[nodiscard]] QVariantMap cardProps()
    {
        return ifaceProps(cardPath(), QStringLiteral("org.librescrs.Agent.Card1"));
    }
    [[nodiscard]] QVariantMap readerProps()
    {
        return ifaceProps(readerPath(), QStringLiteral("org.librescrs.Agent.Reader1"));
    }

    /// @brief Mutate the server-side card presence (marshaled to its thread).
    void setCardPresent(bool present)
    {
        runOnThread(m_context, [this, present]() { m_agent->setCardPresent(present); });
    }

    /// @brief Register a Card1 (visible to GetManagedObjects) and flip the reader
    ///        to HasCard, but DON'T announce the Card1 — the deferred-publish /
    ///        dropped-InterfacesAdded window.
    void exportCardSilently()
    {
        runOnThread(m_context, [this]() { m_agent->exportCardSilently(); });
    }

    /// @brief Drop the card from GetManagedObjects WITHOUT a live InterfacesRemoved
    ///        — a dropped removal signal only a discovery reconcile can catch.
    void dropCardSilently()
    {
        runOnThread(m_context, [this]() { m_agent->dropCardSilently(); });
    }

    /// @brief Register a second reader visible to GetManagedObjects but WITHOUT
    ///        emitting its InterfacesAdded — the hot-plugged-reader signal drop.
    void registerSecondReaderSilently()
    {
        runOnThread(m_context, [this]() { m_agent->registerSecondReaderSilently(); });
    }

    /// @brief Emit a PropertiesChanged carrying the full new Capabilities value.
    void emitCardCapabilitiesChanged(unsigned capabilities)
    {
        runOnThread(m_context, [this, capabilities]() { m_agent->emitCardCapabilitiesChanged(capabilities); });
    }

    /// @brief Emit a PropertiesChanged that invalidates Capabilities (GetAll path).
    void invalidateCardCapabilities(unsigned capabilities)
    {
        runOnThread(m_context, [this, capabilities]() { m_agent->invalidateCardCapabilities(capabilities); });
    }

    /// @brief Change the card's Capabilities WITHOUT any signal (a
    ///        client-vs-agent capability desync; the Credentials1 entry gate
    ///        then refuses a client whose cache still advertises the bit).
    void setCardCapabilitiesSilently(unsigned capabilities)
    {
        runOnThread(m_context, [this, capabilities]() { m_agent->setCardCapabilitiesSilently(capabilities); });
    }

    /// @brief Re-emit InterfacesAdded for the existing card path with new caps.
    void reAddCardWithCapabilities(unsigned capabilities)
    {
        runOnThread(m_context, [this, capabilities]() { m_agent->reAddCardWithCapabilities(capabilities); });
    }

    /// @brief Ops minted so far (read off the server thread). The lazy-I/O probe.
    [[nodiscard]] int operationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->operationCount(); });
        return out;
    }

    /// @brief Operation1.Cancel calls received by minted ops so far — the
    ///        observable seam for "an abandoned op was cancelled agent-side".
    [[nodiscard]] int cancelledOperationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->cancelledOperationCount(); });
        return out;
    }

    /// @brief Steps of the faithful "reader arrives already holding a card"
    ///        sequence (a/b/c). Driven separately so the test pumps the client
    ///        loop between them — the client must register its per-path match
    ///        rules from each InterfacesAdded before the next signal arrives.
    void emitReaderArrivesEmpty()
    {
        runOnThread(m_context, [this]() { m_agent->emitReaderArrivesEmpty(); });
    }
    QString emitArrivedReaderCardAdded(unsigned capabilities, const QString& preReadAuth = QStringLiteral("None"))
    {
        QString out;
        runOnThread(m_context, [this, capabilities, &preReadAuth, &out]() {
            out = m_agent->emitArrivedReaderCardAdded(capabilities, preReadAuth);
        });
        return out;
    }
    void emitArrivedReaderHasCard()
    {
        runOnThread(m_context, [this]() { m_agent->emitArrivedReaderHasCard(); });
    }

    /// @brief Read the verbatim Sign() in-args the fake captured (marshaled off
    ///        the server thread, where the FakeAgent lives).
    [[nodiscard]] QString lastSignCertId()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignCertId(); });
        return out;
    }
    [[nodiscard]] QVariantMap lastSignOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignOptions(); });
        return out;
    }
    [[nodiscard]] QByteArray lastSignInputBytes()
    {
        QByteArray out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignInputBytes(); });
        return out;
    }

    /// @brief The (reader, certId) the fake's Pkcs11_1.CertDer last received
    ///        (read off the server thread, where the FakeAgent lives).
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

    /// @brief Script the card's wedged Properties.GetAll (Config::wedgeCardProperties)
    ///        to answer after @p delayMs with @p props (a SLOW agent) instead of
    ///        wedging forever.
    void scriptCardGetAll(int delayMs, const QVariantMap& props)
    {
        runOnThread(m_context, [this, delayMs, &props]() { m_agent->scriptCardGetAll(delayMs, props); });
    }
    /// @brief How many GetAll calls reached the card's wedge so far (read off
    ///        the server thread, where the FakeAgent lives).
    [[nodiscard]] int cardGetAllCallCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->cardGetAllCallCount(); });
        return out;
    }
    /// @brief Ditto for the reader's wedge (Config::wedgeReaderProperties).
    void scriptReaderGetAll(int delayMs, const QVariantMap& props)
    {
        runOnThread(m_context, [this, delayMs, &props]() { m_agent->scriptReaderGetAll(delayMs, props); });
    }
    [[nodiscard]] int readerGetAllCallCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->readerGetAllCallCount(); });
        return out;
    }

    /// @brief Emit a Card1 PropertiesChanged carrying @p changed / @p invalidated
    ///        verbatim (the general form; see FakeAgent::emitCardPropertiesChanged).
    void emitCardPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated = {})
    {
        runOnThread(m_context,
                    [this, &changed, &invalidated]() { m_agent->emitCardPropertiesChanged(changed, invalidated); });
    }
    /// @brief Ditto for Reader1.
    void emitReaderPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated = {})
    {
        runOnThread(m_context,
                    [this, &changed, &invalidated]() { m_agent->emitReaderPropertiesChanged(changed, invalidated); });
    }

    /// @brief Drop the agent's bus name (simulates the daemon vanishing).
    void unregisterService()
    {
        runOnThread(m_context, [this]() {
            if (m_server) {
                m_server->unregisterService(m_service);
            }
        });
    }

    /// @brief Re-claim the agent's bus name after `unregisterService()` — the
    ///        inverse, for a test that models the agent (re)appearing on a
    ///        live QDBusServiceWatcher rather than only vanishing.
    void registerService()
    {
        bool named = false;
        runOnThread(m_context, [this, &named]() {
            if (m_server) {
                named = m_server->registerService(m_service);
            }
        });
        EXPECT_TRUE(named) << "could not re-claim " << m_service.toStdString();
    }

    /// @brief Mutate the FakeAgent Config on its own thread (synchronous). Affects
    ///        operations minted AFTER this returns — e.g. re-script a failed
    ///        ListCredentials to Ok before an explicit re-fetch.
    template <typename Fn>
    void mutateConfig(Fn&& fn)
    {
        runOnThread(m_context, [this, &fn]() { fn(m_agent->config()); });
    }

private:
    QVariantMap ifaceProps(const QString& objectPath, const QString& iface)
    {
        QVariantMap out;
        runOnThread(m_context, [this, &objectPath, &iface, &out]() {
            const FakeManagedObjects managed = m_agent->managedObjects();
            const auto it = managed.constFind(QDBusObjectPath(objectPath));
            if (it != managed.constEnd()) {
                out = it.value().value(iface);
            }
        });
        return out;
    }

    QString m_serverConnName;
    QString m_clientName;
    QString m_service;
    FakeAgent::Config m_config;
    QThread* m_thread = nullptr;
    QObject* m_context = nullptr;
    std::unique_ptr<QDBusConnection> m_server;
    std::unique_ptr<FakeAgent> m_agent;
    std::unique_ptr<QDBusConnection> m_client;
};

} // namespace LibreSCRS::AgentClient::Fakes
