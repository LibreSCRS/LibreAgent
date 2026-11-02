// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Starting an installed agent that is not running. A session bus that has the
// agent's `.service` file but no agent is the state a fresh login leaves on a
// packaged system, and the one the in-process FakeAgent harness can never
// produce: there the agent is always already on the bus. So each case here runs
// its own bus daemon, with or without a service file that launches the
// FakeAgent as a separate process, and drives a real DBusTransport against it.

#include <LibreSCRS/AgentClient/AgentClient.h>

#include "ClientTestAccess.h"
#include "dbus/DBusTransport.h"
#include "fakes/TestBus.h"

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QFile>
#include <QPointer>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTimer>

#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <optional>

using namespace LibreSCRS::AgentClient;

namespace {

const QString kAgentName = QStringLiteral("org.librescrs.Agent");

/// A bus daemon of this case's own, optionally able to start the FakeAgent.
class PrivateBus
{
public:
    explicit PrivateBus(bool agentActivatable)
    {
        const QString services = m_dir.filePath(QStringLiteral("services"));
        QDir().mkpath(services);
        if (agentActivatable) {
            QFile service(services + QStringLiteral("/org.librescrs.Agent.service"));
            EXPECT_TRUE(service.open(QIODevice::WriteOnly));
            service.write(QStringLiteral("[D-BUS Service]\nName=%1\nExec=%2\n")
                              .arg(kAgentName, QStringLiteral(LIBREAGENT_ACTIVATABLE_AGENT))
                              .toUtf8());
        }
        QFile config(m_dir.filePath(QStringLiteral("bus.conf")));
        EXPECT_TRUE(config.open(QIODevice::WriteOnly));
        config.write(
            QStringLiteral("<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n"
                           " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
                           "<busconfig><type>session</type>"
                           "<listen>unix:dir=%1</listen>"
                           "<servicedir>%2</servicedir>"
                           "<policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/>"
                           "<allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>\n")
                .arg(m_dir.path(), services)
                .toUtf8());
        config.close();
        m_daemon.setProgram(QStringLiteral(LIBREAGENT_DBUS_DAEMON));
        m_daemon.setArguments({QStringLiteral("--config-file=") + config.fileName(), QStringLiteral("--nofork"),
                               QStringLiteral("--print-address=1")});
        m_daemon.start();
        EXPECT_TRUE(m_daemon.waitForStarted());
        EXPECT_TRUE(m_daemon.waitForReadyRead(5000));
        const QString address = QString::fromUtf8(m_daemon.readLine()).trimmed();
        m_connectionName = QStringLiteral("activation-client-%1").arg(++s_counter);
        m_connection = std::make_unique<QDBusConnection>(QDBusConnection::connectToBus(address, m_connectionName));
        EXPECT_TRUE(m_connection->isConnected()) << address.toStdString();
    }

    ~PrivateBus()
    {
        m_connection.reset();
        QDBusConnection::disconnectFromBus(m_connectionName);
        m_daemon.terminate();
        m_daemon.waitForFinished(3000);
    }

    PrivateBus(const PrivateBus&) = delete;
    PrivateBus& operator=(const PrivateBus&) = delete;

    [[nodiscard]] std::unique_ptr<AgentClient> makeClient() const
    {
        return std::unique_ptr<AgentClient>(
            ClientTestAccess::create(std::make_unique<DBusTransport>(*m_connection, kAgentName)));
    }

    [[nodiscard]] bool agentOnBus() const
    {
        return m_connection->interface()->isServiceRegistered(kAgentName).value();
    }

private:
    static inline int s_counter = 0;
    QTemporaryDir m_dir;
    QProcess m_daemon;
    QString m_connectionName;
    std::unique_ptr<QDBusConnection> m_connection;
};

TEST(AgentActivationTest, ConstructionDoesNotStartTheAgent)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    EXPECT_FALSE(client->isAvailable());
    EXPECT_TRUE(client->agentInstalled());
    EXPECT_EQ(client->agentState(), AgentState::Stopped);
    // Give a start that should not have happened the time to show up.
    Fakes::waitFor([] { return false; }, 300);
    EXPECT_FALSE(bus.agentOnBus());
    EXPECT_FALSE(client->isAvailable());
}

TEST(AgentActivationTest, RefreshDiscoveryStartsAnInstalledAgent)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    ASSERT_FALSE(client->isAvailable());
    QSignalSpy availability(client.get(), &AgentClient::availabilityChanged);
    QSignalSpy config(client.get(), &AgentClient::configChanged);

    client->refreshDiscovery();

    EXPECT_TRUE(client->isAvailable());
    EXPECT_EQ(client->agentState(), AgentState::Ready);
    EXPECT_TRUE(bus.agentOnBus());
    ASSERT_EQ(availability.count(), 1);
    EXPECT_TRUE(availability.constFirst().constFirst().toBool());
    EXPECT_FALSE(client->readers().isEmpty());
    // A settings snapshot taken while the agent was down is empty: "try
    // again" must tell its holder to read again, exactly once.
    ASSERT_EQ(config.count(), 1);
    EXPECT_TRUE(config.constFirst().constFirst().toString().isEmpty());
}

TEST(AgentActivationTest, RefreshDiscoveryOfARunningAgentDoesNotAskForANewSnapshot)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    client->refreshDiscovery();
    ASSERT_TRUE(client->isAvailable());
    QSignalSpy availability(client.get(), &AgentClient::availabilityChanged);
    QSignalSpy config(client.get(), &AgentClient::configChanged);

    client->refreshDiscovery();

    EXPECT_TRUE(client->isAvailable());
    EXPECT_EQ(availability.count(), 0);
    EXPECT_EQ(config.count(), 0);
}

TEST(AgentActivationTest, ConfigSnapshotStartsAnInstalledAgent)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    ASSERT_FALSE(client->isAvailable());
    QSignalSpy config(client.get(), &AgentClient::configChanged);

    const QVariantMap snapshot = client->configSnapshot();

    EXPECT_TRUE(client->isAvailable());
    EXPECT_FALSE(snapshot.isEmpty());
    // Whoever took a snapshot while the agent was down is told to read again.
    ASSERT_GE(config.count(), 1);
    EXPECT_TRUE(config.constFirst().constFirst().toString().isEmpty());
}

TEST(AgentActivationTest, RequestAgentStartReportsRunning)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    EXPECT_EQ(client->requestAgentStart(), AgentStartResult::Running);
    EXPECT_TRUE(client->isAvailable());
    // A second request finds it running and changes nothing.
    EXPECT_EQ(client->requestAgentStart(), AgentStartResult::Running);
}

/// Stands in for a QML button behind a Loader: its click handler asks for a
/// gesture and then, as QQuickAbstractButtonPrivate::handleRelease does after
/// emitting clicked(), goes on using the control. Whether the control was still
/// alive at that point is written outside it, so a deleted control is never
/// touched.
class GestureControl final : public QObject
{
public:
    GestureControl(std::function<void()> gesture, std::optional<bool>* survivedItsClick)
        : m_gesture(std::move(gesture)), m_survivedItsClick(survivedItsClick)
    {}

    void click()
    {
        const QPointer<GestureControl> self(this);
        std::optional<bool>* const survived = m_survivedItsClick;
        const std::function<void()> gesture = m_gesture;
        gesture();
        *survived = !self.isNull();
    }

private:
    std::function<void()> m_gesture;
    std::optional<bool>* m_survivedItsClick;
};

/// Clicks @p control from the event loop, the way a pointer release reaches a
/// button, and waits until its click handler has returned.
void clickFromTheEventLoop(GestureControl* control, const std::optional<bool>& survived)
{
    QTimer::singleShot(0, control, &GestureControl::click);
    ASSERT_TRUE(Fakes::waitFor([&survived] { return survived.has_value(); }, 30000));
}

TEST(AgentActivationTest, AStartAskedFromAClickLeavesTheClickedControlAlive)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    ASSERT_FALSE(client->isAvailable());
    std::optional<bool> survived;
    QSignalSpy finished(client.get(), &AgentClient::agentStartFinished);
    auto* control = new GestureControl([&client] { client->requestAgentStartLater(); }, &survived);
    const QPointer<GestureControl> watched(control);
    // The consumer swaps its view once the agent is up, as a Loader does when
    // the state it is bound to changes: the control goes, later.
    QObject::connect(client.get(), &AgentClient::availabilityChanged, control, [control](bool available) {
        if (available) {
            control->deleteLater();
        }
    });

    clickFromTheEventLoop(control, survived);

    EXPECT_TRUE(*survived) << "the control was deleted while its click handler was still running";
    ASSERT_TRUE(Fakes::waitFor([&finished] { return !finished.isEmpty(); }, 30000));
    EXPECT_EQ(finished.constFirst().constFirst().value<AgentStartResult>(), AgentStartResult::Running);
    EXPECT_TRUE(client->isAvailable());
    // The consumer did react: the swap happened, after the click.
    EXPECT_TRUE(Fakes::waitFor([&watched] { return watched.isNull(); }));
}

TEST(AgentActivationTest, ARefreshAskedFromAClickLeavesTheClickedControlAlive)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    ASSERT_FALSE(client->isAvailable());
    std::optional<bool> survived;
    auto* control = new GestureControl([&client] { client->refreshDiscoveryLater(); }, &survived);
    const QPointer<GestureControl> watched(control);
    QObject::connect(client.get(), &AgentClient::availabilityChanged, control, [control](bool available) {
        if (available) {
            control->deleteLater();
        }
    });

    clickFromTheEventLoop(control, survived);

    EXPECT_TRUE(*survived) << "the control was deleted while its click handler was still running";
    EXPECT_TRUE(Fakes::waitFor([&client] { return client->isAvailable(); }, 30000));
    EXPECT_TRUE(Fakes::waitFor([&watched] { return watched.isNull(); }));
}

TEST(AgentActivationTest, ARefreshOfARunningAgentAskedFromAClickLeavesTheClickedControlAlive)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    ASSERT_EQ(client->requestAgentStart(), AgentStartResult::Running);
    std::optional<bool> survived;
    QPointer<GestureControl> watched;
    auto* control = new GestureControl(
        [&client, &watched] {
            // Anything delivered while the refresh waits on the agent -- a card
            // inserted or removed, which makes the consumer swap its view --
            // stands in here as the next event the loop delivers.
            QTimer::singleShot(0, watched.data(), [&watched] { watched->deleteLater(); });
            client->refreshDiscoveryLater();
        },
        &survived);
    watched = control;
    QSignalSpy readers(client.get(), &AgentClient::readersChanged);

    clickFromTheEventLoop(control, survived);

    EXPECT_TRUE(*survived) << "the control was deleted while its click handler was still running";
    EXPECT_TRUE(Fakes::waitFor([&readers] { return !readers.isEmpty(); }));
    EXPECT_TRUE(Fakes::waitFor([&watched] { return watched.isNull(); }));
}

/// Waits until every call queued on @p receiver before this one has run and
/// returned. Queued calls run in the order they were posted, and this is read
/// at the top of the stack, where any of them that ran inside another's local
/// loop has unwound too: so a second gesture that was not absorbed has already
/// signalled by now, with no quiet period to guess.
bool drainQueuedCalls(QObject* receiver)
{
    const auto reached = std::make_shared<bool>(false);
    QMetaObject::invokeMethod(receiver, [reached] { *reached = true; }, Qt::QueuedConnection);
    return Fakes::waitFor([reached] { return *reached; }, 30000);
}

TEST(AgentActivationTest, AGestureAskedAgainBeforeItEndsAsksForNothingMore)
{
    PrivateBus bus(/*agentActivatable=*/true);
    auto client = bus.makeClient();
    QSignalSpy finished(client.get(), &AgentClient::agentStartFinished);
    QSignalSpy readers(client.get(), &AgentClient::readersChanged);

    client->requestAgentStartLater();
    client->requestAgentStartLater();
    // Nothing runs under the caller.
    EXPECT_FALSE(client->isAvailable());
    EXPECT_TRUE(finished.isEmpty());
    ASSERT_TRUE(drainQueuedCalls(client.get()));
    EXPECT_EQ(finished.count(), 1);
    EXPECT_EQ(finished.constFirst().constFirst().value<AgentStartResult>(), AgentStartResult::Running);

    readers.clear();
    client->refreshDiscoveryLater();
    client->refreshDiscoveryLater();
    EXPECT_TRUE(readers.isEmpty());
    ASSERT_TRUE(drainQueuedCalls(client.get()));
    EXPECT_EQ(readers.count(), 1);

    // Once it has ended, asking again asks again.
    client->requestAgentStartLater();
    EXPECT_TRUE(Fakes::waitFor([&finished] { return finished.count() == 2; }));
}

TEST(AgentActivationTest, NoServiceFileMeansNotInstalled)
{
    PrivateBus bus(/*agentActivatable=*/false);
    auto client = bus.makeClient();
    EXPECT_FALSE(client->agentInstalled());
    EXPECT_EQ(client->agentState(), AgentState::Missing);
    EXPECT_EQ(client->requestAgentStart(), AgentStartResult::NotInstalled);
    client->refreshDiscovery();
    EXPECT_FALSE(client->isAvailable());
    EXPECT_TRUE(client->configSnapshot().isEmpty());
    EXPECT_EQ(client->setConfigValue(QStringLiteral("DefaultReason"), QStringLiteral("x")),
              SyncError::CommunicationError);
}

} // namespace
