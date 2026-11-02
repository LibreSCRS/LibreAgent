// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// What a private test bus can start. ctest points XDG_DATA_HOME and
// XDG_DATA_DIRS at a directory holding the agent's activation file -- the state
// of a machine with the agent installed -- so a bus that reads the standard
// session service directories offers the agent here, and a suite that starts an
// installed agent would launch the real one. libreagent_private_session_bus()
// must give a bus that reads none of them, and, when asked, exactly the one
// directory a suite names.

#include <QByteArray>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusReply>
#include <QFile>
#include <QString>
#include <QStringList>

#include <gtest/gtest.h>

#ifndef LIBREAGENT_BUS_SUITE
#error "LIBREAGENT_BUS_SUITE must name this binary's suite"
#endif

namespace {

const QString kAgentName = QStringLiteral("org.librescrs.Agent");

QStringList activatableNames()
{
    QDBusConnectionInterface* bus = QDBusConnection::sessionBus().interface();
    if (bus == nullptr) {
        ADD_FAILURE() << "no session bus";
        return {};
    }
    const QDBusReply<QStringList> names = bus->activatableServiceNames();
    EXPECT_TRUE(names.isValid()) << names.error().message().toStdString();
    return names.value();
}

} // namespace

// Not vacuous: the machine this test simulates really does carry the agent's
// activation file where the standard session service directories look.
TEST(LIBREAGENT_BUS_SUITE, TheSimulatedMachineHasTheAgentInstalled)
{
    const QByteArray dataHome = qgetenv("XDG_DATA_HOME");
    ASSERT_FALSE(dataHome.isEmpty()) << "XDG_DATA_HOME is unset: the test's ENVIRONMENT did not reach it";
    EXPECT_TRUE(QFile::exists(QString::fromLocal8Bit(dataHome) +
                              QStringLiteral("/dbus-1/services/org.librescrs.Agent.service")));
}

TEST(LIBREAGENT_BUS_SUITE, AnInstalledAgentIsNotActivatableOnThePrivateBus)
{
    EXPECT_FALSE(activatableNames().contains(kAgentName))
        << "the private bus reads the machine's service directories: a suite that starts the agent starts the "
           "installed one";
}

#if defined(LIBREAGENT_SUITE_ACTIVATABLE)
TEST(LIBREAGENT_BUS_SUITE, TheSuitesOwnServiceDirectoryIsRead)
{
    EXPECT_TRUE(activatableNames().contains(QStringLiteral(LIBREAGENT_SUITE_ACTIVATABLE)));
}
#endif
