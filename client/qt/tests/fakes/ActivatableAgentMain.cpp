// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The FakeAgent as a separate, bus-activatable program: a private bus daemon
// started by AgentActivationTest launches this through an ordinary D-Bus
// `.service` file, exactly as a session bus launches the real agent. It claims
// the well-known agent name on the bus that started it and exits when that bus
// goes away.

#include "FakeAgent.h"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QTimer>

#include <cstdio>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QDBusConnection bus = QDBusConnection::connectToBus(QDBusConnection::ActivationBus, QStringLiteral("starter"));
    if (!bus.isConnected()) {
        std::fprintf(stderr, "activatable fake agent: no starter bus\n");
        return 1;
    }
    LibreSCRS::AgentClient::Fakes::FakeAgent::Config config;
    config.service = QStringLiteral("org.librescrs.Agent");
    LibreSCRS::AgentClient::Fakes::FakeAgent agent(bus, config);
    if (!bus.registerService(config.service)) {
        std::fprintf(stderr, "activatable fake agent: could not claim the agent name\n");
        return 1;
    }
    // The bus is private to one test case; once the test tears it down there
    // is nothing left to serve, and a lingering process would outlive ctest.
    QTimer watchdog;
    QObject::connect(&watchdog, &QTimer::timeout, &app, [&bus]() {
        if (!bus.isConnected()) {
            QCoreApplication::quit();
        }
    });
    watchdog.start(100);
    QTimer::singleShot(120000, &app, &QCoreApplication::quit);
    return QCoreApplication::exec();
}
