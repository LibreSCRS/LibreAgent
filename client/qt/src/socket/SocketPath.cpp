// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "SocketPath.h"

#include <QDir>

namespace LibreSCRS::AgentClient {

QString resolveAgentSocketPath()
{
    const QByteArray override = qgetenv(kAgentSocketEnvVar);
    if (!override.isEmpty()) {
        return QString::fromLocal8Bit(override);
    }
// Q_OS_MACOS, not Q_OS_DARWIN. The two agreed on macOS and nowhere else, and
// the factory that decides whether this transport exists at all
// (AgentClient.cpp) says Q_OS_MACOS. A path helper claiming a platform the
// factory refuses is a promise nothing keeps: on another Darwin target it would
// hand back an App-Group container path for a transport that is never built,
// and the socket tests would FAIL there rather than not run.
#if defined(Q_OS_MACOS)
    // The App-Group container's socket, addressed by its well-known absolute
    // path — the same directory the entitlement-gated container lookup
    // resolves, reachable without the application-groups entitlement (the
    // Swift client's last-resort spelling of the same location).
    return QDir::homePath() + QStringLiteral("/Library/Group Containers/") + QLatin1String(kAgentAppGroupIdentifier) +
           QStringLiteral("/agent.sock");
#else
    // No production default on this platform: the socket transport is built
    // here as the portable, testable implementation, and tests always export
    // the environment override for their fake agent's temp path.
    return {};
#endif
}

} // namespace LibreSCRS::AgentClient
