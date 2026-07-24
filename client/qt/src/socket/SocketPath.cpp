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
#if defined(Q_OS_DARWIN)
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
