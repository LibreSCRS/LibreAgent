// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "SocketPath.h"

#include <LibreSCRS/Agent/wire/SocketLocation.h>

#include <QDir>
#include <QFile>

#include <pwd.h>
#include <unistd.h>

#include <string>

// The team is a compiled constant, never read from the environment: every
// target that compiles this file must say which team it was built for, even
// when that is none.
#ifndef LIBRESCRS_TEAM_ID
#error "LIBRESCRS_TEAM_ID must be defined (empty for a build without a team)"
#endif

namespace LibreSCRS::AgentClient {

QString appGroupFor(QStringView team)
{
    return QString::fromStdString(Agent::Wire::appGroupFor(team.toString().toStdString()));
}

QString agentAppGroupIdentifier()
{
    return appGroupFor(QStringLiteral(LIBRESCRS_TEAM_ID));
}

QString accountHomeDirectory()
{
    // getpwuid_r, not getpwuid: a GUI process may resolve this from more than
    // one thread, and the static buffer of the plain call is shared.
    passwd entry{};
    passwd* found = nullptr;
    std::string buffer(16384, '\0');
    if (::getpwuid_r(::getuid(), &entry, buffer.data(), buffer.size(), &found) == 0 && found != nullptr &&
        found->pw_dir != nullptr && found->pw_dir[0] != '\0') {
        return QFile::decodeName(found->pw_dir);
    }
    return QDir::homePath();
}

QString resolveAgentSocketPath()
{
#if defined(LIBREAGENT_CLIENT_SOCKET_TESTING)
    const QByteArray override = qgetenv(kAgentSocketEnvVar);
    if (!override.isEmpty()) {
        return QString::fromLocal8Bit(override);
    }
#endif
// Q_OS_MACOS, not Q_OS_DARWIN. The two agreed on macOS and nowhere else, and
// the factory that decides whether this transport exists at all
// (AgentClient.cpp) says Q_OS_MACOS. A path helper claiming a platform the
// factory refuses is a promise nothing keeps.
#if defined(Q_OS_MACOS)
    // The App-Group container's socket, addressed by its well-known absolute
    // path — the same directory the entitlement-gated container lookup
    // resolves, reachable without the application-groups entitlement.
    return accountHomeDirectory() + QStringLiteral("/Library/Group Containers/") + agentAppGroupIdentifier() +
           QLatin1Char('/') +
           QString::fromUtf8(Agent::Wire::kAgentSocketName.data(),
                             static_cast<qsizetype>(Agent::Wire::kAgentSocketName.size()));
#else
    return {};
#endif
}

} // namespace LibreSCRS::AgentClient
