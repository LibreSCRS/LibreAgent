// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The socket path as the shipped library resolves it: this binary compiles
// SocketPath.cpp WITHOUT the test-only override, exactly like the library.
// Nothing in the environment may move the socket -- not a dedicated variable,
// not a redirected $HOME -- because every process running as the user can set
// both for every other one (`launchctl setenv` on macOS).

#include "socket/SocketPath.h"

#include <QByteArray>
#include <QString>

#include <gtest/gtest.h>

#include <pwd.h>
#include <unistd.h>

#include <cstdlib>

using namespace LibreSCRS::AgentClient;

namespace {

/// Set an environment variable for one scope, then put back what was there.
class ScopedEnv
{
public:
    ScopedEnv(const char* name, const char* value) : m_name(name), m_had(qEnvironmentVariableIsSet(name))
    {
        m_saved = qgetenv(name);
        qputenv(name, value);
    }
    ~ScopedEnv()
    {
        if (m_had) {
            qputenv(m_name, m_saved);
        } else {
            qunsetenv(m_name);
        }
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    const char* m_name;
    bool m_had;
    QByteArray m_saved;
};

TEST(SocketPath, TheShippedResolutionIgnoresTheOldOverrideVariable)
{
    const QString before = resolveAgentSocketPath();
    ScopedEnv override("LIBRESCRS_AGENT_SOCK", "/tmp/somebody-elses.sock");
    EXPECT_EQ(resolveAgentSocketPath(), before);
    EXPECT_NE(resolveAgentSocketPath(), QStringLiteral("/tmp/somebody-elses.sock"));
}

TEST(SocketPath, TheHomeDirectoryComesFromThePasswordDatabase)
{
    const passwd* entry = ::getpwuid(::getuid());
    ASSERT_NE(entry, nullptr);
    ASSERT_NE(entry->pw_dir, nullptr);
    const QString recorded = QString::fromLocal8Bit(entry->pw_dir);
    ASSERT_NE(recorded, QStringLiteral("/somewhere/else"));

    ScopedEnv home("HOME", "/somewhere/else");
    EXPECT_EQ(accountHomeDirectory(), recorded);
#if defined(Q_OS_MACOS)
    EXPECT_TRUE(resolveAgentSocketPath().startsWith(recorded + QLatin1Char('/')));
#endif
}

} // namespace
