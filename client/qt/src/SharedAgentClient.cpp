// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/SharedAgentClient.h>

#include <LibreSCRS/AgentClient/AgentClient.h>

#include <QGlobalStatic>

#include <memory>

namespace LibreSCRS::AgentClient {

// The one process-wide AgentClient, via the Q_GLOBAL_STATIC shared-Qt-state
// idiom. Constructed on first access via the AgentClient(QObject*) production
// ctor; a shared_ptr owns it (no QObject parent), destroyed at process exit
// with the global static.
//
// NOTE: AgentClient is a QObject owning a live transport (availability watch +
// connection). Destroying a QObject/its transport at static teardown —
// possibly after QCoreApplication is gone, and (for a plugin consumer) inside
// a dlopened module whose host owns the QApplication — can emit Qt teardown
// warnings or touch an already-torn-down connection. This is behaviourally
// acceptable (no functional effect; the agent connection is process-scoped
// anyway). If exit-time warnings ever appear, guard teardown by tying the
// lifetime to QCoreApplication::aboutToQuit or by intentionally leaking on
// exit.
Q_GLOBAL_STATIC_WITH_ARGS(std::shared_ptr<AgentClient>, g_sharedAgentClient, (std::make_shared<AgentClient>()))

std::shared_ptr<AgentClient> sharedAgentClient()
{
    return *g_sharedAgentClient;
}

} // namespace LibreSCRS::AgentClient
