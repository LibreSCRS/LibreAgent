// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "CappedCall.h"

#include <QDBusError>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QEventLoop>
#include <QTimer>

namespace LibreSCRS::AgentClient {

QDBusMessage cappedCall(const QDBusConnection& connection, const QDBusMessage& call, int timeoutMs)
{
    // asyncCall queues the send on the connection's manager thread and returns a
    // pending handle immediately (it never blocks). We then pump a LOCAL
    // QEventLoop that (a) receives the pending-call completion (Qt queues it to
    // the watcher on THIS thread) and (b) services a single-shot QTimer hard-cap.
    // Because the QTimer is a THIS-thread timer serviced by the very loop we
    // spin, the cap fires deterministically even if no reply ever arrives — so
    // the call is guaranteed to return within ~timeoutMs regardless of the
    // connection's state. Unlike a bare QDBus::Block — which freezes a RUNNING
    // outer event loop (a GUI consumer) for its entire timeout and, in a loop-
    // less worker, relies solely on libdbus's blocking read — this pumps a
    // local loop, so the outer loop stays responsive and the reply is driven
    // to completion either way.
    QDBusPendingCall pending = connection.asyncCall(call, timeoutMs);
    if (pending.isFinished()) {
        return pending.reply();
    }
    QEventLoop loop;
    QDBusPendingCallWatcher watcher(pending);
    QObject::connect(&watcher, &QDBusPendingCallWatcher::finished, &loop, &QEventLoop::quit);
    QTimer cap;
    cap.setSingleShot(true);
    QObject::connect(&cap, &QTimer::timeout, &loop, &QEventLoop::quit);
    // A small margin over the async timeout so, in the common case, asyncCall's
    // own error reply (delivered at ~timeoutMs) is preferred; the QTimer is the
    // hard backstop for the pathological "reply never dispatched at all" case.
    cap.start(timeoutMs + 200);
    loop.exec();
    if (pending.isFinished()) {
        return pending.reply();
    }
    // Hard cap fired before any reply: synthesize a timeout error so callers map
    // it exactly like any other failed call (their reply-type checks already
    // treat a non-ReplyMessage as unavailable).
    return call.createErrorReply(QDBusError::Timeout, QStringLiteral("agentclient: capped D-Bus call timed out"));
}

} // namespace LibreSCRS::AgentClient
