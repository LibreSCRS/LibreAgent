// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <QDBusConnection>
#include <QDBusMessage>

/// @file
/// @brief INTERNAL — never installed. A bounded, event-loop-safe synchronous
///        D-Bus call. The single transport primitive for "I need this reply
///        NOW, but I must NEVER hang" — used at every synchronous discovery
///        call site (DBusTransport).

namespace LibreSCRS::AgentClient {

/// @brief Issue @p call and return its reply, bounded by @p timeoutMs, in a way
///        that terminates EVEN in a process/thread with no running event loop.
///        The reply is driven on a scoped local QEventLoop and a QTimer
///        hard-cap quits that loop if no reply arrives — so the call cannot
///        hang the way a bare QDBus::Block can when the caller's bus
///        integration is half-initialised. On timeout it returns an error
///        QDBusMessage (type ErrorMessage), which every call site already
///        treats as "unavailable". @p call MUST be a method call.
[[nodiscard]] QDBusMessage cappedCall(const QDBusConnection& connection, const QDBusMessage& call, int timeoutMs);

} // namespace LibreSCRS::AgentClient
