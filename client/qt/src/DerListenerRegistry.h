// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. Token-keyed bookkeeping for one transport's
// in-flight DerListener registrations (TransportSeam::requestCertificateDer /
// cancelCertificateDer). Every seam implementation with an asynchronous DER
// fetch needs this same discipline: a reply that lands after its own
// registration was removed (cancelled, or already delivered) must be a
// no-op, and — the bug this class exists to prevent — a SECOND registration
// that happens to reuse the SAME listener pointer as an earlier,
// already-cancelled one (a deleted AgentOperation::Private's heap address
// recycled by a freshly minted one) must never be silently unregistered by
// the earlier registration's own stale reply arriving late. Keying by TOKEN
// rather than by listener identity makes that impossible: two registrations
// sharing a pointer still occupy two distinct slots, so cancelling/consuming
// one never touches the other.
#include "TransportSeam.h"

#include <QHash>

namespace LibreSCRS::AgentClient {

class DerListenerRegistry
{
public:
    using DerListener = TransportSeam::DerListener;

    /// Register @p listener under a freshly minted token; returns it. The
    /// caller (the reply-lambda's capture, and the operation that must later
    /// cancel) is the token's sole owner from this point on.
    [[nodiscard]] quint64 add(DerListener* listener)
    {
        const quint64 token = ++m_nextToken;
        m_pending.insert(token, listener);
        return token;
    }

    /// Cancel path: drop @p token's registration (a no-op if it already fired
    /// or was already cancelled). Keyed by token, NEVER by listener identity —
    /// an unrelated registration that happens to share the same listener
    /// pointer must survive untouched.
    void cancel(quint64 token)
    {
        m_pending.remove(token);
    }

    /// Reply path: atomically look up and remove @p token's registration.
    /// Returns nullptr when the token is gone (cancelled, or a stale/
    /// duplicate reply) — the caller must then do nothing further (in
    /// particular, never touch the listener: it may belong to a different,
    /// still-live registration now).
    [[nodiscard]] DerListener* takeIfPresent(quint64 token)
    {
        const auto it = m_pending.find(token);
        if (it == m_pending.end()) {
            return nullptr;
        }
        DerListener* listener = it.value();
        m_pending.erase(it);
        return listener;
    }

private:
    QHash<quint64, DerListener*> m_pending;
    quint64 m_nextToken = 0;
};

} // namespace LibreSCRS::AgentClient
