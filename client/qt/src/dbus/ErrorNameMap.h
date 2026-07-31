// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The D-Bus error-name -> SeamError mapping table:
// the one place the transport turns wire error-name STRINGS into the public
// CallError/ErrorCode surface (the scrub that removed error-name strings from
// the lifted client's API). Pure string classification — no QtDBus types —
// so the table is unit-testable without a bus.
#include "../TransportSeam.h"

#include <QString>
#include <QStringView>

namespace LibreSCRS::AgentClient {

/// @brief Classify an agent-namespace error by its SHORT name (the spelling
///        after "org.librescrs.Agent.Error.", which is also the socket wire's
///        sync-error vocabulary — a later transport reuses this table).
///
/// The classification rule (see SeamError): a name that maps onto the
/// wire-frozen ErrorCode taxonomy sets errorCode (the agent ANSWERED with a
/// taxonomy refusal); a name describing a pre-operation rejection outside the
/// taxonomy sets callError. An unknown agent error name degrades to
/// ErrorCode::CommunicationError — the lifted client's catch-all — so a
/// future agent-side name never crashes an old client into a misleading
/// transport-failure diagnosis.
///
/// On top of that, this function ALWAYS engages the third axis, syncError, with
/// the name decoded to its enumerator: reaching here means a name in the agent
/// vocabulary was involved, which is exactly what that axis reports. So call it
/// ONLY for a name the peer actually sent, or for a refusal this client decides
/// on the peer's behalf in that same vocabulary so both transports converge (a
/// feature-gate miss). For a failure the CLIENT diagnosed about the exchange
/// itself, use localExchangeFailure() below instead — otherwise the client's own
/// decoding fault is attributed to the agent as an error it never named.
[[nodiscard]] SeamError mapAgentErrorShortName(QStringView shortName, const QString& message);

/// @brief Classify a failure the CLIENT diagnosed about the exchange itself,
///        not one the peer named: a non-reply carrying no error name at all, an
///        empty reply body, a reply that does not answer the request.
///
/// Lands on exactly the same CallError/ErrorCode/wireName the
/// unknown-agent-name arm of mapAgentErrorShortName produces — these sites have
/// always reported the taxonomy catch-all and that is deliberately unchanged —
/// but leaves syncError DISENGAGED, because nothing on the wire named anything.
/// The distinction is not cosmetic: a consumer branching on syncError() would
/// otherwise read a local D-Bus framing fault as the card answering
/// CommunicationError, and recover for the wrong failure.
[[nodiscard]] SeamError localExchangeFailure(const QString& message);

/// @brief Classify a FULL D-Bus error name: the agent namespace defers to
///        mapAgentErrorShortName; the org.freedesktop.DBus.Error.* family maps
///        onto the transport-level CallError buckets (unavailable / timeout /
///        access / arguments / transport); anything else is a reply outside
///        the wire contract (ProtocolError).
[[nodiscard]] SeamError mapDBusErrorName(const QString& fullName, const QString& message);

} // namespace LibreSCRS::AgentClient
