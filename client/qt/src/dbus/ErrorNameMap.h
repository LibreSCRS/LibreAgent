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
/// The two-axis rule (see SeamError): a name that maps onto the wire-frozen
/// ErrorCode taxonomy sets errorCode (the agent ANSWERED with a taxonomy
/// refusal); a name describing a pre-operation rejection outside the taxonomy
/// sets callError. An unknown agent error name degrades to
/// ErrorCode::CommunicationError — the lifted client's catch-all — so a
/// future agent-side name never crashes an old client into a misleading
/// transport-failure diagnosis.
[[nodiscard]] SeamError mapAgentErrorShortName(QStringView shortName, const QString& message);

/// @brief Classify a FULL D-Bus error name: the agent namespace defers to
///        mapAgentErrorShortName; the org.freedesktop.DBus.Error.* family maps
///        onto the transport-level CallError buckets (unavailable / timeout /
///        access / arguments / transport); anything else is a reply outside
///        the wire contract (ProtocolError).
[[nodiscard]] SeamError mapDBusErrorName(const QString& fullName, const QString& message);

} // namespace LibreSCRS::AgentClient
