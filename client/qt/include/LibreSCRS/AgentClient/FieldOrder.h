// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>

#include <QString>
#include <QStringList>

/// @file
/// @brief The reading order for a group whose fields the wire delivers sorted.
///
/// Identity crosses the wire as a map of maps, so a group's fields arrive in
/// byte order of their keys. For a group whose substance is an address that
/// puts "apartment" third and "street" last, which is not an order anyone
/// reads an address in.
///
/// Both desktop hosts corrected that, and both did it with a hand-written list
/// of the same fifteen keys, each pinned by its own test, each carrying a
/// comment asking the reader to change both together. A comment is not a
/// mechanism. The order lives here now, in the client library both hosts
/// already link, and each host keeps its own test aimed at this function.
///
/// This is STRUCTURE, not presentation: no key here is ever shown to anyone.
/// Turning a field key into a caption needs a catalogue in the reader's
/// language, and those stay in the hosts.

namespace LibreSCRS::AgentClient {

/// @brief Reading order for @p groupKey, or empty when the group has none.
///
/// Empty is not a failure and not a default: it means the wire's delivery
/// order is the order to use. A caller that receives an empty list keeps the
/// fields exactly as they arrived.
///
/// Keys the returned list does not name keep their relative delivery order
/// after every named one — a group that grows a field still renders it.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT QStringList fieldOrderForGroup(const QString& groupKey);

} // namespace LibreSCRS::AgentClient
