// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — not client API, never installed. What the two transports do with
// the Config1 key vocabulary of `ConfigKeys.h`: which keys may be written, and
// the ONE canonical client-side shape a `TslSources` row takes.
#include <LibreSCRS/AgentClient/ConfigKeys.h>

#include <QString>
#include <QStringView>
#include <QVariant>
#include <QVariantList>

namespace LibreSCRS::AgentClient {

/// Whether @p key may be written (`Config1.SetValue` / socket `SetConfig`).
[[nodiscard]] inline bool isSettableConfigKey(QStringView key)
{
    return key == kConfigDefaultLevel || key == kConfigDefaultReason || key == kConfigDefaultLocation ||
           key == kConfigTsaUrls || key == kConfigTslSources;
}

/// Whether @p key names a Config1 property at all (settable or read-only) —
/// the CDDL's `config-key`, which is also `Config1.Reset`'s argument set.
[[nodiscard]] inline bool isKnownConfigKey(QStringView key)
{
    return isSettableConfigKey(key) || key == kConfigLastTsaUrl || key == kConfigCscaAnchorState ||
           key == kConfigTslCacheDir;
}

/// ONE `TslSources` row in the canonical client-side shape: a three-entry
/// list `[QString url, bool isLotl, bool eager]`.
///
/// Spelled once, here, because the two wires arrive at it from genuinely
/// different places — D-Bus demarshals a typed `a(sbb)` struct array, the
/// socket normalizes a value the grammar types as bare `any` — and the public
/// `configSnapshot()` contract promises consumers exactly one shape whichever
/// transport they got. A row built anywhere else is a row that can drift.
[[nodiscard]] inline QVariant tslSourceRow(const QString& url, bool isLotl, bool eager)
{
    return QVariantList{QVariant(url), QVariant(isLotl), QVariant(eager)};
}

} // namespace LibreSCRS::AgentClient
