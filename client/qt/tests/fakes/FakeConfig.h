// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// The Config1 property set both fakes serve by default, in ONE shape.
//
// Its own header rather than a member of either fake, for a build reason and
// a contract reason. The build one: FakeAgent.h pulls in QtDBus, and the
// socket suite neither compiles that TU nor links Qt6::DBus, so anything the
// two fakes share has to sit in a QtDBus-free header. The contract one: the
// shape below IS the client-side promise (`AgentClient::configSnapshot()`
// hands out one map whichever transport produced it), so a parity scenario
// scripts this map once and each fake re-encodes it into its own wire form —
// a typed `a(sbb)` property array on D-Bus, a CBOR value the grammar types as
// bare `any` on the socket. Two default maps, one per fake, would let the
// thing under test be scripted differently on each side of the comparison.
#include "ConfigKeys.h"

#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

namespace LibreSCRS::AgentClient::Fakes {

/// @brief The nine Config1 properties with plausible values, keyed by the
///        wire spellings and valued in the canonical client-side shape
///        (`TslSources` as three-entry `[url, isLotl, eager]` lists).
[[nodiscard]] inline QVariantMap defaultAgentConfig()
{
    return QVariantMap{
        {QString(kConfigDefaultLevel), QStringLiteral("b-t")},
        {QString(kConfigTsaUrls), QStringList{QStringLiteral("https://tsa.example.invalid/tsr")}},
        {QString(kConfigLastTsaUrl), QStringLiteral("https://tsa.example.invalid/tsr")},
        {QString(kConfigTslSources),
         QVariantList{tslSourceRow(QStringLiteral("https://example.invalid/tl.xml"), false, true)}},
        {QString(kConfigTslCacheDir), QStringLiteral("/var/cache/librescrs/tsl")},
        {QString(kConfigAiaCacheDir), QStringLiteral("/var/cache/librescrs/aia")},
        {QString(kConfigDefaultReason), QStringLiteral("Approval")},
        {QString(kConfigDefaultLocation), QStringLiteral("Belgrade")},
        {QString(kConfigPluginDir), QStringLiteral("/usr/lib/librescrs/plugins")},
    };
}

} // namespace LibreSCRS::AgentClient::Fakes
