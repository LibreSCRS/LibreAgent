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
// a typed `a(sbb)` / `a(sb)` property array on D-Bus, a CBOR value the grammar
// types as bare `any` on the socket. Two default maps, one per fake, would let
// the thing under test be scripted differently on each side of the comparison.
#include "ConfigKeys.h"
#include "CscaAnchorKeys.h"

#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

namespace LibreSCRS::AgentClient::Fakes {

[[nodiscard]] inline QVariantMap defaultCscaAnchorState();

/// @brief The eleven Config1 properties with plausible values, keyed by the
///        wire spellings and valued in the canonical client-side shape
///        (`TslSources` as three-entry `[url, isLotl, eager]` lists,
///        `CscaSources` as TWO-entry `[uri, eager]` ones, `CscaAnchorState`
///        as the anchor-state dict below).
[[nodiscard]] inline QVariantMap defaultAgentConfig()
{
    return QVariantMap{
        {QString(kConfigDefaultLevel), QStringLiteral("b-t")},
        {QString(kConfigTsaUrls), QStringList{QStringLiteral("https://tsa.example.invalid/tsr")}},
        {QString(kConfigLastTsaUrl), QStringLiteral("https://tsa.example.invalid/tsr")},
        {QString(kConfigTslSources),
         QVariantList{tslSourceRow(QStringLiteral("https://example.invalid/tl.xml"), false, true)}},
        {QString(kConfigCscaSources),
         QVariantList{cscaSourceRow(QStringLiteral("https://example.invalid/csca.ldif"), true)}},
        {QString(kConfigTslCacheDir), QStringLiteral("/var/cache/librescrs/tsl")},
        {QString(kConfigAiaCacheDir), QStringLiteral("/var/cache/librescrs/aia")},
        {QString(kConfigDefaultReason), QStringLiteral("Approval")},
        {QString(kConfigDefaultLocation), QStringLiteral("Belgrade")},
        {QString(kConfigPluginDir), QStringLiteral("/usr/lib/librescrs/plugins")},
        // The read-only dictionary key. Valued from the SAME function the
        // import reply is scripted with: the property and the reply are one
        // dict on both wires, so scripting them from two tables here would let
        // a client read one shape after a restart and another after an import.
        {QString(kConfigCscaAnchorState), defaultCscaAnchorState()},
    };
}

/// @brief The `CscaAnchorState` dict both fakes answer an accepted
///        `ImportCscaMasterList` with, in the canonical client-side shape
///        (the same eight keys the D-Bus property and the socket reply arm
///        carry). Here for the same reason `defaultAgentConfig()` above is:
///        the parity corpus scripts it ONCE and each fake re-encodes it into
///        its own wire form, so the thing under comparison cannot be scripted
///        differently on the two sides.
///
/// The integer members are typed deliberately: `anchors`/`issuers` are `u` on
/// the bus and `acceptedAt`/`signedAt` are `x`, so a `quint32`/`qint64` split
/// here is what makes the D-Bus fake marshal the property's real signature
/// rather than something QtDBus guessed from a bare int.
[[nodiscard]] inline QVariantMap defaultCscaAnchorState()
{
    return QVariantMap{
        {QString(kCscaAnchorAnchors), QVariant::fromValue<quint32>(212)},
        {QString(kCscaAnchorIssuers), QVariant::fromValue<quint32>(47)},
        {QString(kCscaAnchorReplayRefusalActive), true},
        {QString(kCscaAnchorSigner),
         QStringLiteral("9c1f5c7b2f4b4d6f8a0e3d5c7b9a1f3e5d7c9b1a3f5e7d9c1b3a5f7e9d1c3b5a")},
        {QString(kCscaAnchorSignerPinned), true},
        {QString(kCscaAnchorAcceptedAt), QVariant::fromValue<qint64>(1756000000)},
        {QString(kCscaAnchorSignedAt), QVariant::fromValue<qint64>(1755000000)},
        {QString(kCscaAnchorOrigin), QStringLiteral("import")},
    };
}

} // namespace LibreSCRS::AgentClient::Fakes
