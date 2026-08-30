// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The Config1 key vocabulary and the ONE canonical
// client-side shape a `TslSources` / `CscaSources` row takes, shared by both
// transports (and by the fakes that model each wire) so the two cannot drift.
//
// The vocabulary is the wire's, mirrored here rather than invented: the CDDL's
// `settable-config-key` / `config-key` groups (wire/librescrs-agent.cddl) and
// the D-Bus `org.librescrs.Agent.Config1` interface are the same ten
// properties under the same ten spellings. The SPLIT between them is what
// this header exists for — it is load-bearing on the socket wire, where
// `set-config`'s grammar admits a `settable-config-key` ONLY, so a
// non-settable key cannot be encoded at all and the transport has to refuse
// it locally before it builds a frame (see SocketTransport::setConfig). D-Bus
// has no such limit: every key marshals, and the agent names the refusal
// itself (`…Error.ReadOnlyConfig`). Both paths must land on the SAME
// SyncError, which is why the split lives in one place instead of two.
//
// The agent's own ConfigStore carries three further FileOnly keys
// (CscaCacheDir / Pkcs11IdleTimeoutSecs / Pkcs11MaxLifetimeSecs) that neither
// wire exposes. They are deliberately absent here: this header mirrors the WIRE
// contract, not the agent's on-disk file. CscaCacheDir in particular is
// file-only precisely so no client can choose it, which is also why no client
// needs a spelling for it.
#include <QLatin1StringView>
#include <QString>
#include <QStringView>
#include <QVariant>
#include <QVariantList>

namespace LibreSCRS::AgentClient {

// The six keys a client may WRITE (CDDL `settable-config-key`). The first
// three are the D-Bus XML's low tier (polkit org.librescrs.agent.configure),
// the last three its trust tier (…configure.trust) — a distinction the agent
// enforces and the client only observes, as a NotAuthorized refusal.
inline constexpr QLatin1StringView kConfigDefaultLevel{"DefaultLevel"};
inline constexpr QLatin1StringView kConfigDefaultReason{"DefaultReason"};
inline constexpr QLatin1StringView kConfigDefaultLocation{"DefaultLocation"};
inline constexpr QLatin1StringView kConfigTsaUrls{"TsaUrls"};
inline constexpr QLatin1StringView kConfigTslSources{"TslSources"};
inline constexpr QLatin1StringView kConfigCscaSources{"CscaSources"};

// The four READ-ONLY keys (CDDL `config-key` minus the settable set): three
// file-only paths — a wire-settable PluginDir is a dlopen code-exec vector —
// plus one piece of agent-internal state.
inline constexpr QLatin1StringView kConfigLastTsaUrl{"LastTsaUrl"};
inline constexpr QLatin1StringView kConfigTslCacheDir{"TslCacheDir"};
inline constexpr QLatin1StringView kConfigAiaCacheDir{"AiaCacheDir"};
inline constexpr QLatin1StringView kConfigPluginDir{"PluginDir"};

/// Whether @p key may be written (`Config1.SetValue` / socket `SetConfig`).
[[nodiscard]] inline bool isSettableConfigKey(QStringView key)
{
    return key == kConfigDefaultLevel || key == kConfigDefaultReason || key == kConfigDefaultLocation ||
           key == kConfigTsaUrls || key == kConfigTslSources || key == kConfigCscaSources;
}

/// Whether @p key names a Config1 property at all (settable or read-only) —
/// the CDDL's `config-key`, which is also `Config1.Reset`'s argument set.
[[nodiscard]] inline bool isKnownConfigKey(QStringView key)
{
    return isSettableConfigKey(key) || key == kConfigLastTsaUrl || key == kConfigTslCacheDir ||
           key == kConfigAiaCacheDir || key == kConfigPluginDir;
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

/// ONE `CscaSources` row in the canonical client-side shape: a TWO-entry list
/// `[QString uri, bool eager]`.
///
/// Two entries, not three. `tslSourceRow` above carries an isLotl pivot
/// because a trusted list can name further trusted lists; country-signing
/// anchors have no such indirection — a source names anchors, never other
/// sources — so a third cell would describe a structure that does not exist.
/// Spelled here for the same reason its trusted-list twin is: the two wires
/// arrive at the row from different places (a typed `a(sb)` struct array on
/// D-Bus, a value the socket grammar types as bare `any`) and
/// `configSnapshot()` promises consumers one shape whichever produced it.
[[nodiscard]] inline QVariant cscaSourceRow(const QString& uri, bool eager)
{
    return QVariantList{QVariant(uri), QVariant(eager)};
}

} // namespace LibreSCRS::AgentClient
