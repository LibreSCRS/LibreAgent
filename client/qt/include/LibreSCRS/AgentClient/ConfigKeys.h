// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// The Config1 key vocabulary, shared by both transports (and by the fakes that
// model each wire) so the two cannot drift.
//
// The vocabulary is the wire's, mirrored here rather than invented: the CDDL's
// `settable-config-key` / `config-key` groups (wire/librescrs-agent.cddl) and
// the D-Bus `org.librescrs.Agent.Config1` interface are the same properties
// under the same spellings. The SPLIT between the settable and the read-only
// keys is load-bearing on the socket wire, where `set-config`'s grammar admits
// a `settable-config-key` ONLY, so a non-settable key cannot be encoded at all
// and the transport refuses it locally before it builds a frame (see
// SocketTransport::setConfig). D-Bus has no such limit: every key marshals,
// and the agent names the refusal itself (`…Error.ReadOnlyConfig`). Both paths
// must land on the SAME SyncError.
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

// The five keys a client may WRITE (CDDL `settable-config-key`). The first
// three are the D-Bus XML's low tier (polkit org.librescrs.agent.configure),
// the last two its trust tier (…configure.trust) — a distinction the agent
// enforces and the client only observes, as a NotAuthorized refusal.
inline constexpr QLatin1StringView kConfigDefaultLevel{"DefaultLevel"};
inline constexpr QLatin1StringView kConfigDefaultReason{"DefaultReason"};
inline constexpr QLatin1StringView kConfigDefaultLocation{"DefaultLocation"};
inline constexpr QLatin1StringView kConfigTsaUrls{"TsaUrls"};
inline constexpr QLatin1StringView kConfigTslSources{"TslSources"};

// The three READ-ONLY keys (CDDL `config-key` minus the settable set): one
// file-only path plus two pieces of agent-internal state.
//
// CscaAnchorState is the one whose value is a DICTIONARY rather than a string
// (`CscaAnchorKeys.h` names its members), and the one that is read-only for
// more than a housekeeping reason: it reports what country-signing anchors the
// agent HOLDS, so a client able to write it could claim what passports are
// checked against without installing a single anchor. It exists so a client
// that has just STARTED — with no ImportCscaMasterList reply to read — can say
// what is installed rather than that it cannot be known from here.
inline constexpr QLatin1StringView kConfigLastTsaUrl{"LastTsaUrl"};
inline constexpr QLatin1StringView kConfigCscaAnchorState{"CscaAnchorState"};
inline constexpr QLatin1StringView kConfigTslCacheDir{"TslCacheDir"};

} // namespace LibreSCRS::AgentClient
