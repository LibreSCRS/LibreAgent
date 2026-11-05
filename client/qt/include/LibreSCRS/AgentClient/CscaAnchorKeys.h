// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// The `CscaAnchorState` key vocabulary: the seven members of the agent's
// anchor-state dict, as the D-Bus `org.librescrs.Agent.Config1.CscaAnchorState`
// property (and the identical dict `ImportCscaMasterList` replies with) and
// the CDDL's `csca-anchor-state` arm spell them. A host that reads
// `configSnapshot()["CscaAnchorState"]` names a member with these.
#include <LibreSCRS/AgentClient/Types.h>

#include <QDateTime>
#include <QLatin1StringView>
#include <QString>
#include <QVariant>
#include <QVariantMap>

namespace LibreSCRS::AgentClient {

// The three keys the agent ALWAYS carries once anything has been imported.
// `replayRefusalActive` is among them for a reason that is not symmetry: its
// FALSE is the value worth knowing (see CscaAnchorState's own doc comment), so
// a wire that could omit it would let a surface stay silent about the one
// thing a person cannot infer.
inline constexpr QLatin1StringView kCscaAnchorAnchors{"anchors"};
inline constexpr QLatin1StringView kCscaAnchorIssuers{"issuers"};
inline constexpr QLatin1StringView kCscaAnchorReplayRefusalActive{"replayRefusalActive"};

// The four that may be absent. Only `signedAt` is absent-able at the SOURCE
// (CMS makes signingTime optional); the other three are absent only from an
// agent that did not carry them, which the untyped `a{sv}` on one of these two
// wires cannot rule out.
inline constexpr QLatin1StringView kCscaAnchorSigner{"signer"};
inline constexpr QLatin1StringView kCscaAnchorSignerPinned{"signerPinned"};
inline constexpr QLatin1StringView kCscaAnchorAcceptedAt{"acceptedAt"};
inline constexpr QLatin1StringView kCscaAnchorSignedAt{"signedAt"};

} // namespace LibreSCRS::AgentClient
