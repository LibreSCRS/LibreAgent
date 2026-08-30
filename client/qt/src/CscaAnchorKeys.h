// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The `CscaAnchorState` key vocabulary and the ONE
// canonical conversion between the agent's untyped state dict and the public
// `CscaAnchorState` value type, shared by both transports (and by the fakes
// that model each wire) so the two cannot drift.
//
// The vocabulary is the wire's, mirrored here rather than invented: the D-Bus
// `org.librescrs.Agent.Config1.CscaAnchorState` property (and the identical
// dict `ImportCscaMasterList` replies with) and the CDDL's `csca-anchor-state`
// arm are the same eight keys under the same eight spellings.
//
// The property and the reply are the SAME dict, so both entry points converge
// here: `importCscaMasterList()` returns the typed value straight away, and
// `configSnapshot()["CscaAnchorState"]` carries the normalized dict a client
// that has just STARTED reads instead — the case that has no import reply to
// learn from.
//
// Why the conversion lives here and not in either transport: the two wires
// arrive at this value from genuinely different places — D-Bus demarshals an
// untyped `a{sv}` in which every value is whatever the agent put there, while
// the socket decodes a TYPED CBOR arm whose optionality the grammar already
// enforced — and the public surface promises consumers exactly one
// `CscaAnchorState` whichever transport produced it. A conversion written
// twice is a conversion that can disagree with itself, which is the failure
// ConfigKeys.h's `tslSourceRow`/`cscaSourceRow` already exist to prevent for
// the two source lists.
//
// ABSENCE IS NOT ZERO, and this file is where that is enforced for both wires.
// `signedAt` is absent whenever the master list carried no CMS signingTime,
// and the public type spells that as an INVALID QDateTime rather than a zero:
// a list signed at the epoch and a list with no date at all must never read
// alike (the D-Bus interface says so in as many words, and the CDDL arm
// repeats it). Reading a missing key through `QVariant::toLongLong()` would
// quietly produce 0 and erase exactly that distinction, so every optional key
// below is tested for PRESENCE first.
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

// The five that may be absent. Only `signedAt` is absent-able at the SOURCE
// (CMS makes signingTime optional); the other four are absent only from an
// agent that did not carry them, which the untyped `a{sv}` on one of these two
// wires cannot rule out.
inline constexpr QLatin1StringView kCscaAnchorSigner{"signer"};
inline constexpr QLatin1StringView kCscaAnchorSignerPinned{"signerPinned"};
inline constexpr QLatin1StringView kCscaAnchorAcceptedAt{"acceptedAt"};
inline constexpr QLatin1StringView kCscaAnchorSignedAt{"signedAt"};
inline constexpr QLatin1StringView kCscaAnchorOrigin{"origin"};

/// Whether @p key names a member of the anchor-state dict this build knows.
/// Used to decide what belongs in `CscaAnchorState::extra` — everything else.
[[nodiscard]] inline bool isKnownCscaAnchorKey(QStringView key)
{
    return key == kCscaAnchorAnchors || key == kCscaAnchorIssuers || key == kCscaAnchorReplayRefusalActive ||
           key == kCscaAnchorSigner || key == kCscaAnchorSignerPinned || key == kCscaAnchorAcceptedAt ||
           key == kCscaAnchorSignedAt || key == kCscaAnchorOrigin;
}

/// One epoch-seconds member as a `QDateTime`: INVALID when @p map does not
/// carry @p key at all. Never a zero stand-in — see the file comment.
[[nodiscard]] inline QDateTime cscaAnchorTime(const QVariantMap& map, QLatin1StringView key)
{
    const auto it = map.constFind(QString(key));
    if (it == map.constEnd()) {
        return {};
    }
    return QDateTime::fromSecsSinceEpoch(it.value().toLongLong());
}

/// The agent's state dict in the ONE canonical client-side shape
/// `configSnapshot()["CscaAnchorState"]` promises, whichever transport
/// produced it.
///
/// Needed because the two wires carry these members as genuinely different
/// types and neither is wrong: D-Bus declares `anchors`/`issuers` as `u` and
/// the two dates as `x`, so QtDBus hands back `uint`/`qlonglong`, while the
/// socket's CBOR types every small non-negative integer as a signed one, so
/// the same four arrive as `qlonglong` there. A consumer that read them with
/// `toUInt()`/`toLongLong()` would not notice — but one that compared the two
/// snapshots, or switched on `metaType()`, would, and the public contract is
/// that the shape does not depend on the transport.
///
/// PRESENCE IS PRESERVED, never manufactured: a key the agent did not send
/// stays absent from the result. `signedAt` is the member that makes this
/// load-bearing (an undated master list carries none, and a 0 would read as
/// signed at the epoch), but the rule applies to every member — including
/// `replayRefusalActive`, whose absence means "this agent said nothing" and
/// is not the same statement as its false. A key this build does not name is
/// passed through VERBATIM rather than dropped, so a newer agent's addition
/// reaches a consumer that knows what to do with it.
[[nodiscard]] inline QVariantMap normalizeCscaAnchorState(const QVariantMap& raw)
{
    QVariantMap out;
    for (auto it = raw.constBegin(); it != raw.constEnd(); ++it) {
        const QString& key = it.key();
        if (key == kCscaAnchorAnchors || key == kCscaAnchorIssuers) {
            out.insert(key, QVariant::fromValue<quint32>(it.value().toUInt()));
        } else if (key == kCscaAnchorReplayRefusalActive || key == kCscaAnchorSignerPinned) {
            out.insert(key, it.value().toBool());
        } else if (key == kCscaAnchorAcceptedAt || key == kCscaAnchorSignedAt) {
            out.insert(key, QVariant::fromValue<qint64>(it.value().toLongLong()));
        } else if (key == kCscaAnchorSigner || key == kCscaAnchorOrigin) {
            out.insert(key, it.value().toString());
        } else {
            out.insert(key, it.value());
        }
    }
    return out;
}

/// The agent's state dict as the public value type. Tolerant by design: a key
/// this build does not name lands in `extra` rather than being dropped, and an
/// absent key leaves its member at the type's own default (which for the two
/// dates is an INVALID QDateTime, not the epoch).
[[nodiscard]] inline CscaAnchorState cscaAnchorStateFromMap(const QVariantMap& map)
{
    CscaAnchorState state;
    state.anchors = map.value(QString(kCscaAnchorAnchors)).toUInt();
    state.issuers = map.value(QString(kCscaAnchorIssuers)).toUInt();
    state.replayRefusalActive = map.value(QString(kCscaAnchorReplayRefusalActive)).toBool();
    state.signer = map.value(QString(kCscaAnchorSigner)).toString();
    state.signerPinned = map.value(QString(kCscaAnchorSignerPinned)).toBool();
    state.acceptedAt = cscaAnchorTime(map, kCscaAnchorAcceptedAt);
    state.signedAt = cscaAnchorTime(map, kCscaAnchorSignedAt);
    state.origin = map.value(QString(kCscaAnchorOrigin)).toString();
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (!isKnownCscaAnchorKey(it.key())) {
            state.extra.insert(it.key(), it.value());
        }
    }
    return state;
}

} // namespace LibreSCRS::AgentClient
