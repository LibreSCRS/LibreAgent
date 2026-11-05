// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — not client API, never installed. The ONE canonical conversion
// between the agent's untyped anchor-state dict and the public
// `CscaAnchorState` value type, shared by both transports (and by the fakes
// that model each wire) so the two cannot drift. The keys it reads are the
// public vocabulary of `CscaAnchorKeys.h`.
//
// The property and the import reply are the SAME dict, so both entry points
// converge here: `importCscaMasterList()` returns the typed value straight
// away, and `configSnapshot()["CscaAnchorState"]` carries the normalized dict
// a client that has just STARTED reads instead.
//
// ABSENCE IS NOT ZERO, and this file is where that is enforced for both wires.
// `signedAt` is absent whenever the master list carried no CMS signingTime,
// and the public type spells that as an INVALID QDateTime rather than a zero:
// a list signed at the epoch and a list with no date at all must never read
// alike. Reading a missing key through `QVariant::toLongLong()` would quietly
// produce 0 and erase exactly that distinction, so every optional key below is
// tested for PRESENCE first.
#include <LibreSCRS/AgentClient/CscaAnchorKeys.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QDateTime>
#include <QString>
#include <QStringView>
#include <QVariant>
#include <QVariantMap>

namespace LibreSCRS::AgentClient {

/// Whether @p key names a member of the anchor-state dict this build knows.
/// Used to decide what belongs in `CscaAnchorState::extra` — everything else.
[[nodiscard]] inline bool isKnownCscaAnchorKey(QStringView key)
{
    return key == kCscaAnchorAnchors || key == kCscaAnchorIssuers || key == kCscaAnchorReplayRefusalActive ||
           key == kCscaAnchorSigner || key == kCscaAnchorSignerPinned || key == kCscaAnchorAcceptedAt ||
           key == kCscaAnchorSignedAt;
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
        } else if (key == kCscaAnchorSigner) {
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
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (!isKnownCscaAnchorKey(it.key())) {
            state.extra.insert(it.key(), it.value());
        }
    }
    return state;
}

} // namespace LibreSCRS::AgentClient
