// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — not client API, never installed. The conversion of each
// demarshaled wire shape (WireShapes.h) into the public value types
// (Types.h / SignOptions.h / CredentialTypes.h). The transport is the only
// consumer.
#include "WireShapes.h"

#include <LibreSCRS/AgentClient/CredentialTypes.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QDBusUnixFileDescriptor>
#include <QList>
#include <QString>
#include <QVariant>
#include <QVariantMap>

#include <vector>

namespace LibreSCRS::AgentClient {

// ---- wire -> public scrub -------------------------------------------------------

/// Flatten every QDBusObjectPath value in @p props to its plain path string —
/// the id scrub at the transport boundary, so nothing QtDBus-typed crosses
/// the seam.
[[nodiscard]] QVariantMap scrubObjectPaths(const QVariantMap& props);

/// Dual demarshal of an `a{sv}` argument: a remote reply arrives as a
/// QDBusArgument, a local one as a plain map.
[[nodiscard]] QVariantMap demarshalVariantMap(const QVariant& arg);

/// Duplicate the descriptor behind @p fd into an owning FdHandle (invalid
/// handle when @p fd is invalid or the dup fails).
[[nodiscard]] FdHandle toFdHandle(const QDBusUnixFileDescriptor& fd);

/// One Identity1 group's field map (the `a{s(sssv)}` shape the Group SIGNAL
/// carries as its own `fields` arg, and that IdentityFieldsWire's mapped_type
/// already is) -> a public FieldGroup keyed by @p groupKey. Field::extra
/// carries the wire metadata under the canonical keys (see FieldExtraKeys.h);
/// binary payloads ride Field::detail as QByteArray with an empty display
/// value. Shared by toFieldGroups' per-group loop below and by
/// DBusOperationWatch::onIdentityGroup so the two conversions of this SAME
/// cell shape can never drift apart.
[[nodiscard]] FieldGroup toFieldGroup(const QString& groupKey, const IdentityFieldGroupWire& fields);

/// Identity wire map -> public field groups. Field::extra carries the wire
/// metadata under the canonical keys (see FieldExtraKeys.h); binary payloads
/// ride Field::detail as QByteArray with an empty display value.
[[nodiscard]] QList<FieldGroup> toFieldGroups(const IdentityFieldsWire& fields);

/// Certificates wire list -> public certificate infos (typed TrustStatus,
/// ISO-8601 strings parsed to QDateTime, and the trailing wire members
/// keyUsageBits/extendedKeyUsageOids/chainSubjectCns landing in the TYPED
/// CertificateInfo members of the same names -- not in `extra`, so a rename
/// is a compile error rather than a silently empty value). Only the raw
/// trust verdict still rides `extra`, under "trustStatusWire": no typed
/// member mirrors it, because `trust` collapses several wire verdicts into
/// one display value.
[[nodiscard]] QList<CertificateInfo> toCertificateInfos(const CertListWire& certs);

/// Photo wire map -> move-only public photo items (each fd dup'd into an
/// owning FdHandle).
[[nodiscard]] std::vector<PhotoItem> toPhotoItems(const PhotoMapWire& photos);

/// SignBatch1 rows wire list -> move-only public batch-sign rows (each
/// artifact fd dup'd into an owning FdHandle; errorCode carried through
/// raw/untranslated — see BatchSignRow's own doc comment).
[[nodiscard]] std::vector<BatchSignRow> toBatchSignRows(const SignBatchRowsWire& rows);

/// Credential records wire list -> public records.
[[nodiscard]] CredentialList toCredentialList(const CredentialRecordsWire& records);

} // namespace LibreSCRS::AgentClient
