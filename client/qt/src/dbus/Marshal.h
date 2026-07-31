// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. Everything QDBusArgument-shaped the lift
// scrubbed out of the public headers lives HERE: the wire-shape mirror types
// for the agent's typed results, their stream operators, the D-Bus metatype
// registration, and the conversion of each demarshaled wire shape into the
// public value types (Types.h / SignOptions.h / CredentialTypes.h). The
// transport is the only consumer.
#include "../TransportSeam.h"

#include <LibreSCRS/AgentClient/CredentialTypes.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QDBusArgument>
#include <QDBusUnixFileDescriptor>
#include <QDBusVariant>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <vector>

namespace LibreSCRS::AgentClient {

// ---- ObjectManager wire shapes -------------------------------------------------

/// ObjectManager `a{sa{sv}}` interface→properties map (registered as a D-Bus
/// metatype so `InterfacesAdded` demarshals straight into a slot).
using AgentInterfaceProps = QMap<QString, QVariantMap>;

// ---- typed-result wire shapes ---------------------------------------------------

/// One Identity1 field — the `(sssv)` tuple from `a{sa{s(sssv)}}`.
struct IdentityFieldWire
{
    QString labelKey;
    QString labelFallback;
    QString type;       ///< "text" | "date" | "binary"
    QDBusVariant value; ///< "s" for text/date, "ay" for binary
};

/// Identity1 field map: group → (field → field-tuple), the demarshaled
/// `a{sa{s(sssv)}}` payload.
using IdentityFieldGroupWire = QMap<QString, IdentityFieldWire>;
using IdentityFieldsWire = QMap<QString, IdentityFieldGroupWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const IdentityFieldWire& f);
const QDBusArgument& operator>>(const QDBusArgument& arg, IdentityFieldWire& f);

/// One Certificates1 field — the `(ssv)` tuple (labelKey, labelFallback,
/// value) of the `a{sa{s(ssv)}}` field-group map. Distinct from Identity1's
/// `(sssv)` (no redundant type string). These intermediate types are
/// registered as D-Bus metatypes so Qt derives the exact nested container
/// signature in BOTH directions (hand-rolling nested `beginMap` signatures is
/// error-prone).
struct CertFieldWire
{
    QString labelKey;
    QString labelFallback;
    QDBusVariant value; ///< "s" UTF-8 string (the agent emits a variant `v`, mirroring IdentityFieldWire).
};
using CertFieldGroupWire = QMap<QString, CertFieldWire>;
using CertFieldGroupsWire = QMap<QString, CertFieldGroupWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const CertFieldWire& f);
const QDBusArgument& operator>>(const QDBusArgument& arg, CertFieldWire& f);

/// One Certificates1 entry — the wire struct `(s b a{sa{s(ssv)}} u as as u)`.
/// No DER crosses the wire: the agent parses X.509 and the client renders
/// only.
struct CertInfoWire
{
    QString certId;                   ///< Opaque SHA-256(DER) handle; the value Sign() takes.
    bool signingCapable = false;      ///< Paired on-card key + signing-suitable keyUsage.
    QString subjectCn;                ///< subject/cn field (display only).
    QString issuerCn;                 ///< issuer/cn field (display only).
    QString notBefore;                ///< validity/notBefore (display only, ISO-8601 UTC).
    QString notAfter;                 ///< validity/notAfter (display only, ISO-8601 UTC).
    quint32 keyUsageBits = 0;         ///< `u` X.509 KeyUsage bitmask (bit i per ordinal); client localizes.
    QStringList extendedKeyUsageOids; ///< `as` EKU OIDs (dotted).
    QStringList chainSubjectCns;      ///< `as` ordered leaf..root subject CNs (display only).
    quint32 trustStatus = 255;        ///< `u` 0 Trusted .. 4 Expired, 5 Revoked, 6 OfflineUnverified, 255 Unknown.
    /// Closed-vocabulary tokens mirroring trustStatus ("trusted",
    /// "untrusted-root", "broken-chain", "invalid", "expired", "revoked",
    /// "offline-unverified"). NOT its own struct member on the wire — carried
    /// inside the `fields` map's "security" group (dict-key growth); demarshaled
    /// out of that group here purely for the client's convenience, mirroring
    /// how subjectCn/issuerCn/notBefore/notAfter are pulled out of `fields`.
    QStringList securityStatus;
};

using CertListWire = QList<CertInfoWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const CertInfoWire& c);
const QDBusArgument& operator>>(const QDBusArgument& arg, CertInfoWire& c);

/// Photo1 `a{sh}` result: `"groupKey:fieldKey"` → sealed memfd.
using PhotoMapWire = QMap<QString, QDBusUnixFileDescriptor>;

/// One `Card1.SignBatch` request document — the `(sh)` struct of the
/// `a(sh) documents` in-arg: a caller-supplied display name plus the fd
/// carrying that document's bytes.
struct BatchDocumentWire
{
    QString name;
    QDBusUnixFileDescriptor fd;
};
using BatchDocumentsWire = QList<BatchDocumentWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const BatchDocumentWire& d);
const QDBusArgument& operator>>(const QDBusArgument& arg, BatchDocumentWire& d);

/// One `Operation.SignBatch1.Result`/`GetResult` row — the `(sha{sv}u)`
/// struct: displayName, artifact fd (a valid, possibly zero-length sealed
/// memfd on a failed row — see `BatchSignRow`'s own doc comment), meta, and
/// the raw numeric errorCode (0/`ErrorCode::None` on a successful row).
struct SignBatchRowWire
{
    QString displayName;
    QDBusUnixFileDescriptor artifact;
    QVariantMap meta;
    quint32 errorCode = 0;
};
using SignBatchRowsWire = QList<SignBatchRowWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const SignBatchRowWire& r);
const QDBusArgument& operator>>(const QDBusArgument& arg, SignBatchRowWire& r);

/// The `aa{sv}` credential records container as it arrives on the
/// Operation.Credentials1 Result signal / GetResult — the wire-shape typedef
/// the scrub internalized out of the public CredentialTypes.h.
using CredentialRecordsWire = QList<QVariantMap>;

/// Register every wire shape above as a D-Bus metatype. Idempotent; MUST run
/// before any signal connect / demarshal that names them.
void ensureDBusMetatypes();

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

Q_DECLARE_METATYPE(LibreSCRS::AgentClient::AgentInterfaceProps)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::IdentityFieldWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::IdentityFieldGroupWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::IdentityFieldsWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CertFieldWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CertFieldGroupWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CertFieldGroupsWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CertInfoWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CertListWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::PhotoMapWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CredentialRecordsWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::BatchDocumentWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::BatchDocumentsWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::SignBatchRowWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::SignBatchRowsWire)
