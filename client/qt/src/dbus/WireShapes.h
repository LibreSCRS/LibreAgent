// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// The agent's D-Bus wire shapes as Qt types: the mirror of each typed result
// and of the two structured Config1 properties, their D-Bus stream operators,
// and their metatype registration. Not client API. The client's D-Bus
// transport reads them; the D-Bus agent double (ClientQtTestSupport, which
// installs this header beside FakeAgent.h) writes them, so both sides of the
// test bus speak one definition of every signature.
#include <QByteArray>
#include <QDBusArgument>
#include <QDBusUnixFileDescriptor>
#include <QDBusVariant>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <QtGlobal>

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

/// One Certificates1 entry — the wire struct `(s b a{sa{s(ssv)}} u as as u b ay s u b)`.
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
    bool alwaysAuthenticate = false;  ///< `b` the card asks for the PIN before every use of this key.
    QByteArray keyId;                 ///< `ay` the key's CKA_ID.
    QString keyType = QStringLiteral("OTHER"); ///< `s` "RSA" / "EC" / "OTHER".
    quint32 keyBits = 0;                       ///< `u` modulus bits or 256/384/521.
    bool canDerive = false;                    ///< `b` the agent derives with this key.
    /// Closed-vocabulary tokens mirroring trustStatus ("trusted",
    /// "untrusted-root", "broken-chain", "invalid", "expired", "revoked",
    /// "offline-unverified"). NOT its own struct member on the wire — carried
    /// inside the `fields` map's "security" group (dict-key growth); demarshaled
    /// out of that group here purely for the client's convenience, mirroring
    /// how subjectCn/issuerCn/notBefore/notAfter are pulled out of `fields`.
    QStringList securityStatus;
    /// The `a{sa{s(ssv)}}` field groups, WHOLE — including the five cells the
    /// convenience members above are pulled out of. `operator>>` fills it and
    /// the public decode surfaces it on `CertificateInfo::extra["fields"]`, so
    /// a group this build has never heard of still reaches a consumer (the
    /// group vocabulary is append-only on the wire).
    ///
    /// `operator<<` SEEDS its payload from this member and then overlays the
    /// cells it derives from the convenience members, so a producer that sets
    /// only those members emits exactly what it emitted before this member
    /// existed, and one that sets both never has a scripted cell shadow the
    /// member it mirrors.
    CertFieldGroupsWire fields;
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

/// One `Config1.TslSources` entry — the `(sbb)` struct of that property's
/// `a(sbb)` type: the trusted-list URL, whether it is a List-of-Trusted-Lists
/// pivot rather than a leaf list, and whether the agent fetches it eagerly at
/// startup. One of the two Config1 properties whose D-Bus type is not `s` or
/// `as` (CscaSources below is the other), hence one of the two needing a
/// registered metatype in both directions (the property READ demarshals it out
/// of the GetAll variant; SetValue marshals it back).
struct TslSourceWire
{
    QString url;
    bool isLotl = false;
    bool eager = false;
};
using TslSourcesWire = QList<TslSourceWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const TslSourceWire& s);
const QDBusArgument& operator>>(const QDBusArgument& arg, TslSourceWire& s);

/// One `Config1.CscaSources` entry — the `(sb)` struct of that property's
/// `a(sb)` type: where a set of country-signing trust anchors is fetched from,
/// and whether the agent fetches it eagerly at startup rather than lazily at
/// first use.
///
/// TWO fields, deliberately not three. TslSourceWire above carries isLotl
/// because the trusted-list world has a list-of-lists: one URL can name
/// further lists to follow. Country-signing anchors have no such indirection —
/// a source names anchors, never other sources — so there is no third field to
/// carry, and adding one for symmetry with the struct above would put a cell
/// on the wire that describes nothing.
struct CscaSourceWire
{
    QString uri;
    bool eager = false;
};
using CscaSourcesWire = QList<CscaSourceWire>;

QDBusArgument& operator<<(QDBusArgument& arg, const CscaSourceWire& s);
const QDBusArgument& operator>>(const QDBusArgument& arg, CscaSourceWire& s);

/// Register every wire shape above as a D-Bus metatype. Idempotent; MUST run
/// before any signal connect / demarshal that names them.
void ensureDBusMetatypes();

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
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::TslSourceWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::TslSourcesWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CscaSourceWire)
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::CscaSourcesWire)
