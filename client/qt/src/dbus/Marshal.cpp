// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "Marshal.h"

#include "../FieldExtraKeys.h"

#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDateTime>

#include <fcntl.h>

namespace LibreSCRS::AgentClient {

// (sssv) struct marshalling for the Identity1 field tuple.
QDBusArgument& operator<<(QDBusArgument& arg, const IdentityFieldWire& f)
{
    arg.beginStructure();
    arg << f.labelKey << f.labelFallback << f.type << f.value;
    arg.endStructure();
    return arg;
}
const QDBusArgument& operator>>(const QDBusArgument& arg, IdentityFieldWire& f)
{
    arg.beginStructure();
    arg >> f.labelKey >> f.labelFallback >> f.type >> f.value;
    arg.endStructure();
    return arg;
}

// (ssv) struct marshalling for the Certificates1 field tuple (NO type string —
// distinct from Identity1's (sssv)).
QDBusArgument& operator<<(QDBusArgument& arg, const CertFieldWire& f)
{
    arg.beginStructure();
    arg << f.labelKey << f.labelFallback << f.value;
    arg.endStructure();
    return arg;
}
const QDBusArgument& operator>>(const QDBusArgument& arg, CertFieldWire& f)
{
    arg.beginStructure();
    arg >> f.labelKey >> f.labelFallback >> f.value;
    arg.endStructure();
    return arg;
}

// Certificates1 cert struct `(s b a{sa{s(ssv)}} u as as u)`. The nested
// field-group maps are the registered CertFieldGroupsWire type, so Qt derives
// the exact `a{sa{s(ssv)}}` signature in both directions (a fake agent reuses
// the `<<` to emit a faithful payload; the client uses `>>`). Both must exist
// for qDBusRegisterMetaType<CertListWire>().
QDBusArgument& operator<<(QDBusArgument& arg, const CertInfoWire& c)
{
    CertFieldGroupsWire fields;
    if (!c.subjectCn.isEmpty()) {
        fields[QStringLiteral("subject")][QStringLiteral("cn")] = {
            QStringLiteral("label_subject_cn"), QStringLiteral("Subject CN"), QDBusVariant(c.subjectCn)};
    }
    if (!c.issuerCn.isEmpty()) {
        fields[QStringLiteral("issuer")][QStringLiteral("cn")] = {
            QStringLiteral("label_issuer_cn"), QStringLiteral("Issuer CN"), QDBusVariant(c.issuerCn)};
    }
    if (!c.notBefore.isEmpty()) {
        fields[QStringLiteral("validity")][QStringLiteral("notBefore")] = {
            QStringLiteral("label_not_before"), QStringLiteral("Not before"), QDBusVariant(c.notBefore)};
    }
    if (!c.notAfter.isEmpty()) {
        fields[QStringLiteral("validity")][QStringLiteral("notAfter")] = {
            QStringLiteral("label_not_after"), QStringLiteral("Not after"), QDBusVariant(c.notAfter)};
    }

    // chainSubjectCns falls back to [leaf CN] when the caller left it empty
    // (the single-entry chain), so an operator<<-built payload always has a
    // non-empty chain like the agent's.
    const QStringList chain = c.chainSubjectCns.isEmpty() ? QStringList{c.subjectCn} : c.chainSubjectCns;

    arg.beginStructure();
    arg << c.certId << c.signingCapable << fields;
    arg << static_cast<uint>(c.keyUsageBits); // keyUsageBits
    arg << c.extendedKeyUsageOids;            // extendedKeyUsageOids
    arg << chain;                             // chainSubjectCns
    arg << static_cast<uint>(c.trustStatus);  // trustStatus
    arg.endStructure();
    return arg;
}

const QDBusArgument& operator>>(const QDBusArgument& arg, CertInfoWire& c)
{
    CertFieldGroupsWire fields;
    arg.beginStructure();
    arg >> c.certId >> c.signingCapable >> fields;

    // Trailing members: u keyUsageBits, as EKU OIDs, as chainSubjectCns,
    // u trustStatus. keyUsageBits/trustStatus are `u`; the client localizes
    // the KeyUsage bitmask and renders the trust verdict (Unknown until
    // evaluated).
    uint keyUsageBits = 0;
    uint trustStatus = 0;
    arg >> keyUsageBits >> c.extendedKeyUsageOids >> c.chainSubjectCns >> trustStatus;
    c.keyUsageBits = keyUsageBits;
    c.trustStatus = trustStatus;
    arg.endStructure();

    // Pull the display fields out of the demarshaled field-groups. Each field
    // value is a D-Bus variant `v` (the agent wire is (ssv)); the string lives
    // inside it.
    if (const auto subj = fields.constFind(QStringLiteral("subject")); subj != fields.constEnd()) {
        c.subjectCn = subj->value(QStringLiteral("cn")).value.variant().toString();
    }
    if (const auto iss = fields.constFind(QStringLiteral("issuer")); iss != fields.constEnd()) {
        c.issuerCn = iss->value(QStringLiteral("cn")).value.variant().toString();
    }
    if (const auto val = fields.constFind(QStringLiteral("validity")); val != fields.constEnd()) {
        c.notBefore = val->value(QStringLiteral("notBefore")).value.variant().toString();
        c.notAfter = val->value(QStringLiteral("notAfter")).value.variant().toString();
    }
    return arg;
}

void ensureDBusMetatypes()
{
    static const bool done = [] {
        qDBusRegisterMetaType<AgentInterfaceProps>();
        qDBusRegisterMetaType<QMap<QDBusObjectPath, AgentInterfaceProps>>();
        qDBusRegisterMetaType<IdentityFieldWire>();
        qDBusRegisterMetaType<IdentityFieldGroupWire>();
        qDBusRegisterMetaType<IdentityFieldsWire>();
        qDBusRegisterMetaType<CertFieldWire>();
        qDBusRegisterMetaType<CertFieldGroupWire>();
        qDBusRegisterMetaType<CertFieldGroupsWire>();
        qDBusRegisterMetaType<CertInfoWire>();
        qDBusRegisterMetaType<CertListWire>();
        qDBusRegisterMetaType<PhotoMapWire>();
        qDBusRegisterMetaType<CredentialRecordsWire>();
        return true;
    }();
    Q_UNUSED(done)
}

QVariantMap scrubObjectPaths(const QVariantMap& props)
{
    QVariantMap out;
    for (auto it = props.constBegin(); it != props.constEnd(); ++it) {
        if (it->metaType() == QMetaType::fromType<QDBusObjectPath>()) {
            out.insert(it.key(), qvariant_cast<QDBusObjectPath>(*it).path());
        } else {
            out.insert(it.key(), it.value());
        }
    }
    return out;
}

QVariantMap demarshalVariantMap(const QVariant& arg)
{
    if (arg.metaType().id() == qMetaTypeId<QDBusArgument>()) {
        QVariantMap map;
        arg.value<QDBusArgument>() >> map;
        return map;
    }
    return arg.toMap();
}

FdHandle toFdHandle(const QDBusUnixFileDescriptor& fd)
{
    if (!fd.isValid()) {
        return {};
    }
    // O_CLOEXEC dup: the descriptor must never leak into a child the consumer
    // spawns (the payloads are PII / signed artifacts).
    return FdHandle{::fcntl(fd.fileDescriptor(), F_DUPFD_CLOEXEC, 0)};
}

QList<FieldGroup> toFieldGroups(const IdentityFieldsWire& fields)
{
    QList<FieldGroup> groups;
    for (auto groupIt = fields.constBegin(); groupIt != fields.constEnd(); ++groupIt) {
        FieldGroup group;
        group.key = groupIt.key();
        const IdentityFieldGroupWire& wireGroup = groupIt.value();
        for (auto fieldIt = wireGroup.constBegin(); fieldIt != wireGroup.constEnd(); ++fieldIt) {
            const IdentityFieldWire& wireField = fieldIt.value();
            Field field;
            field.key = fieldIt.key();
            field.extra.insert(kFieldExtraLabelKey, wireField.labelKey);
            field.extra.insert(kFieldExtraLabelFallback, wireField.labelFallback);
            field.extra.insert(kFieldExtraType, wireField.type);
            const QVariant value = wireField.value.variant();
            if (wireField.type == kFieldTypeBinary) {
                // Binary payloads (raw photo bytes etc.) are not display text:
                // the bytes ride `detail`, the display value stays empty.
                field.detail = value.toByteArray();
            } else {
                field.value = value.toString();
            }
            group.fields.append(std::move(field));
        }
        groups.append(std::move(group));
    }
    return groups;
}

QList<CertificateInfo> toCertificateInfos(const CertListWire& certs)
{
    QList<CertificateInfo> out;
    out.reserve(certs.size());
    for (const CertInfoWire& wire : certs) {
        CertificateInfo info;
        info.id = wire.certId;
        info.signingCapable = wire.signingCapable;
        info.subject = wire.subjectCn;
        info.issuer = wire.issuerCn;
        info.notBefore = QDateTime::fromString(wire.notBefore, Qt::ISODate);
        info.notAfter = QDateTime::fromString(wire.notAfter, Qt::ISODate);
        // Wire trust verdict -> the client-facing display set. The wire's three
        // untrusted causes (untrusted root / broken chain / invalid cert)
        // collapse to Untrusted; the raw value rides `extra` for consumers
        // that render the cause.
        switch (wire.trustStatus) {
        case 0U:
            info.trust = TrustStatus::Trusted;
            break;
        case 1U:
        case 2U:
        case 3U:
            info.trust = TrustStatus::Untrusted;
            break;
        case 4U:
            info.trust = TrustStatus::Expired;
            break;
        default:
            info.trust = TrustStatus::Unknown;
            break;
        }
        info.extra.insert(QStringLiteral("keyUsageBits"), wire.keyUsageBits);
        info.extra.insert(QStringLiteral("extendedKeyUsageOids"), wire.extendedKeyUsageOids);
        info.extra.insert(QStringLiteral("chainSubjectCns"), wire.chainSubjectCns);
        info.extra.insert(QStringLiteral("trustStatusWire"), wire.trustStatus);
        out.append(std::move(info));
    }
    return out;
}

std::vector<PhotoItem> toPhotoItems(const PhotoMapWire& photos)
{
    std::vector<PhotoItem> out;
    out.reserve(static_cast<std::size_t>(photos.size()));
    for (auto it = photos.constBegin(); it != photos.constEnd(); ++it) {
        PhotoItem item;
        item.key = it.key();
        item.fd = toFdHandle(it.value());
        out.push_back(std::move(item));
    }
    return out;
}

CredentialList toCredentialList(const CredentialRecordsWire& records)
{
    CredentialList out;
    out.reserve(records.size());
    for (const QVariantMap& record : records) {
        out.append(CredentialRecord::fromVariantMap(record));
    }
    return out;
}

} // namespace LibreSCRS::AgentClient
