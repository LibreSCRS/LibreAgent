// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The ONE builder for the certificate `fields`
// dict as it lands on `CertificateInfo::extra["fields"]`.
//
// Both transports decode that dict out of containers with nothing in common —
// a QtDBus-demarshalled `a{sa{s(ssv)}}` of QDBusVariant cells, and a
// `std::map<std::string, std::map<std::string, Wire::CertField>>` of CBOR text
// — so the WALK cannot be shared. The SHAPE can, and must be: the consumer
// that renders this dict is written against the shape, not against either
// wire, and two hand-written builders is exactly how the two transports would
// come to hand that consumer different answers. Each transport walks its own
// container and feeds this builder; the nesting, the cell encoding and the
// empty-case rule live here, once.
//
// The key spellings below are PUBLIC API surface (documented on
// `CertificateInfo::extra` in Types.h) — change them nowhere.
#include <QLatin1StringView>
#include <QMap>
#include <QString>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

#include <utility>

namespace LibreSCRS::AgentClient {

/// The `CertificateInfo::extra` key the grouped certificate fields land under.
inline constexpr QLatin1StringView kCertExtraFields{"fields"};

/// @brief Accumulates the wire's grouped certificate fields into the one
///        `extra["fields"]` shape both transports promise:
///        group -> field -> `[labelKey, labelFallback, value]`.
///
/// The wire grouping is preserved verbatim — group and field keys are the
/// agent's own spellings, never re-mapped here, because the group vocabulary
/// is append-only on the wire and a client that re-mapped it would have to be
/// re-released for every lawful append.
class CertFieldsExtra
{
public:
    /// Record one cell. A repeated (@p group, @p field) pair overwrites, which
    /// is what makes a transport's derived cell win over a scripted one of the
    /// same name rather than silently duplicating it.
    void add(const QString& group, const QString& field, const QString& labelKey, const QString& labelFallback,
             const QString& value)
    {
        m_groups[group].insert(field, QVariantList{labelKey, labelFallback, value});
    }

    /// Install under `kCertExtraFields`, or do nothing at all when no cell was
    /// recorded. Deliberately NOT an unconditional insert: a consumer tells
    /// "this certificate carried no fields dict" from "it carried an empty
    /// one" by the key's absence, and an empty map written on every certificate
    /// would erase that distinction on all of them.
    void installInto(QVariantMap& extra) const
    {
        if (m_groups.isEmpty()) {
            return;
        }
        QVariantMap groups;
        for (auto it = m_groups.constBegin(); it != m_groups.constEnd(); ++it) {
            groups.insert(it.key(), it.value());
        }
        extra.insert(QString(kCertExtraFields), std::move(groups));
    }

private:
    QMap<QString, QVariantMap> m_groups;
};

} // namespace LibreSCRS::AgentClient
