// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/IdentityRows.h>

#include "FieldExtraKeys.h"

#include <QDate>

namespace LibreSCRS::AgentClient {

QList<IdentityRow> flattenIdentityFields(const QList<FieldGroup>& groups)
{
    QList<IdentityRow> rows;
    for (const FieldGroup& group : groups) {
        for (const Field& field : group.fields) {
            if (field.extra.value(kFieldExtraType).toString() == kFieldTypeBinary) {
                continue; // raw photos etc. are not text rows
            }
            IdentityRow row;
            row.groupKey = group.key;
            row.fieldKey = field.key;
            row.labelKey = field.extra.value(kFieldExtraLabelKey).toString();
            row.labelFallback = field.extra.value(kFieldExtraLabelFallback).toString();
            row.value = field.value;
            rows.append(row);
        }
    }
    return rows;
}

std::optional<QString> normalizedCardDate(const QString& value)
{
    if (value.isEmpty()) {
        return std::nullopt;
    }
    if (QDate::fromString(value, QStringLiteral("dd.MM.yyyy")).isValid()) {
        return value; // already readable; the card's own text is kept verbatim
    }
    if (const QDate raw = QDate::fromString(value, QStringLiteral("ddMMyyyy")); raw.isValid()) {
        return raw.toString(QStringLiteral("dd.MM.yyyy"));
    }
    return std::nullopt;
}

} // namespace LibreSCRS::AgentClient
