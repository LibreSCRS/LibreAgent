// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/IdentityRows.h>

#include "FieldExtraKeys.h"

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

} // namespace LibreSCRS::AgentClient
