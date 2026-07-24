// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QList>
#include <QString>

/// @file
/// @brief Structural flattening of an identity read into presentation-neutral
///        rows. This is the STRUCTURAL half of the lifted row assembly: it
///        operates on the frozen label KEYS the agent ships; mapping a label
///        key onto a localized display string is deliberately NOT this
///        library's job (the library never translates) — each GUI host keeps
///        its own label table keyed on `IdentityRow::labelKey`.

namespace LibreSCRS::AgentClient {

/// @brief One flattened identity field, neutral of any presentation layer.
///        The single skip-binary / stringify rule lives here so every consumer
///        renders the same row set.
struct IdentityRow
{
    QString groupKey;      ///< Group key (e.g. "personal").
    QString fieldKey;      ///< Field key (e.g. "given_name").
    QString labelKey;      ///< Frozen i18n key the agent ships (e.g. "field.surname"); resolver input.
    QString labelFallback; ///< Agent-authored English label (display fallback only).
    QString value;         ///< Stringified value; binary fields are dropped entirely.
};

/// @brief Flatten an identity result's field groups into a neutral row list.
///
/// Takes the `AgentOperation::identityResult()` shape. Each `Field` carries
/// its wire metadata in `Field::extra` under the canonical keys "labelKey" /
/// "labelFallback" / "type" (type is "text" | "date" | "binary"); fields whose
/// type is "binary" (raw photos etc.) are skipped — they are not text rows.
/// Empty values are RETAINED (a tabular renderer shows them); a caller that
/// wants them dropped filters locally.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT QList<IdentityRow> flattenIdentityFields(const QList<FieldGroup>& groups);

} // namespace LibreSCRS::AgentClient
