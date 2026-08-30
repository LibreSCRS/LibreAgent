// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/SecurityChecks.h>

#include "FieldExtraKeys.h"

#include <QHash>
#include <QLatin1StringView>

#include <algorithm>
#include <optional>
#include <utility>

namespace LibreSCRS::AgentClient {

namespace {

constexpr QLatin1StringView kCheckPrefix{"check_"};

/// The key prefixes a verdict group uses for its AGGREGATE verdicts — the
/// roll-ups that describe the whole document rather than one check. Everything
/// else in a group that is not speaking the structured shape is a check in the
/// joined shape, whose key is the check id itself.
constexpr QLatin1StringView kAggregateOverallPrefix{"overall_"};
constexpr QLatin1StringView kAggregateAnnexPrefix{"annex_"};

/// One `check_<N>_<suffix>` field key, split.
struct CheckFieldKey
{
    QString ordinal;      ///< The `N` as text — kept for the caller, never arithmetic.
    qulonglong order = 0; ///< The same `N` as a number, for ordering only.
    QString suffix;       ///< `id` / `category` / `status` / `label` / `detail` / `error` / `reason` / …
};

/// Splits @p fieldKey as `check_<digits>_<suffix>`; nothing when it is not that
/// shape. The joined shape, whose key IS a check id, never matches — and
/// neither does an ordinal too large to be a number, which is a malformed
/// producer rather than a check this build should try to place in an order.
std::optional<CheckFieldKey> parseCheckFieldKey(const QString& fieldKey)
{
    if (!fieldKey.startsWith(kCheckPrefix)) {
        return std::nullopt;
    }
    const qsizetype digitsBegin = kCheckPrefix.size();
    qsizetype i = digitsBegin;
    while (i < fieldKey.size() && fieldKey.at(i).isDigit()) {
        ++i;
    }
    if (i == digitsBegin || i >= fieldKey.size() || fieldKey.at(i) != QLatin1Char('_')) {
        return std::nullopt;
    }
    CheckFieldKey parsed;
    parsed.suffix = fieldKey.mid(i + 1);
    if (parsed.suffix.isEmpty()) {
        return std::nullopt;
    }
    parsed.ordinal = fieldKey.mid(digitsBegin, i - digitsBegin);
    bool numeric = false;
    parsed.order = QStringView{parsed.ordinal}.toULongLong(&numeric);
    if (!numeric) {
        return std::nullopt;
    }
    return parsed;
}

bool isAggregateKey(const QString& fieldKey)
{
    return fieldKey.startsWith(kAggregateOverallPrefix) || fieldKey.startsWith(kAggregateAnnexPrefix);
}

/// Writes @p value onto the member @p suffix names. Returns false for a suffix
/// this build has no member for — the caller drops it, and drops it so
/// thoroughly that a check known only by such a suffix never appears: its raw
/// text has no place a reader could make sense of.
bool assignSuffix(SecurityCheckEntry& entry, const QString& suffix, const QString& value)
{
    if (suffix == QLatin1String("id")) {
        entry.id = value;
    } else if (suffix == QLatin1String("category")) {
        entry.category = value;
    } else if (suffix == QLatin1String("status")) {
        entry.status = value;
    } else if (suffix == QLatin1String("label")) {
        entry.label = value;
    } else if (suffix == QLatin1String("detail")) {
        entry.detail = value;
    } else if (suffix == QLatin1String("error")) {
        entry.error = value;
    } else if (suffix == QLatin1String("reason")) {
        entry.reason = value;
    } else {
        return false;
    }
    return true;
}

/// The joined shape's `"STATUS (detail)"`, split into its two halves. The
/// leading word is taken as the status WITHOUT being checked against any
/// vocabulary: the wire's status set is append-only, and a token this build has
/// never heard of is a verdict a newer agent is reporting correctly.
SecurityCheckEntry joinedCheck(const Field& field)
{
    SecurityCheckEntry entry;
    entry.id = field.key;
    entry.label = field.extra.value(kFieldExtraLabelFallback).toString();

    const qsizetype split = field.value.indexOf(QLatin1Char(' '));
    if (split < 0) {
        entry.status = field.value;
        return entry;
    }
    entry.status = field.value.left(split);
    QString detail = field.value.mid(split + 1);
    if (detail.size() >= 2 && detail.startsWith(QLatin1Char('(')) && detail.endsWith(QLatin1Char(')'))) {
        // Unwrap exactly one enclosing pair, so a client that re-joins the two
        // halves for display does not print "((no store))". Anything nested
        // inside is the producer's own text and stays.
        detail = detail.mid(1, detail.size() - 2);
    }
    entry.detail = std::move(detail);
    return entry;
}

/// A check under assembly, with the number it will be ordered by.
struct CheckSlot
{
    qulonglong order = 0;
    SecurityCheckEntry entry;
};

} // namespace

bool isSecurityVerdictGroup(const QString& groupKey)
{
    return groupKey == QLatin1String("security_status") ||
           (groupKey.startsWith(QLatin1String("annex.")) && groupKey.endsWith(QLatin1String(".security")));
}

SecurityVerdict separateSecurityChecks(const FieldGroup& group)
{
    SecurityVerdict verdict;
    if (!isSecurityVerdictGroup(group.key)) {
        // Not this function's business. Handing the fields straight back lets a
        // caller run every group through here instead of keeping its own copy
        // of the scope rule — which is how the scope came to be spelled two
        // different ways in the first place.
        verdict.aggregates = group.fields;
        return verdict;
    }

    // The shape is a property of the GROUP: one structured field anywhere in it
    // settles the question for every other key present.
    const bool structured = std::any_of(group.fields.cbegin(), group.fields.cend(),
                                        [](const Field& field) { return parseCheckFieldKey(field.key).has_value(); });

    // Not `slots`: Qt's keyword macro expands that to nothing.
    QList<CheckSlot> checkSlots;
    QHash<QString, qsizetype> slotByOrdinal;

    for (const Field& field : group.fields) {
        if (!structured) {
            if (isAggregateKey(field.key)) {
                verdict.aggregates.append(field);
            } else {
                CheckSlot slot;
                slot.order = static_cast<qulonglong>(checkSlots.size());
                slot.entry = joinedCheck(field);
                checkSlots.append(std::move(slot));
            }
            continue;
        }

        const std::optional<CheckFieldKey> parsed = parseCheckFieldKey(field.key);
        if (!parsed) {
            verdict.aggregates.append(field);
            continue;
        }

        const auto known = slotByOrdinal.constFind(parsed->ordinal);
        if (known == slotByOrdinal.constEnd()) {
            // A slot is opened only by a suffix this build can store. Opening
            // one for an unrecognised suffix would put a check with every
            // member empty in front of a reader — a blank row that says a
            // check exists and nothing else.
            SecurityCheckEntry entry;
            if (!assignSuffix(entry, parsed->suffix, field.value)) {
                continue;
            }
            entry.ordinal = parsed->ordinal;
            slotByOrdinal.insert(parsed->ordinal, checkSlots.size());
            checkSlots.append(CheckSlot{parsed->order, std::move(entry)});
            continue;
        }
        // Same rule for a check already opened: a suffix with no member here
        // is read and dropped, never surfaced.
        assignSuffix(checkSlots[*known].entry, parsed->suffix, field.value);
    }

    // Ascending ordinal, so the result does not depend on the order the fields
    // arrived in. Stable, so the joined shape — where every slot carries its
    // arrival position and no producer-assigned number — keeps its own order.
    std::stable_sort(checkSlots.begin(), checkSlots.end(),
                     [](const CheckSlot& a, const CheckSlot& b) { return a.order < b.order; });

    verdict.checks.reserve(checkSlots.size());
    for (CheckSlot& slot : checkSlots) {
        verdict.checks.append(std::move(slot.entry));
    }
    return verdict;
}

} // namespace LibreSCRS::AgentClient
