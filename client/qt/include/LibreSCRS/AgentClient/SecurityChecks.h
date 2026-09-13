// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QList>
#include <QString>
#include <QStringView>

#include <cstdint>
#include <optional>

/// @file
/// @brief The one reader of a security-verdict group's wire shape.
///
/// A card plugin reports what it checked as ordinary identity fields, and the
/// field `value` is deliberately an open string — so no closed vocabulary can
/// describe the SHAPE those fields make between them. Left to each consumer,
/// that shape gets re-invented per consumer: three mutually incompatible
/// readings of the same group were live in this project at the same time, and
/// every one of them had a passing test, because each test measured a reader
/// against its own author's idea of the wire.
///
/// This is where that shape is owned instead. Both desktop clients build this
/// library, so a check separated here is a check separated the same way in all
/// of them.
///
/// @par What the library does NOT do
///
/// It never translates and never judges. `status`, `category` and `reason` come
/// back as the producer's own tokens; turning a token into words needs a
/// catalogue in the reader's language, and those live in the GUI hosts. In
/// particular `SecurityCheckEntry::reason` is a KEY, not a sentence.

namespace LibreSCRS::AgentClient {

/// @brief What kind of thing a check verified.
///
/// The producer names this with a token on the wire and the vocabulary is
/// closed. Decoding it is structure, not presentation: the enumerator says
/// which kind, and a host still needs its own catalogue to put a word on it.
///
/// `Other` is the honest landing place for a token this build has no
/// enumerator for, but only when a caller CHOOSES it — @ref LibreSCRS::AgentClient::categoryFromString
/// returns nothing rather than picking it, because a category nobody
/// recognised and a category explicitly outside the canonical three are
/// different situations.
enum class SecurityCategory : std::uint8_t {
    DataIntegrity, ///< Hash/MAC integrity of the data groups.
    Authenticity,  ///< Signature / passive authentication over the data.
    Genuineness,   ///< Chip genuineness (active authentication, chip auth).
    Other,         ///< A check outside the canonical categories.
};

/// @brief How a single check came out.
///
/// `NotPerformed` is not a failure and must never be rendered as one: a check
/// nobody ran says nothing about the card.
enum class SecurityCheckStatus : std::uint8_t {
    Passed,       ///< Performed and succeeded.
    Failed,       ///< Performed and failed.
    NotPerformed, ///< Not run (a prerequisite was missing).
    NotSupported, ///< The card does not implement the check.
    Skipped,      ///< The read chose to bypass the check.
};

/// @brief Decode a status token; nothing for a token this build cannot name.
///
/// Deliberately NOT defaulting to @ref LibreSCRS::AgentClient::SecurityCheckStatus::NotPerformed. That
/// is the safest-LOOKING wrong answer: it turns a verdict this build failed to
/// understand into a confident statement that no check ran, and a reader
/// cannot tell the two apart afterwards. The caller decides, in the open.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT std::optional<SecurityCheckStatus> statusFromString(QStringView token);

/// @brief Decode a category token; nothing for a token this build cannot name.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT std::optional<SecurityCategory> categoryFromString(QStringView token);

/// @brief One security check, its wire fields separated.
///
/// Every member is the producer's own text, verbatim. An absent field is an
/// empty string rather than a stand-in: a check that shipped no reason and a
/// check whose reason this build cannot name are different situations, and
/// only the caller knows what to show for either.
struct SecurityCheckEntry
{
    /// @brief The `N` of `check_<N>_<suffix>`, as text; empty for the joined shape.
    ///
    /// A positional ordinal on the wire and nothing more — never identity.
    /// Read @ref id to know WHICH check this is. Empty is the one thing it
    /// says on its own: this check arrived in the joined shape.
    QString ordinal;
    QString id;       ///< `check_<N>_id`; the joined shape's field KEY is the id.
    QString category; ///< `check_<N>_category`, raw token ("data_integrity", …); empty when absent.
    QString status;   ///< `check_<N>_status`, raw token ("PASSED", …); the joined value's leading word.
    QString label;    ///< `check_<N>_label`; for the joined shape, the field's `labelFallback`.
    QString detail;   ///< `check_<N>_detail` — producer-authored prose; the joined value's parenthetical.
    QString error;    ///< `check_<N>_error` — producer-authored diagnostic text; empty when absent.
    /// @brief `check_<N>_reason` — a stable KEY ("csca.not-configured"), never a sentence.
    ///
    /// Returned exactly as it arrived. A key a build does not recognise must
    /// never reach a reader raw, so resolving it — and deciding what an
    /// unknown one degrades to — is the caller's job, next to its catalogue.
    QString reason;
};

/// @brief A verdict group, separated: its checks, and everything else untouched.
struct SecurityVerdict
{
    /// @brief One entry per security check, ordered by ascending numeric
    ///        ordinal (so ten follows two) and therefore independent of the
    ///        order the fields arrived in — no producer promises one.
    ///        Joined-shape checks carry no ordinal and keep their arrival
    ///        order, after any structured ones.
    QList<SecurityCheckEntry> checks;
    /// @brief Every field not consumed as a check, in arrival order, byte for
    ///        byte as it arrived — the three `overall_*` aggregate verdicts,
    ///        the annex reader's `annex_*` pair, and any key this build does
    ///        not know. Carried, never reinterpreted.
    QList<Field> aggregates;
};

/// @brief Whether @p groupKey names a group whose values are verdicts rather
///        than card data.
///
/// The eMRTD plugin's `security_status`, and an annex reader's
/// `annex.<id>.security`. Scoped deliberately: a `personal` field whose value
/// happens to read "PASSED" is not a verdict, and a field keyed like a check
/// outside these groups is not a check.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT bool isSecurityVerdictGroup(const QString& groupKey);

/// @brief Separate a verdict group's flat fields into one entry per security
///        check, leaving the aggregate verdicts alone.
///
/// @param group Any field group from an identity read. Safe to call on every
///              group: one that is not a verdict group comes back with no
///              checks at all and ALL of its fields in
///              `SecurityVerdict::aggregates`, in order and unmodified —
///              so a caller may pipe every group through this without first
///              testing the scope itself.
///
/// @par The two shapes a check arrives in
///
/// A check normally travels as a family of fields — `check_<N>_id`,
/// `_category`, `_status`, `_label`, plus `_detail`, `_error` and `_reason`
/// when it carries them. A plugin that has not moved yet spells the same check
/// as ONE field whose key IS the check id and whose value is
/// `"STATUS (detail)"`; a client still renders those, so they are read too —
/// the leading word becomes `SecurityCheckEntry::status`, the remainder
/// (unwrapped from a single enclosing pair of parentheses) becomes
/// `SecurityCheckEntry::detail`, and the field's `labelFallback` becomes
/// `SecurityCheckEntry::label`.
///
/// The shape is decided ONCE PER GROUP, not per field: a group holding any
/// `check_<N>_<suffix>` field is structured, and every other key in it is then
/// an aggregate. Otherwise the group may be joined, and every key outside the
/// `overall_` / `annex_` aggregate prefixes is one check. Deciding per field
/// would let a single unfamiliar key in a modern group be rendered as a
/// security check nobody ran.
///
/// @par Suffixes this build does not know
///
/// Read and DROPPED — never surfaced, not as a member and not as a
/// pass-through field. A newer agent may append a suffix whose meaning has no
/// catalogue here yet, and putting its raw text on screen shows a person a
/// machine key. A check known ONLY by an unrecognised suffix therefore does
/// not appear at all: there is nothing this build could say about it.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT SecurityVerdict separateSecurityChecks(const FieldGroup& group);

} // namespace LibreSCRS::AgentClient
