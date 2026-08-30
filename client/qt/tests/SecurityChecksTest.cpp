// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the ONE reader of a verdict group's wire shape. Two desktop clients
// render these fields, and before this function existed each carried its own
// understanding of them — three incompatible ones were live at the same time,
// every one of them with a passing test, because each test measured its own
// reader against its own idea of the wire.
//
// So the cases below are written against the shapes a PRODUCER can send, not
// against an implementation: both spellings of a check, a suffix this build
// has never heard of, a check that omits its optional fields, and the same
// fields delivered in a different order.

#include <LibreSCRS/AgentClient/SecurityChecks.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <ostream>

using namespace LibreSCRS::AgentClient;

// Readable diagnostics on a mismatch. Must live at namespace scope for gtest's
// unqualified lookup to find them.
inline void PrintTo(const QString& value, std::ostream* os)
{
    *os << '"' << value.toStdString() << '"';
}

inline void PrintTo(const QStringList& value, std::ostream* os)
{
    *os << '[' << value.join(QStringLiteral(", ")).toStdString() << ']';
}

namespace {

Field field(const QString& key, const QString& value, const QString& labelFallback = {})
{
    Field f;
    f.key = key;
    f.value = value;
    if (!labelFallback.isEmpty()) {
        f.extra.insert(QStringLiteral("labelFallback"), labelFallback);
    }
    return f;
}

FieldGroup group(const QString& key, QList<Field> fields)
{
    FieldGroup g;
    g.key = key;
    g.fields = std::move(fields);
    return g;
}

/// The structured shape of one complete check, as the eMRTD plugin ships it.
QList<Field> structuredCheck()
{
    return {
        field(QStringLiteral("overall_integrity"), QStringLiteral("PASSED"), QStringLiteral("Data Integrity")),
        field(QStringLiteral("overall_authenticity"), QStringLiteral("NOT_PERFORMED"),
              QStringLiteral("Data Authenticity")),
        field(QStringLiteral("check_0_id"), QStringLiteral("pa_csca_chain"), QStringLiteral("CSCA Chain")),
        field(QStringLiteral("check_0_category"), QStringLiteral("data_authenticity"), QStringLiteral("CSCA Chain")),
        field(QStringLiteral("check_0_status"), QStringLiteral("NOT_PERFORMED"), QStringLiteral("CSCA Chain")),
        field(QStringLiteral("check_0_label"), QStringLiteral("CSCA Certificate Chain"), QStringLiteral("CSCA Chain")),
        field(QStringLiteral("check_0_detail"), QStringLiteral("no anchors on this machine"),
              QStringLiteral("CSCA Chain")),
        field(QStringLiteral("check_0_error"), QStringLiteral("X509_STORE_load_path: no such file"),
              QStringLiteral("CSCA Chain")),
        field(QStringLiteral("check_0_reason"), QStringLiteral("csca.not-configured"), QStringLiteral("CSCA Chain")),
    };
}

QStringList aggregateKeys(const SecurityVerdict& verdict)
{
    QStringList keys;
    for (const Field& f : verdict.aggregates) {
        keys.append(f.key);
    }
    return keys;
}

} // namespace

TEST(SecurityChecks, VerdictGroupScopeCoversTheAnnexGroupsToo)
{
    EXPECT_TRUE(isSecurityVerdictGroup(QStringLiteral("security_status")));
    EXPECT_TRUE(isSecurityVerdictGroup(QStringLiteral("annex.rs_eid.security")));
    EXPECT_FALSE(isSecurityVerdictGroup(QStringLiteral("personal")));
    EXPECT_FALSE(isSecurityVerdictGroup(QStringLiteral("annex.rs_eid.personal")));
    EXPECT_FALSE(isSecurityVerdictGroup(QString()));
}

TEST(SecurityChecks, StructuredShapeSeparatesEverySuffix)
{
    const SecurityVerdict verdict = separateSecurityChecks(group(QStringLiteral("security_status"), structuredCheck()));

    ASSERT_EQ(verdict.checks.size(), 1) << "nine wire fields must not become nine checks";
    const SecurityCheckEntry& check = verdict.checks.at(0);
    EXPECT_EQ(check.ordinal, QStringLiteral("0"));
    EXPECT_EQ(check.id, QStringLiteral("pa_csca_chain"));
    EXPECT_EQ(check.category, QStringLiteral("data_authenticity"));
    EXPECT_EQ(check.status, QStringLiteral("NOT_PERFORMED"));
    EXPECT_EQ(check.label, QStringLiteral("CSCA Certificate Chain"));
    EXPECT_EQ(check.detail, QStringLiteral("no anchors on this machine"));
    EXPECT_EQ(check.error, QStringLiteral("X509_STORE_load_path: no such file"));
    EXPECT_EQ(check.reason, QStringLiteral("csca.not-configured"));
}

// The reason is a KEY. Resolving it into a sentence is the client's job — the
// catalogues live there, in the reader's language — so it must arrive here
// exactly as the producer spelled it, and must not be folded into any other
// member on the way.
TEST(SecurityChecks, ReasonComesBackAsTheKeyItArrivedAs)
{
    const SecurityVerdict verdict = separateSecurityChecks(group(QStringLiteral("security_status"), structuredCheck()));

    ASSERT_EQ(verdict.checks.size(), 1);
    EXPECT_EQ(verdict.checks.at(0).reason, QStringLiteral("csca.not-configured"));
    EXPECT_FALSE(verdict.checks.at(0).detail.contains(QStringLiteral("csca.")))
        << "the key must not be joined into the producer's own prose";
    EXPECT_FALSE(verdict.checks.at(0).status.contains(QStringLiteral("csca.")));
}

// Aggregates are carried, not interpreted: same keys, same values, same order,
// and the wire metadata still on them.
TEST(SecurityChecks, AggregateVerdictsAreLeftAlone)
{
    const SecurityVerdict verdict = separateSecurityChecks(group(QStringLiteral("security_status"), structuredCheck()));

    ASSERT_EQ(aggregateKeys(verdict),
              QStringList({QStringLiteral("overall_integrity"), QStringLiteral("overall_authenticity")}));
    EXPECT_EQ(verdict.aggregates.at(0).value, QStringLiteral("PASSED"));
    EXPECT_EQ(verdict.aggregates.at(1).value, QStringLiteral("NOT_PERFORMED"));
    EXPECT_EQ(verdict.aggregates.at(0).extra.value(QStringLiteral("labelFallback")).toString(),
              QStringLiteral("Data Integrity"));
}

// A plugin that has not moved still spells a check as ONE field whose key is
// the check id and whose value is "STATUS (detail)". A client renders those
// today; dropping the shape would blank a working display.
TEST(SecurityChecks, JoinedShapeStillBecomesOneCheck)
{
    const SecurityVerdict verdict = separateSecurityChecks(
        group(QStringLiteral("security_status"),
              {
                  field(QStringLiteral("overall_authenticity"), QStringLiteral("NOT_PERFORMED")),
                  field(QStringLiteral("pa_csca_chain"), QStringLiteral("NOT_PERFORMED (no store)"),
                        QStringLiteral("CSCA Certificate Chain")),
              }));

    ASSERT_EQ(verdict.checks.size(), 1);
    const SecurityCheckEntry& check = verdict.checks.at(0);
    EXPECT_EQ(check.id, QStringLiteral("pa_csca_chain")) << "the joined field's KEY is the check id";
    EXPECT_EQ(check.status, QStringLiteral("NOT_PERFORMED"));
    EXPECT_EQ(check.detail, QStringLiteral("no store")) << "the parenthetical is the detail, unwrapped";
    EXPECT_EQ(check.label, QStringLiteral("CSCA Certificate Chain"));
    EXPECT_TRUE(check.ordinal.isEmpty()) << "the joined shape carries no ordinal";
    EXPECT_TRUE(check.reason.isEmpty());
    EXPECT_EQ(aggregateKeys(verdict), QStringList({QStringLiteral("overall_authenticity")}));
}

TEST(SecurityChecks, JoinedShapeWithNoDetailHasNoDetail)
{
    const SecurityVerdict verdict = separateSecurityChecks(
        group(QStringLiteral("security_status"), {field(QStringLiteral("chip_auth"), QStringLiteral("PASSED"))}));

    ASSERT_EQ(verdict.checks.size(), 1);
    EXPECT_EQ(verdict.checks.at(0).status, QStringLiteral("PASSED"));
    EXPECT_TRUE(verdict.checks.at(0).detail.isEmpty());
}

// A newer agent may append a suffix this build has never heard of. Rendering it
// raw puts a machine key in front of a person; it is read and dropped, and it
// reaches no member of the entry and no aggregate either.
TEST(SecurityChecks, UnrecognisedSuffixIsIgnoredNotSurfaced)
{
    const SecurityVerdict verdict = separateSecurityChecks(
        group(QStringLiteral("security_status"),
              {
                  field(QStringLiteral("check_0_id"), QStringLiteral("pa_csca_chain")),
                  field(QStringLiteral("check_0_status"), QStringLiteral("NOT_PERFORMED")),
                  field(QStringLiteral("check_0_futuresuffix"), QStringLiteral("something a newer agent sends")),
              }));

    ASSERT_EQ(verdict.checks.size(), 1) << "an unrecognised suffix must not become its own check";
    const SecurityCheckEntry& check = verdict.checks.at(0);
    EXPECT_EQ(check.id, QStringLiteral("pa_csca_chain"));
    EXPECT_EQ(check.status, QStringLiteral("NOT_PERFORMED"));
    for (const QString& member : {check.category, check.label, check.detail, check.error, check.reason}) {
        EXPECT_FALSE(member.contains(QStringLiteral("newer agent"))) << "value leaked into: " << member.toStdString();
    }
    EXPECT_TRUE(verdict.aggregates.isEmpty()) << "nor may it escape as a pass-through field";
}

// A check that ships only what it must: everything optional comes back empty
// rather than defaulted to something that reads like an answer.
TEST(SecurityChecks, OptionalFieldsAbsentComeBackEmpty)
{
    const SecurityVerdict verdict = separateSecurityChecks(
        group(QStringLiteral("security_status"), {
                                                     field(QStringLiteral("check_1_id"), QStringLiteral("chip_auth")),
                                                     field(QStringLiteral("check_1_status"), QStringLiteral("PASSED")),
                                                 }));

    ASSERT_EQ(verdict.checks.size(), 1);
    const SecurityCheckEntry& check = verdict.checks.at(0);
    EXPECT_EQ(check.ordinal, QStringLiteral("1"));
    EXPECT_TRUE(check.category.isEmpty());
    EXPECT_TRUE(check.label.isEmpty());
    EXPECT_TRUE(check.detail.isEmpty());
    EXPECT_TRUE(check.error.isEmpty());
    EXPECT_TRUE(check.reason.isEmpty());
}

// No producer promises a field order, so no consumer may depend on one. The
// same fields shuffled must yield the same checks, in the same sequence.
TEST(SecurityChecks, WireFieldOrderDoesNotChangeTheChecks)
{
    QList<Field> fields = structuredCheck();
    fields.append(field(QStringLiteral("check_1_id"), QStringLiteral("chip_auth")));
    fields.append(field(QStringLiteral("check_1_status"), QStringLiteral("PASSED")));
    fields.append(field(QStringLiteral("check_1_label"), QStringLiteral("Chip Authentication")));

    const SecurityVerdict forward = separateSecurityChecks(group(QStringLiteral("security_status"), fields));

    QList<Field> reversed = fields;
    std::reverse(reversed.begin(), reversed.end());
    const SecurityVerdict backward = separateSecurityChecks(group(QStringLiteral("security_status"), reversed));

    ASSERT_EQ(forward.checks.size(), 2);
    ASSERT_EQ(backward.checks.size(), forward.checks.size());
    for (qsizetype i = 0; i < forward.checks.size(); ++i) {
        EXPECT_EQ(backward.checks.at(i).ordinal, forward.checks.at(i).ordinal);
        EXPECT_EQ(backward.checks.at(i).id, forward.checks.at(i).id);
        EXPECT_EQ(backward.checks.at(i).category, forward.checks.at(i).category);
        EXPECT_EQ(backward.checks.at(i).status, forward.checks.at(i).status);
        EXPECT_EQ(backward.checks.at(i).label, forward.checks.at(i).label);
        EXPECT_EQ(backward.checks.at(i).detail, forward.checks.at(i).detail);
        EXPECT_EQ(backward.checks.at(i).error, forward.checks.at(i).error);
        EXPECT_EQ(backward.checks.at(i).reason, forward.checks.at(i).reason);
    }
    EXPECT_EQ(forward.checks.at(0).id, QStringLiteral("pa_csca_chain"));
    EXPECT_EQ(forward.checks.at(1).id, QStringLiteral("chip_auth"));
}

// The ordinal is a number on the wire, so ten sorts after two. Three checks,
// aiming at the middle one: two entries cannot tell an off-by-one from a
// working comparison.
TEST(SecurityChecks, ChecksAreOrderedByOrdinalNumericallyNotAsText)
{
    const SecurityVerdict verdict = separateSecurityChecks(
        group(QStringLiteral("security_status"), {
                                                     field(QStringLiteral("check_10_id"), QStringLiteral("third")),
                                                     field(QStringLiteral("check_2_id"), QStringLiteral("second")),
                                                     field(QStringLiteral("check_1_id"), QStringLiteral("first")),
                                                 }));

    ASSERT_EQ(verdict.checks.size(), 3);
    EXPECT_EQ(verdict.checks.at(0).id, QStringLiteral("first"));
    EXPECT_EQ(verdict.checks.at(1).id, QStringLiteral("second"));
    EXPECT_EQ(verdict.checks.at(2).id, QStringLiteral("third"));
}

// The annex reader ships a verdict group whose two fields are aggregates and
// whose checks are none at all.
TEST(SecurityChecks, AnnexVerdictGroupIsAllAggregateAndNoChecks)
{
    const SecurityVerdict verdict = separateSecurityChecks(
        group(QStringLiteral("annex.rs_eid.security"),
              {
                  field(QStringLiteral("annex_integrity"), QStringLiteral("PASSED"), QStringLiteral("Data Integrity")),
                  field(QStringLiteral("annex_authenticity"), QStringLiteral("NOT_PERFORMED"),
                        QStringLiteral("Data Authenticity")),
              }));

    EXPECT_TRUE(verdict.checks.isEmpty());
    EXPECT_EQ(aggregateKeys(verdict),
              QStringList({QStringLiteral("annex_integrity"), QStringLiteral("annex_authenticity")}));
}

// Once a group speaks the structured shape, a key that is not a check field is
// an aggregate — never a joined check. Otherwise one unfamiliar key in a modern
// group would be rendered as a security check nobody ran.
TEST(SecurityChecks, StructuredGroupNeverReadsAStrayKeyAsAJoinedCheck)
{
    const SecurityVerdict verdict =
        separateSecurityChecks(group(QStringLiteral("security_status"),
                                     {
                                         field(QStringLiteral("check_0_id"), QStringLiteral("pa_csca_chain")),
                                         field(QStringLiteral("check_0_status"), QStringLiteral("PASSED")),
                                         field(QStringLiteral("something_new"), QStringLiteral("PASSED (whatever)")),
                                     }));

    ASSERT_EQ(verdict.checks.size(), 1);
    EXPECT_EQ(verdict.checks.at(0).id, QStringLiteral("pa_csca_chain"));
    EXPECT_EQ(aggregateKeys(verdict), QStringList({QStringLiteral("something_new")}));
    EXPECT_EQ(verdict.aggregates.at(0).value, QStringLiteral("PASSED (whatever)")) << "carried, not reinterpreted";
}

// The scoping is on the GROUP. A personal field that happens to be keyed like a
// check is card data, and comes back untouched.
TEST(SecurityChecks, NonVerdictGroupComesBackWholeWithNoChecks)
{
    const QList<Field> fields{
        field(QStringLiteral("check_0_id"), QStringLiteral("looks like a check")),
        field(QStringLiteral("surname"), QStringLiteral("Doe")),
    };
    const SecurityVerdict verdict = separateSecurityChecks(group(QStringLiteral("personal"), fields));

    EXPECT_TRUE(verdict.checks.isEmpty());
    ASSERT_EQ(verdict.aggregates.size(), fields.size());
    EXPECT_EQ(aggregateKeys(verdict), QStringList({QStringLiteral("check_0_id"), QStringLiteral("surname")}));
    EXPECT_EQ(verdict.aggregates.at(0).value, QStringLiteral("looks like a check"));
}

TEST(SecurityChecks, EmptyGroupYieldsNothing)
{
    const SecurityVerdict verdict = separateSecurityChecks(group(QStringLiteral("security_status"), {}));
    EXPECT_TRUE(verdict.checks.isEmpty());
    EXPECT_TRUE(verdict.aggregates.isEmpty());
}
