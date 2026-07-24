// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/IdentityRows.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

namespace {

Field makeField(const QString& key, const QString& value, const QString& labelKey, const QString& labelFallback,
                const QString& type)
{
    Field f;
    f.key = key;
    f.value = value;
    f.extra.insert(QStringLiteral("labelKey"), labelKey);
    f.extra.insert(QStringLiteral("labelFallback"), labelFallback);
    f.extra.insert(QStringLiteral("type"), type);
    return f;
}

} // namespace

TEST(IdentityRows, FlattensGroupsIntoRowsWithLabelKeys)
{
    FieldGroup personal;
    personal.key = QStringLiteral("personal");
    personal.fields.append(makeField(QStringLiteral("surname"), QStringLiteral("Doe"), QStringLiteral("field.surname"),
                                     QStringLiteral("Surname"), QStringLiteral("text")));
    personal.fields.append(makeField(QStringLiteral("date_of_birth"), QStringLiteral("1990-01-01"),
                                     QStringLiteral("field.date_of_birth"), QStringLiteral("Date of Birth"),
                                     QStringLiteral("date")));

    const QList<IdentityRow> rows = flattenIdentityFields({personal});
    ASSERT_EQ(rows.size(), 2);
    EXPECT_EQ(rows[0].groupKey, QStringLiteral("personal"));
    EXPECT_EQ(rows[0].fieldKey, QStringLiteral("surname"));
    EXPECT_EQ(rows[0].labelKey, QStringLiteral("field.surname"));
    EXPECT_EQ(rows[0].labelFallback, QStringLiteral("Surname"));
    EXPECT_EQ(rows[0].value, QStringLiteral("Doe"));
    EXPECT_EQ(rows[1].fieldKey, QStringLiteral("date_of_birth"));
    EXPECT_EQ(rows[1].value, QStringLiteral("1990-01-01"));
}

TEST(IdentityRows, BinaryFieldsAreSkipped)
{
    // Raw photos etc. are not text rows — the single skip-binary rule.
    FieldGroup group;
    group.key = QStringLiteral("personal");
    Field photo = makeField(QStringLiteral("photo"), QString(), QStringLiteral("field.photo"), QStringLiteral("Photo"),
                            QStringLiteral("binary"));
    photo.detail = QByteArray("\xFF\xD8\xFF", 3);
    group.fields.append(photo);
    group.fields.append(makeField(QStringLiteral("surname"), QStringLiteral("Doe"), QStringLiteral("field.surname"),
                                  QStringLiteral("Surname"), QStringLiteral("text")));

    const QList<IdentityRow> rows = flattenIdentityFields({group});
    ASSERT_EQ(rows.size(), 1);
    EXPECT_EQ(rows[0].fieldKey, QStringLiteral("surname"));
}

TEST(IdentityRows, EmptyValuesAreRetained)
{
    // A tabular renderer shows empty values; a caller that wants them dropped
    // filters locally.
    FieldGroup group;
    group.key = QStringLiteral("address");
    group.fields.append(makeField(QStringLiteral("street"), QString(), QStringLiteral("field.street"),
                                  QStringLiteral("Street"), QStringLiteral("text")));

    const QList<IdentityRow> rows = flattenIdentityFields({group});
    ASSERT_EQ(rows.size(), 1);
    EXPECT_TRUE(rows[0].value.isEmpty());
}

TEST(IdentityRows, FieldsWithoutTypeMetadataAreTreatedAsText)
{
    // A producer that omits the canonical extra keys still yields rows (the
    // type check only SKIPS an explicit "binary").
    Field bare;
    bare.key = QStringLiteral("custom");
    bare.value = QStringLiteral("v");
    FieldGroup group;
    group.key = QStringLiteral("g");
    group.fields.append(bare);

    const QList<IdentityRow> rows = flattenIdentityFields({group});
    ASSERT_EQ(rows.size(), 1);
    EXPECT_EQ(rows[0].value, QStringLiteral("v"));
    EXPECT_TRUE(rows[0].labelKey.isEmpty());
}

TEST(IdentityRows, MultipleGroupsPreserveOrder)
{
    FieldGroup a;
    a.key = QStringLiteral("a");
    a.fields.append(makeField(QStringLiteral("f1"), QStringLiteral("1"), {}, {}, QStringLiteral("text")));
    FieldGroup b;
    b.key = QStringLiteral("b");
    b.fields.append(makeField(QStringLiteral("f2"), QStringLiteral("2"), {}, {}, QStringLiteral("text")));

    const QList<IdentityRow> rows = flattenIdentityFields({a, b});
    ASSERT_EQ(rows.size(), 2);
    EXPECT_EQ(rows[0].groupKey, QStringLiteral("a"));
    EXPECT_EQ(rows[1].groupKey, QStringLiteral("b"));
}
