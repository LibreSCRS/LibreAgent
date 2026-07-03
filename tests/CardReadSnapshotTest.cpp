// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/value/CardReadSnapshot.h>

#include <gtest/gtest.h>
#include <vector>

using LibreSCRS::Agent::CardReadSnapshot;
using LibreSCRS::Agent::FieldType;

TEST(CardReadSnapshot, DefaultIsEmpty)
{
    CardReadSnapshot snap;
    EXPECT_TRUE(snap.empty());
    EXPECT_TRUE(snap.groups.empty());
}

TEST(CardReadSnapshot, PopulatedReportsNonEmpty)
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    snap.groups.push_back({.groupKey = "personal",
                           .labelKey = "group.personal",
                           .labelFallback = "Personal",
                           .fields = {{.fieldKey = "given_name",
                                       .labelKey = "field.given_name",
                                       .labelFallback = "Given name",
                                       .type = FieldType::Text,
                                       .textValue = "ANA",
                                       .binaryValue = {}}}});
    EXPECT_FALSE(snap.empty());
    ASSERT_EQ(snap.groups.size(), 1u);
    EXPECT_EQ(snap.groups[0].fields[0].type, FieldType::Text);
    EXPECT_EQ(snap.groups[0].fields[0].textValue, "ANA");
}

TEST(CardReadSnapshot, FieldTypeAllValuesPresent)
{
    EXPECT_EQ(static_cast<int>(FieldType::Text), 0);
    EXPECT_EQ(static_cast<int>(FieldType::Date), 1);
    EXPECT_EQ(static_cast<int>(FieldType::Binary), 2);
    EXPECT_EQ(static_cast<int>(FieldType::Photo), 3);
}

TEST(CardReadSnapshot, BinaryAndPhotoFieldsCarryBytes)
{
    CardReadSnapshot snap;
    snap.groups.push_back({.groupKey = "photo",
                           .labelKey = "group.photo",
                           .labelFallback = "Photo",
                           .fields = {{.fieldKey = "portrait",
                                       .labelKey = "field.portrait",
                                       .labelFallback = "Portrait",
                                       .type = FieldType::Photo,
                                       .textValue = {},
                                       .binaryValue = {0xFF, 0xD8, 0xFF, 0xE0}}}});
    EXPECT_FALSE(snap.empty());
    EXPECT_EQ(snap.groups[0].fields[0].binaryValue.size(), 4u);
}
