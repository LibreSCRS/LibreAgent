// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>

#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using LibreSCRS::Agent::CardReadSnapshot;
using LibreSCRS::Agent::cleanseGroup;
using LibreSCRS::Agent::cleanseGroups;
using LibreSCRS::Agent::FieldType;
using LibreSCRS::Agent::GroupSnapshot;
using LibreSCRS::Agent::secureZero;

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

namespace {

// A value long enough to live on the heap, so its buffer outlives clear().
const std::string kLongValue = "ANA-SECRET-GIVEN-NAME-0123456789";

GroupSnapshot groupWithData()
{
    return {.groupKey = "personal",
            .labelKey = "group.personal",
            .labelFallback = "Personal",
            .fields = {{.fieldKey = "given_name",
                        .labelKey = "field.given_name",
                        .labelFallback = "Given name",
                        .type = FieldType::Text,
                        .textValue = kLongValue,
                        .binaryValue = {}},
                       {.fieldKey = "portrait",
                        .labelKey = "field.portrait",
                        .labelFallback = "Portrait",
                        .type = FieldType::Binary,
                        .textValue = {},
                        .binaryValue = std::vector<std::uint8_t>(64, 0xAB)}}};
}

} // namespace

TEST(SecureZero, ZeroesTheBytesOfAStringAndKeepsItsLength)
{
    std::string s = kLongValue;
    const char* const buffer = s.data();
    secureZero(s);
    EXPECT_EQ(s.size(), kLongValue.size());
    EXPECT_EQ(s.data(), buffer);
    EXPECT_TRUE(std::all_of(s.begin(), s.end(), [](char c) { return c == '\0'; }));
}

TEST(CardReadSnapshot, CleanseGroupZeroesTheObservedBuffersAndEmptiesThem)
{
    auto group = groupWithData();
    const char* const text = group.fields[0].textValue.data();
    const std::uint8_t* const bytes = group.fields[1].binaryValue.data();
    const auto textSize = group.fields[0].textValue.size();
    const auto binarySize = group.fields[1].binaryValue.size();

    cleanseGroup(group);

    EXPECT_TRUE(group.fields[0].textValue.empty());
    EXPECT_TRUE(group.fields[1].binaryValue.empty());
    // clear() keeps the storage, so the bytes the field held can still be read.
    EXPECT_TRUE(std::all_of(text, text + textSize, [](char c) { return c == '\0'; })) << "the text was not zeroed";
    EXPECT_TRUE(std::all_of(bytes, bytes + binarySize, [](std::uint8_t b) { return b == 0; }))
        << "the binary value was not zeroed";
    EXPECT_EQ(group.groupKey, "personal") << "only personal data is wiped, not the keys";
}

TEST(CardReadSnapshot, CleanseGroupsReachesEveryGroup)
{
    std::vector<GroupSnapshot> groups{groupWithData(), groupWithData()};
    const char* const second = groups[1].fields[0].textValue.data();
    cleanseGroups(groups);
    for (const auto& g : groups) {
        EXPECT_TRUE(g.fields[0].textValue.empty());
        EXPECT_TRUE(g.fields[1].binaryValue.empty());
    }
    EXPECT_EQ(second[0], '\0');
}
