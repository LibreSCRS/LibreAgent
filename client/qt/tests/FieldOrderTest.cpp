// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The reading order is a contract two desktop hosts and this library share.
// The literals below are written out by hand rather than compared against the
// implementation's own list: a test that asks the code what it thinks the
// order is agrees with every reordering the code ever makes.
#include <LibreSCRS/AgentClient/FieldOrder.h>

#include <gtest/gtest.h>

#include <QStringList>

using LibreSCRS::AgentClient::fieldOrderForGroup;

namespace {

const QStringList kAnnexPersonalOrder = {
    QStringLiteral("address_label"),     QStringLiteral("street"),
    QStringLiteral("house_number"),      QStringLiteral("house_letter"),
    QStringLiteral("entrance"),          QStringLiteral("floor"),
    QStringLiteral("apartment_number"),  QStringLiteral("place"),
    QStringLiteral("community"),         QStringLiteral("state"),
    QStringLiteral("parent_given_name"), QStringLiteral("community_of_birth"),
    QStringLiteral("state_of_birth"),    QStringLiteral("document_serial"),
    QStringLiteral("address_date"),
};

} // namespace

TEST(FieldOrderTest, AnnexPersonalReadsAsAnAddress)
{
    EXPECT_EQ(fieldOrderForGroup(QStringLiteral("annex.0.personal")), kAnnexPersonalOrder);
}

TEST(FieldOrderTest, TheAnnexIdIsNotPartOfTheMatch)
{
    // The id is minted per annex and is foreign input; only the prefix and the
    // suffix decide the order.
    EXPECT_EQ(fieldOrderForGroup(QStringLiteral("annex.7fa1.personal")), kAnnexPersonalOrder);
    EXPECT_EQ(fieldOrderForGroup(QStringLiteral("annex..personal")), kAnnexPersonalOrder);
}

TEST(FieldOrderTest, StreetPrecedesApartmentWhichTheSortedWireWouldNot)
{
    // The whole reason this list exists: byte order of the keys puts
    // "apartment_number" before "street".
    const QStringList order = fieldOrderForGroup(QStringLiteral("annex.0.personal"));
    ASSERT_FALSE(order.isEmpty());
    EXPECT_LT(order.indexOf(QStringLiteral("street")), order.indexOf(QStringLiteral("apartment_number")));
    EXPECT_LT(QStringLiteral("apartment_number").compare(QStringLiteral("street")), 0);
}

TEST(FieldOrderTest, AnnexSecurityReadsIntegrityThenAuthenticity)
{
    EXPECT_EQ(fieldOrderForGroup(QStringLiteral("annex.0.security")),
              QStringList({QStringLiteral("annex_integrity"), QStringLiteral("annex_authenticity")}));
}

TEST(FieldOrderTest, AGroupWithNoPrescribedOrderReturnsEmpty)
{
    // Empty means "keep delivery order", which is a different statement from
    // any list this function could invent.
    EXPECT_TRUE(fieldOrderForGroup(QStringLiteral("personal")).isEmpty());
    EXPECT_TRUE(fieldOrderForGroup(QStringLiteral("annex.0.unknown")).isEmpty());
    EXPECT_TRUE(fieldOrderForGroup(QStringLiteral("notannex.0.personal")).isEmpty());
    EXPECT_TRUE(fieldOrderForGroup(QString()).isEmpty());
}
