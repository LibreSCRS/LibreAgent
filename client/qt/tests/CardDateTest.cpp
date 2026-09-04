// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The two-shape card-date rule, which both desktop hosts used to write out for
// themselves. Only the parsing half is here; what a host SHOWS for a value
// that is not a date is a decision with a catalogue behind it and stays in the
// host, which is why the empty optional is a distinct outcome and is asserted
// as one.
#include <LibreSCRS/AgentClient/IdentityRows.h>

#include <gtest/gtest.h>

#include <QString>

using LibreSCRS::AgentClient::normalizedCardDate;

TEST(CardDateTest, RawCardDigitsBecomeReadable)
{
    // What the annex reader actually ships: the card's own ddMMyyyy bytes.
    EXPECT_EQ(normalizedCardDate(QStringLiteral("06082016")), QStringLiteral("06.08.2016"));
    EXPECT_EQ(normalizedCardDate(QStringLiteral("01011999")), QStringLiteral("01.01.1999"));
}

TEST(CardDateTest, AnAlreadyReadableDateIsReturnedVerbatim)
{
    // Not re-parsed and re-rendered: the card's text is what the card signed.
    EXPECT_EQ(normalizedCardDate(QStringLiteral("06.08.2016")), QStringLiteral("06.08.2016"));
}

TEST(CardDateTest, AnImpossibleDateIsNotADate)
{
    // Parsing rather than pattern-matching is the whole point: eight digits in
    // the right shape are not a date if no such day exists.
    EXPECT_FALSE(normalizedCardDate(QStringLiteral("32012016")).has_value());
    EXPECT_FALSE(normalizedCardDate(QStringLiteral("01132016")).has_value());
    EXPECT_FALSE(normalizedCardDate(QStringLiteral("29022015")).has_value()); // 2015 is not a leap year
}

TEST(CardDateTest, ALeapDayInALeapYearIsADate)
{
    EXPECT_EQ(normalizedCardDate(QStringLiteral("29022016")), QStringLiteral("29.02.2016"));
}

TEST(CardDateTest, AnythingElseIsTheCardsNoDateMarker)
{
    // The placeholder shapes seen in the field, plus the empty value.
    EXPECT_FALSE(normalizedCardDate(QStringLiteral("00001")).has_value());
    EXPECT_FALSE(normalizedCardDate(QStringLiteral("00000000")).has_value());
    EXPECT_FALSE(normalizedCardDate(QStringLiteral("unknown")).has_value());
    EXPECT_FALSE(normalizedCardDate(QString()).has_value());
}
