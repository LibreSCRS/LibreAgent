// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The security vocabulary's decoders used to live in a desktop host, where
// nothing tested them: that host's widget suite has sixteen cases and every
// one of them is about drawing. So these are not a move of existing coverage;
// they are the first coverage this decoding has ever had.
#include <LibreSCRS/AgentClient/SecurityChecks.h>

#include <gtest/gtest.h>

#include <QString>
#include <QStringView>

#include <optional>

using LibreSCRS::AgentClient::categoryFromString;
using LibreSCRS::AgentClient::SecurityCategory;
using LibreSCRS::AgentClient::SecurityCheckStatus;
using LibreSCRS::AgentClient::statusFromString;

TEST(SecurityVocabularyTest, EveryStatusTokenDecodes)
{
    EXPECT_EQ(statusFromString(u"PASSED"), SecurityCheckStatus::Passed);
    EXPECT_EQ(statusFromString(u"FAILED"), SecurityCheckStatus::Failed);
    EXPECT_EQ(statusFromString(u"NOT_PERFORMED"), SecurityCheckStatus::NotPerformed);
    EXPECT_EQ(statusFromString(u"NOT_SUPPORTED"), SecurityCheckStatus::NotSupported);
    EXPECT_EQ(statusFromString(u"SKIPPED"), SecurityCheckStatus::Skipped);
}

TEST(SecurityVocabularyTest, EveryCategoryTokenDecodes)
{
    EXPECT_EQ(categoryFromString(u"data_integrity"), SecurityCategory::DataIntegrity);
    EXPECT_EQ(categoryFromString(u"data_authenticity"), SecurityCategory::Authenticity);
    EXPECT_EQ(categoryFromString(u"chip_genuineness"), SecurityCategory::Genuineness);
    EXPECT_EQ(categoryFromString(u"other"), SecurityCategory::Other);
}

// The rule this decoding exists to hold. Collapsing an unrecognised verdict
// onto NotPerformed is the safest-looking wrong answer: it turns "this build
// could not read the verdict" into "no check ran", and a reader downstream
// cannot tell the two apart. The vocabulary is closed and nothing is guessed.
TEST(SecurityVocabularyTest, AnUnknownTokenIsNothing)
{
    EXPECT_FALSE(statusFromString(u"MOSTLY_PASSED").has_value());
    EXPECT_FALSE(statusFromString(QStringView()).has_value());
    EXPECT_FALSE(categoryFromString(u"data_freshness").has_value());
    EXPECT_FALSE(categoryFromString(QStringView()).has_value());
}

TEST(SecurityVocabularyTest, TheTokensAreCaseSensitiveAndExact)
{
    // The producer writes them one way. Accepting a second spelling would make
    // this decoder tolerant of a producer that never existed.
    EXPECT_FALSE(statusFromString(u"passed").has_value());
    EXPECT_FALSE(statusFromString(u"NOT PERFORMED").has_value());
    EXPECT_FALSE(statusFromString(u"PASSED ").has_value());
    EXPECT_FALSE(categoryFromString(u"DATA_INTEGRITY").has_value());
}

// Parity with the producer, whose enum lives in the middleware's published
// plugin surface. The token lists below are TRANSCRIBED BY HAND from that
// header rather than derived from anything this library computes: a test that
// generated them from this side would agree with this side no matter what the
// producer said, which is exactly the failure it is meant to catch.
//
// The producer, LibreMiddleware include/LibreSCRS/Plugin/SecurityCheck.h,
// spells the status set "PASSED", "FAILED", "NOT_PERFORMED", "NOT_SUPPORTED",
// "SKIPPED" and the category set "data_integrity", "data_authenticity",
// "chip_genuineness", "other".
TEST(SecurityVocabularyTest, EveryProducerTokenIsAcceptedAndNothingElseIs)
{
    static constexpr const char16_t* kProducerStatuses[] = {u"PASSED", u"FAILED", u"NOT_PERFORMED", u"NOT_SUPPORTED",
                                                            u"SKIPPED"};
    static constexpr const char16_t* kProducerCategories[] = {u"data_integrity", u"data_authenticity",
                                                              u"chip_genuineness", u"other"};

    int statuses = 0;
    for (const char16_t* token : kProducerStatuses) {
        EXPECT_TRUE(statusFromString(QStringView(token)).has_value())
            << "the producer raises a status this reader refuses";
        ++statuses;
    }
    int categories = 0;
    for (const char16_t* token : kProducerCategories) {
        EXPECT_TRUE(categoryFromString(QStringView(token)).has_value())
            << "the producer raises a category this reader refuses";
        ++categories;
    }

    // Counted so the reader cannot grow a token the producer does not raise:
    // every enumerator must be reachable from exactly one producer token.
    EXPECT_EQ(statuses, 5);
    EXPECT_EQ(categories, 4);
    EXPECT_EQ(static_cast<int>(SecurityCheckStatus::Skipped), statuses - 1)
        << "the reader gained a status the producer's set does not cover";
    EXPECT_EQ(static_cast<int>(SecurityCategory::Other), categories - 1)
        << "the reader gained a category the producer's set does not cover";
}
