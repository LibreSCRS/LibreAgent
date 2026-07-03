// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure-logic exercise of the Card1.Sign parameter resolution: the magic-byte
// format sniffer, per-format default packaging, and the closed-set validators
// (the R4 out-of-vocabulary rejection).
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sp = LibreSCRS::Agent::Operations::SignatureParams;

namespace {
std::vector<std::uint8_t> bytes(std::initializer_list<int> v)
{
    std::vector<std::uint8_t> out;
    for (int b : v) {
        out.push_back(static_cast<std::uint8_t>(b));
    }
    return out;
}
} // namespace

TEST(SignatureParams, SniffsEachFormatFromMagicBytes)
{
    EXPECT_EQ(sp::sniffFormat(bytes({'%', 'P', 'D', 'F', '-', '1'})), "pades");
    EXPECT_EQ(sp::sniffFormat(bytes({'P', 'K', 0x03, 0x04})), "asice");
    EXPECT_EQ(sp::sniffFormat(bytes({'<', '?', 'x', 'm', 'l'})), "xades");
    EXPECT_EQ(sp::sniffFormat(bytes({'{', '"', 'a', '"'})), "jades");
    EXPECT_EQ(sp::sniffFormat(bytes({0x30, 0x82, 0x01})), "cades");
}

TEST(SignatureParams, SniffSkipsLeadingWhitespaceForTextFormats)
{
    EXPECT_EQ(sp::sniffFormat(bytes({' ', '\n', '\t', '<', 'x'})), "xades");
    EXPECT_EQ(sp::sniffFormat(bytes({'\r', '\n', '{', '}'})), "jades");
}

TEST(SignatureParams, SniffRejectsUnrecognisedLeadingBytes)
{
    EXPECT_FALSE(sp::sniffFormat(bytes({'h', 'e', 'l', 'l', 'o'})).has_value());
    EXPECT_FALSE(sp::sniffFormat({}).has_value());
}

TEST(SignatureParams, DefaultPackagingIsEnvelopeForContainerFormats)
{
    EXPECT_EQ(sp::defaultPackagingFor("pades"), "enveloped");
    EXPECT_EQ(sp::defaultPackagingFor("asice"), "enveloped");
    EXPECT_EQ(sp::defaultPackagingFor("cades"), "detached");
    EXPECT_EQ(sp::defaultPackagingFor("xades"), "detached");
    EXPECT_EQ(sp::defaultPackagingFor("jades"), "detached");
}

TEST(SignatureParams, ValidatorsAcceptVocabularyAndRejectEverythingElse)
{
    EXPECT_TRUE(sp::isKnownFormat("pades"));
    EXPECT_TRUE(sp::isKnownFormat("asice"));
    EXPECT_FALSE(sp::isKnownFormat("asics")) << "ASiC-S is explicitly out of scope (R4)";
    EXPECT_FALSE(sp::isKnownFormat("auto")) << "auto must be resolved before validation";
    EXPECT_FALSE(sp::isKnownFormat(""));

    EXPECT_TRUE(sp::isKnownLevel("b-b"));
    EXPECT_TRUE(sp::isKnownLevel("b-t"));
    EXPECT_TRUE(sp::isKnownLevel("b-lta"));
    EXPECT_FALSE(sp::isKnownLevel("b-x"));

    EXPECT_TRUE(sp::isKnownPackaging("enveloped"));
    EXPECT_TRUE(sp::isKnownPackaging("detached"));
    EXPECT_FALSE(sp::isKnownPackaging("enveloping")) << "enveloping is out of scope (R4)";
}

TEST(SignatureParams, ResolveSignLevelUpgradesDefaultedBbOnlyWhenTsaConfigured)
{
    // An explicit requested level always wins, regardless of the TSA state.
    EXPECT_EQ(sp::resolveSignLevel(std::string{"b-b"}, "b-b", /*hasTsa=*/true), "b-b")
        << "an explicit b-b is honoured even when a TSA is configured";
    EXPECT_EQ(sp::resolveSignLevel(std::string{"b-t"}, "b-b", /*hasTsa=*/false), "b-t")
        << "an explicit level wins regardless of the configured default / TSA state";

    // Only an UNSET (defaulted-to-b-b) level upgrades to b-t — and only when a TSA is set.
    EXPECT_EQ(sp::resolveSignLevel(std::nullopt, "b-b", /*hasTsa=*/true), "b-t")
        << "unset + a configured TSA derives b-t per request";
    EXPECT_EQ(sp::resolveSignLevel(std::nullopt, "b-b", /*hasTsa=*/false), "b-b") << "unset + no TSA stays b-b";

    // A non-b-b configured default is taken verbatim (no derivation either way).
    EXPECT_EQ(sp::resolveSignLevel(std::nullopt, "b-t", /*hasTsa=*/false), "b-t");
    EXPECT_EQ(sp::resolveSignLevel(std::nullopt, "b-t", /*hasTsa=*/true), "b-t");
}

TEST(SignatureParams, IsQualifiedSignLevelClassifiesTheTimestampedFamily)
{
    EXPECT_FALSE(sp::isQualifiedSignLevel("b-b"));
    EXPECT_TRUE(sp::isQualifiedSignLevel("b-t"));
    EXPECT_TRUE(sp::isQualifiedSignLevel("b-lt"));
    EXPECT_TRUE(sp::isQualifiedSignLevel("b-lta"));
}

TEST(SignatureParams, TimestampWasAppliedIsTruthfulNotALevelGuess)
{
    // tsaUsed must be honest: it is true only when the sign actually succeeded AT
    // a qualified level WITH a TSA configured. A bare level-guess (true whenever
    // the level is qualified, even with no TSA) is exactly what this replaces.
    EXPECT_TRUE(sp::timestampWasApplied(/*signOk=*/true, "b-t", /*hasTsa=*/true));
    EXPECT_FALSE(sp::timestampWasApplied(/*signOk=*/true, "b-b", /*hasTsa=*/true)) << "b-b never timestamps";
    EXPECT_FALSE(sp::timestampWasApplied(/*signOk=*/true, "b-t", /*hasTsa=*/false))
        << "a qualified level with no TSA did not actually timestamp";
    EXPECT_FALSE(sp::timestampWasApplied(/*signOk=*/false, "b-t", /*hasTsa=*/true))
        << "a failed sign timestamps nothing";
    EXPECT_TRUE(sp::timestampWasApplied(/*signOk=*/true, "b-lta", /*hasTsa=*/true));
}

TEST(SignatureParams, ImplementedSignLevelAdmitsTheWholeBaselineFamily)
{
    // The Card1.Sign scope gate: the LM now produces the full baseline family.
    // b-lt/b-lta complete the chain from the Trusted List and embed revocation;
    // the LM fails closed when the chain or revocation cannot be obtained.
    EXPECT_TRUE(sp::isImplementedSignLevel("b-b"));
    EXPECT_TRUE(sp::isImplementedSignLevel("b-t"));
    EXPECT_TRUE(sp::isImplementedSignLevel("b-lt"));
    EXPECT_TRUE(sp::isImplementedSignLevel("b-lta"));
    EXPECT_FALSE(sp::isImplementedSignLevel("b-x")) << "out-of-vocabulary is never implemented";
}

TEST(SignatureParams, ImplementedSignLevelsDisplayMatchesThePredicate)
{
    // The rejection message must be DRIVEN by the same list as the gate
    // predicate so they cannot drift (historical bug: predicate widened to
    // b-lt/b-lta while the message still said "only b-b and b-t"). Assert every
    // token in the display string is an implemented level, and that the display
    // names exactly the levels the predicate admits — no more, no fewer.
    const std::string display = sp::implementedSignLevelsDisplay();
    EXPECT_NE(display.find("b-b"), std::string::npos);
    EXPECT_NE(display.find("b-lta"), std::string::npos);

    std::size_t count = 0;
    for (const auto level : sp::kImplementedSignLevels) {
        EXPECT_TRUE(sp::isImplementedSignLevel(std::string{level}));
        EXPECT_NE(display.find(std::string{level}), std::string::npos)
            << "display must name every implemented level: " << level;
        ++count;
    }
    // The display joins with ", " — its comma count is one less than the level
    // count, proving it names exactly the predicate's levels (no stale extras).
    const auto commas = static_cast<std::size_t>(std::count(display.begin(), display.end(), ','));
    EXPECT_EQ(commas + 1, count);
}
