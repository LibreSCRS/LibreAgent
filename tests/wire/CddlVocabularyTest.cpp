// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <CddlVocabulary.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

using LibreSCRS::Wire::Tools::cddlQuotedTokens;
using LibreSCRS::Wire::Tools::cddlRuleRhs;
using LibreSCRS::Wire::Tools::discoverClosedGroups;
using LibreSCRS::Wire::Tools::firstDuplicateToken;
using LibreSCRS::Wire::Tools::GroupKind;
using LibreSCRS::Wire::Tools::parseCddlNumericGroup;

namespace {
// A miniature grammar carrying one of each shape the real contract uses, plus
// two shapes that must NOT be mistaken for closed vocabularies: an open string
// field and a map group.
const std::string kSample = R"(
; shape 1: a numeric socket
colour-code = &( Red: 0, Green: 1, Blue: 2 )
; shape 2: a PLAIN numeric group -- how a .bits right-hand side is written
flag-bit = ( Alpha: 0, Beta: 1 )
; shape 3: a token alternation
fruit = "apple" / "pear"
; NOT a vocabulary: a plain group whose entries carry TYPES, not integers.
; This is how messages are declared, and mistaking one for a vocabulary is the
; trap that makes shape 2 delicate.
do-thing = ( t: "DoThing", card: handle, ? force: bool )
; NOT a vocabulary: an open string field inside a map
opts = { name: tstr, level: tstr }
; NOT a vocabulary: a commented-out entry must not be read
stale-code = &( Live: 0 ; , Dead: 1
  )
)";

// A boundary-eroded pair: `next` is missing its own name and '=', so
// cddlRuleRhs capturing `kind` never sees a new rule start and runs straight
// into `next`'s body instead of stopping at the true boundary. This is the
// exact shape a mis-edited grammar produces when a rule's start is lost
// without deleting the rule's own name -- the case the generator's duplicate
// check exists to catch, since the absorbed body's "unknown" collides with
// `kind`'s own.
const std::string kBoundaryEroded = R"(
kind      = "user" / "sign" / "unknown"
            "unknown" / "other"
next-rule = "x" / "y"
)";
} // namespace

TEST(CddlVocabulary, ParsesAnyNumericGroupByName)
{
    const auto entries = parseCddlNumericGroup(kSample, "colour-code");
    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(entries[0].value, 0u);
    EXPECT_EQ(entries[0].name, "Red");
    EXPECT_EQ(entries[2].value, 2u);
    EXPECT_EQ(entries[2].name, "Blue");
}

TEST(CddlVocabulary, NumericGroupIgnoresCommentedEntries)
{
    const auto entries = parseCddlNumericGroup(kSample, "stale-code");
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].name, "Live");
}

TEST(CddlVocabulary, UnknownRuleYieldsNothing)
{
    EXPECT_TRUE(parseCddlNumericGroup(kSample, "no-such-rule").empty());
}

TEST(CddlVocabulary, ParsesAPlainNumericGroup)
{
    // The capability bits are written this way in the real grammar, so a
    // reader that only understands `&( ... )` would miss them silently.
    const auto entries = parseCddlNumericGroup(kSample, "flag-bit");
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].name, "Alpha");
    EXPECT_EQ(entries[1].value, 1u);
}

TEST(CddlVocabulary, DiscoversAllThreeClosedShapesAndNothingElse)
{
    const auto groups = discoverClosedGroups(kSample);

    const auto has = [&groups](const std::string& rule, GroupKind kind) {
        return std::any_of(groups.begin(), groups.end(),
                           [&](const auto& g) { return g.rule == rule && g.kind == kind; });
    };

    EXPECT_TRUE(has("colour-code", GroupKind::Numeric));
    EXPECT_TRUE(has("flag-bit", GroupKind::Numeric));
    EXPECT_TRUE(has("stale-code", GroupKind::Numeric));
    EXPECT_TRUE(has("fruit", GroupKind::Token));

    const auto named = [&groups](const std::string& rule) {
        return std::any_of(groups.begin(), groups.end(), [&](const auto& g) { return g.rule == rule; });
    };
    // A message declaration is a plain group too. Reporting it as a vocabulary
    // would put type names into the manifest as if they were members.
    EXPECT_FALSE(named("do-thing"));
    // An open string field's legal values live in prose; nothing can guard it.
    EXPECT_FALSE(named("opts"));
    EXPECT_EQ(groups.size(), 4u);
}

TEST(CddlVocabulary, NoDuplicateTokensYieldsEmpty)
{
    EXPECT_TRUE(firstDuplicateToken({"user", "sign", "puk"}).empty());
}

TEST(CddlVocabulary, FirstDuplicateTokenIsReported)
{
    EXPECT_EQ(firstDuplicateToken({"user", "sign", "user"}), "user");
}

TEST(CddlVocabulary, EmptyTokenListHasNoDuplicate)
{
    EXPECT_TRUE(firstDuplicateToken({}).empty());
}

TEST(CddlVocabulary, ErodedRuleBoundaryProducesADetectableDuplicate)
{
    // The reader has no way to tell "this is a wrong parse" from "this is a
    // valid, if odd, vocabulary" except this signal: a closed vocabulary
    // cannot legitimately repeat a member, so a duplicate token is proof the
    // capture ran past its own rule's boundary.
    const auto tokens = cddlQuotedTokens(cddlRuleRhs(kBoundaryEroded, "kind"));
    ASSERT_EQ(tokens.size(), 5u); // kind's real 3 plus next-rule's absorbed 2
    EXPECT_EQ(firstDuplicateToken(tokens), "unknown");
}
