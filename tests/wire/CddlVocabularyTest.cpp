// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <CddlVocabulary.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

using LibreSCRS::Wire::Tools::cddlAlternatives;
using LibreSCRS::Wire::Tools::cddlQuotedTokens;
using LibreSCRS::Wire::Tools::cddlRuleRhs;
using LibreSCRS::Wire::Tools::discoverClosedGroups;
using LibreSCRS::Wire::Tools::firstDuplicateToken;
using LibreSCRS::Wire::Tools::GroupKind;
using LibreSCRS::Wire::Tools::parseCddlNumericGroup;
using LibreSCRS::Wire::Tools::unionTokens;

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

// A closed group extended by literals -- the requested-* shape of the real
// grammar -- next to every shape that must NOT be reported as such: a union
// over an open type, a rule naming two groups, and a union over a union.
const std::string kUnions = R"(
base     = "x" / "y"
extended = base / "auto"
other    = "p" / "q"
loose    = tstr / "auto"
pair     = base / other / "auto"
deep     = extended / "more"
)";

// The same union with its base defined AFTER it: the reader must not depend on
// definition order, which the real grammar only satisfies by accident.
const std::string kUnionBeforeBase = R"(
extended = base / "auto"
base     = "x" / "y"
)";

// A union whose added literal is already a member of its base.
const std::string kDuplicateUnion = R"(
base = "x" / "y"
dup  = base / "x"
)";

struct GeneratorRun
{
    int exitCode;
    std::string output; // stdout and stderr, in order
};

// Runs the real generator binary over a grammar written to a scratch file.
GeneratorRun runGenerator(const std::string& cddl)
{
    // One name per process and per call. Every case in this file used to write the
    // same path and delete it afterwards, which was safe while the whole suite was
    // a single ctest entry running its cases in sequence. With one entry per case
    // two of them run at once: one writes while the other's generator reads, or
    // deletes underneath it, and the failure reads as a grammar defect
    // ("contract grammar is empty or unreadable") rather than as interference.
    static unsigned serial = 0;
    const auto path = std::filesystem::temp_directory_path()
        / ("CddlVocabularyTest-grammar-" + std::to_string(static_cast<long>(::getpid()))
           + "-" + std::to_string(serial++) + ".cddl");
    {
        std::ofstream out(path);
        out << cddl;
    }
    const std::string cmd = std::string{"'"} + LIBRESCRS_WIRE_VOCABULARY_GEN + "' '" + path.string() + "' 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    GeneratorRun run{-1, {}};
    if (pipe == nullptr) {
        return run;
    }
    char buf[512];
    while (fgets(buf, sizeof buf, pipe) != nullptr) {
        run.output += buf;
    }
    const int status = pclose(pipe);
    run.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    std::filesystem::remove(path);
    return run;
}
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

TEST(CddlVocabulary, SplitsAlternativesOnTheSlashInsteadOfDeletingIt)
{
    // Deleting '/' would fuse `base / other` into `baseother`, which then reads
    // as ONE rule reference; splitting keeps the two apart.
    const auto alts = cddlAlternatives(R"( base / other / "auto" )");
    ASSERT_EQ(alts.size(), 3u);
    EXPECT_EQ(alts[0], "base");
    EXPECT_EQ(alts[1], "other");
    EXPECT_EQ(alts[2], "\"auto\"");
}

namespace {
const LibreSCRS::Wire::Tools::DiscoveredGroup*
findGroup(const std::vector<LibreSCRS::Wire::Tools::DiscoveredGroup>& groups, const std::string& rule)
{
    const auto it = std::find_if(groups.begin(), groups.end(), [&](const auto& g) { return g.rule == rule; });
    return it == groups.end() ? nullptr : &*it;
}
} // namespace

TEST(CddlVocabulary, ReportsAClosedGroupPlusLiteralsAsAUnionOfThatGroup)
{
    const auto groups = discoverClosedGroups(kUnions);
    const auto* extended = findGroup(groups, "extended");
    ASSERT_NE(extended, nullptr);
    EXPECT_EQ(extended->kind, GroupKind::Union);
    EXPECT_EQ(extended->base, "base");
    // Base members first, in grammar order, then the added literals.
    EXPECT_EQ(unionTokens(kUnions, *extended), (std::vector<std::string>{"x", "y", "auto"}));
    // The plain token groups keep an empty base.
    const auto* base = findGroup(groups, "base");
    ASSERT_NE(base, nullptr);
    EXPECT_EQ(base->kind, GroupKind::Token);
    EXPECT_TRUE(base->base.empty());
}

TEST(CddlVocabulary, UnionOverAnOpenTypeStaysUnreported)
{
    // `tstr` resolves to no closed group, so the rule is open and no manifest
    // can carry it -- this is the case that must stay silent.
    EXPECT_EQ(findGroup(discoverClosedGroups(kUnions), "loose"), nullptr);
}

TEST(CddlVocabulary, UnionNamingTwoRulesStaysUnreported)
{
    EXPECT_EQ(findGroup(discoverClosedGroups(kUnions), "pair"), nullptr);
}

TEST(CddlVocabulary, UnionOverAUnionStaysUnreported)
{
    // Transitive flattening was never asked for; refusing it is cheaper than
    // getting it silently wrong.
    EXPECT_EQ(findGroup(discoverClosedGroups(kUnions), "deep"), nullptr);
}

TEST(CddlVocabulary, UnionIsReportedWhenItsBaseIsDefinedLater)
{
    const auto groups = discoverClosedGroups(kUnionBeforeBase);
    const auto* extended = findGroup(groups, "extended");
    ASSERT_NE(extended, nullptr);
    EXPECT_EQ(extended->kind, GroupKind::Union);
    EXPECT_EQ(extended->base, "base");
}

TEST(CddlVocabularyGenerator, EmitsAUnionAsATokenListNamingItsBase)
{
    const auto run = runGenerator(kUnions);
    ASSERT_EQ(run.exitCode, 0) << run.output;
    // "kind": "token" on purpose: every existing reader decodes a token list
    // and ignores keys it does not know, so no consumer has to change to keep
    // working. "union-of" is for the reader that wants to know.
    EXPECT_NE(
        run.output.find(R"("extended": { "kind": "token", "union-of": "base", "entries": [ "x", "y", "auto" ] })"),
        std::string::npos)
        << run.output;
    EXPECT_EQ(run.output.find("union-of"), run.output.rfind("union-of")) << "only the union carries union-of";
}

TEST(CddlVocabularyGenerator, RefusesAUnionThatRepeatsABaseMember)
{
    const auto run = runGenerator(kDuplicateUnion);
    EXPECT_NE(run.exitCode, 0);
    EXPECT_NE(run.output.find("'dup' contains 'x' twice"), std::string::npos) << run.output;
}
