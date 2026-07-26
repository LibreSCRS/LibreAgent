// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Guard: LibreSCRS::Agent::kAgentFeatures (FeatureTokens.h, the single source
// of truth for the feature-token vocabulary served on both wires) must stay in
// lockstep with the CDDL comment documenting the SAME vocabulary
// (wire/librescrs-agent.cddl, near `hello-ack`). Feature tokens are NOT a
// closed CDDL rule -- `features` stays `[* tstr]` so a client tolerates any
// extra token a newer/older agent advertises -- so this guard ties the array
// back to the doc comment instead of a grammar rule: an append to kAgentFeatures
// without touching the CDDL comment (or vice versa) fails the token-set
// comparison below, in either direction.
//
// Dependency-light like WireHeadersTest/WireHeaderPurityCheck alongside it:
// FeatureTokens.h is std-only, so this target needs neither LibreAgent::Core
// nor LibreAgent::Wire, and stays reachable from a Core-less
// (LIBREAGENT_BUILD_CORE=OFF, LIBREAGENT_BUILD_WIRE=ON) configuration.
#include <LibreSCRS/Agent/FeatureTokens.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// The quoted tokens listed on the CDDL comment lines immediately following the
// "Feature-token vocabulary" marker paragraph, stopping at the first line that
// is not a CDDL comment (';'-prefixed) -- i.e. the live-vocabulary list at the
// end of that paragraph.
std::vector<std::string> cddlFeatureVocabulary(const std::string& cddl)
{
    std::vector<std::string> tokens;
    std::istringstream lines(cddl);
    std::string line;
    bool foundMarker = false;
    // Anchors extraction to the indented token-list shape (a ';' comment
    // marker, then whitespace, then an opening quote) so prose lines
    // elsewhere in the comment block -- which may quote an arbitrary word
    // for emphasis -- are never mistaken for vocabulary tokens.
    const std::regex tokenLine(R"(^;\s+")");
    while (std::getline(lines, line)) {
        if (!foundMarker) {
            if (line.find("Feature-token vocabulary") != std::string::npos) {
                foundMarker = true;
            }
            continue;
        }
        if (line.empty() || line.find(';') != 0) {
            break; // the comment block ended
        }
        if (!std::regex_search(line, tokenLine)) {
            continue; // prose line inside the comment block -- not a token line
        }
        // Custom `rx` delimiter: the pattern itself contains the `)"`
        // sequence, which would prematurely close a default-delimiter raw
        // string (see WireContractGuardTest::cddlQuotedTokens for the same
        // workaround).
        const std::regex quoted(R"rx("([^"]*)")rx");
        for (auto it = std::sregex_iterator(line.begin(), line.end(), quoted); it != std::sregex_iterator(); ++it) {
            tokens.push_back((*it)[1].str());
        }
    }
    return tokens;
}

} // namespace

// Scope guard for this task: only tokens whose serving surface exists are
// compiled into the live array. Each later task appends its own token in the
// SAME commit that lands the surface -- this fails loudly if a token is
// pre-advertised before its surface exists. Order is not wire-significant
// (both wires carry `features`/`Manager1.Features` as an unordered set), so
// this compares membership, not position.
TEST(FeatureTokensGuard,
     LiveArrayContainsCredentialsCardTypeTokenInfoTrustStatusTsaUrlVisualSignLayoutPreviewIdentityStreamAndBatchSign)
{
    ASSERT_EQ(LibreSCRS::Agent::kAgentFeatures.size(), 9U);
    const std::vector<std::string_view> tokens(LibreSCRS::Agent::kAgentFeatures.begin(),
                                               LibreSCRS::Agent::kAgentFeatures.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"credentials"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"card-type"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"token-info"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"trust-status"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"tsa-url"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"visual-sign"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"layout-preview"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"identity-stream"}), tokens.end());
    EXPECT_NE(std::find(tokens.begin(), tokens.end(), std::string_view{"batch-sign"}), tokens.end());
}

// Test-local sample block (NOT the real CDDL) shaped like the vocabulary
// comment: a prose line that quotes a word for emphasis, followed by two
// properly-indented token lines. Upcoming tasks edit prose around the real
// block; the parser must not mistake a quoted prose word for a token.
TEST(FeatureTokensGuard, IgnoresQuotedWordInProseLine)
{
    const std::string sample = "; Feature-token vocabulary -- test sample block.\n"
                               "; This is prose that mentions \"quoted\" for emphasis, not a token.\n"
                               ";   \"alpha\"\n"
                               ";   \"beta\"\n"
                               "next-rule = ( foo: tstr )\n";

    const std::vector<std::string> tokens = cddlFeatureVocabulary(sample);
    const std::vector<std::string> expected{"alpha", "beta"};
    EXPECT_EQ(tokens, expected);
}

TEST(FeatureTokensGuard, CddlVocabularyMatchesLiveArray)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const std::vector<std::string> cddlTokens = cddlFeatureVocabulary(cddl);
    ASSERT_FALSE(cddlTokens.empty())
        << "could not locate the 'Feature-token vocabulary' comment block in librescrs-agent.cddl";

    std::vector<std::string> arrayTokens(LibreSCRS::Agent::kAgentFeatures.begin(),
                                         LibreSCRS::Agent::kAgentFeatures.end());
    std::vector<std::string> sortedCddl = cddlTokens;
    std::vector<std::string> sortedArray = arrayTokens;
    std::sort(sortedCddl.begin(), sortedCddl.end());
    std::sort(sortedArray.begin(), sortedArray.end());
    EXPECT_EQ(sortedCddl, sortedArray)
        << "the CDDL feature-token vocabulary comment and LibreSCRS::Agent::kAgentFeatures drifted -- "
           "update both together (tokens without a serving surface yet belong only in FeatureTokens.h's "
           "kPlannedFeatures doc comment, never in either live list)";
}
