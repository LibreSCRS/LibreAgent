// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Guard: the CDDL comment documenting `property-changed`'s served `iface`
// vocabulary (wire/librescrs-agent.cddl, near the `property-changed` rule)
// must stay in lockstep with the SET this task hand-verified against the one
// daemon that actually emits this event (the socket daemon; the D-Bus daemon
// uses its native PropertiesChanged signal instead, so there is no
// second-source array to cross-check against the way FeatureTokensGuardTest
// cross-checks kAgentFeatures). `iface`/`props` stay free-form CDDL types
// (`tstr` / `{* tstr => any}`) -- this guard pins the DOCUMENTED vocabulary,
// not a grammar rule, exactly like FeatureTokensGuardTest pins the
// feature-token vocabulary comment.
//
// Dependency-light like FeatureTokensGuardTest/WireHeadersTest alongside it:
// no LibreAgent library link needed, just the CDDL text file, so this stays
// reachable from a Core-less (LIBREAGENT_BUILD_CORE=OFF) configuration too.
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

// The quoted `iface "..."` tokens on the CDDL comment lines between the
// "A guard test" marker paragraph and the `property-changed = (...)` rule
// itself -- i.e. the served-iface list in that comment block. Deliberately
// anchored to the `;   iface "` line shape (not just any quoted string in the
// block) so the nested `props: { ... }` documentation lines directly below
// each iface entry are never mistaken for a vocabulary token.
std::vector<std::string> cddlPropertyChangedIfaces(const std::string& cddl)
{
    std::vector<std::string> tokens;
    std::istringstream lines(cddl);
    std::string line;
    bool foundMarker = false;
    const std::regex ifaceLine(R"(^;\s+iface\s+")");
    while (std::getline(lines, line)) {
        if (!foundMarker) {
            if (line.find("PropertyChangedVocabGuardTest") != std::string::npos) {
                foundMarker = true;
            }
            continue;
        }
        if (line.rfind("property-changed", 0) == 0) {
            break; // reached the rule itself -- comment block ended
        }
        if (line.empty() || line.find(';') != 0) {
            break;
        }
        if (!std::regex_search(line, ifaceLine)) {
            continue; // a props/prose line inside the block, not an iface line
        }
        const std::regex quoted(R"rx("([^"]*)")rx");
        auto it = std::sregex_iterator(line.begin(), line.end(), quoted);
        if (it != std::sregex_iterator()) {
            tokens.push_back((*it)[1].str());
        }
    }
    return tokens;
}

} // namespace

// The served set this task hand-verified against both real daemons'
// PropertyChanged-emitting code (LibreDarwin's SocketTransport::
// updateProperties / updateCardType -- the ONLY producer, since the D-Bus
// daemon never constructs this event): Card1 pushes cardType once resolved;
// Reader1 pushes hasCard/card transitions. Both spellings are the FULL D-Bus
// interface name -- the same one the Qt client's kReaderIface/kCardIface
// dispatch constants require verbatim (client/qt/src/dbus/AgentDBus.h) --
// not the shortened "Card1"/"Reader1" form a stale comment used to say.
TEST(PropertyChangedVocabGuard, ServedIfaceSetIsCard1AndReader1)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    std::vector<std::string> ifaces = cddlPropertyChangedIfaces(cddl);
    ASSERT_FALSE(ifaces.empty())
        << "could not locate the property-changed iface vocabulary comment in librescrs-agent.cddl";

    std::sort(ifaces.begin(), ifaces.end());
    const std::vector<std::string> expected{"org.librescrs.Agent.Card1", "org.librescrs.Agent.Reader1"};
    EXPECT_EQ(ifaces, expected) << "the property-changed iface vocabulary comment drifted from the served set -- "
                                   "update the CDDL comment AND re-verify the daemon(s) that construct this event "
                                   "still use exactly these two spellings";
}

// Sanity on the parser itself (mirrors FeatureTokensGuardTest's own
// IgnoresQuotedWordInProseLine case): a props sub-bullet line quoting
// something must never be mistaken for an iface line.
TEST(PropertyChangedVocabGuard, IgnoresPropsLineAndMatchesOnlyIfaceLines)
{
    const std::string sample = "; A guard test (tests/wire/PropertyChangedVocabGuardTest.cpp) pins this.\n"
                               ";   iface \"org.librescrs.Agent.Card1\": pushed when...\n"
                               ";     props: { CardType: tstr }\n"
                               ";   iface \"org.librescrs.Agent.Reader1\": pushed on...\n"
                               ";     props: { HasCard: bool, ? Card: tstr }\n"
                               "property-changed = ( t: \"PropertyChanged\" )\n";
    const std::vector<std::string> tokens = cddlPropertyChangedIfaces(sample);
    const std::vector<std::string> expected{"org.librescrs.Agent.Card1", "org.librescrs.Agent.Reader1"};
    EXPECT_EQ(tokens, expected);
}
