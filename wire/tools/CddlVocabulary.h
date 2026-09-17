// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Text helpers for reading closed vocabulary groups out of the wire contract
// grammar. std-only and link-free by construction: both the guard tests and
// the manifest generator use these, and the generator must not pull in the
// agent core.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Wire::Tools {

inline std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// Right-hand side of a top-level CDDL rule `<ruleName> = ...`, comment-stripped
// and joined across continuation lines up to (but excluding) the next top-level
// `name = ...` definition. Empty if the rule is not found. Slurps the credential
// vocabulary groups the way parseCddlErrorCode slurps error-code.
inline std::string cddlRuleRhs(const std::string& cddl, const std::string& ruleName)
{
    std::istringstream lines(cddl);
    std::string line;
    std::string rhs;
    bool capturing = false;
    const std::regex defRe(R"(^\s*([A-Za-z][A-Za-z0-9-]*)\s*=)");
    while (std::getline(lines, line)) {
        const std::string stripped = line.substr(0, line.find(';'));
        std::smatch match;
        const bool isDef = std::regex_search(stripped, match, defRe);
        if (capturing) {
            if (isDef) {
                break; // the next rule begins; the captured rule is complete
            }
            rhs += ' ';
            rhs += stripped;
            continue;
        }
        if (isDef && match[1].str() == ruleName) {
            capturing = true;
            rhs += stripped.substr(stripped.find('=') + 1);
        }
    }
    return rhs;
}

struct NumericEntry
{
    std::uint32_t value;
    std::string name;
};

// Union: a closed token group extended by literals -- `requested-level =
// sign-level / "auto"`. Its members are the base group's members plus its own
// literals, so it is closed too; `base` names the group it extends and is empty
// for the other two kinds.
enum class GroupKind { Numeric, Token, Union };

struct DiscoveredGroup
{
    std::string rule;
    GroupKind kind;
    std::string base;
};

// The `Name: <value>` pairs of a CDDL numeric socket `<rule> = &( ... )`.
// Comments run from ';' to end of line and are stripped first, so a commented
// entry can never be mistaken for a live one.
inline std::vector<NumericEntry> parseCddlNumericGroup(const std::string& cddl, const std::string& ruleName)
{
    std::vector<NumericEntry> entries;
    const std::string rhs = cddlRuleRhs(cddl, ruleName);
    const std::size_t open = rhs.find('(');
    const std::size_t close = rhs.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open) {
        return entries;
    }
    const std::string block = rhs.substr(open + 1, close - open - 1);

    const std::regex entryRe(R"(([A-Za-z][A-Za-z0-9]*)\s*:\s*(\d+))");
    for (auto it = std::sregex_iterator(block.begin(), block.end(), entryRe); it != std::sregex_iterator(); ++it) {
        entries.push_back({static_cast<std::uint32_t>(std::stoul((*it)[2].str())), (*it)[1].str()});
    }
    return entries;
}

// Extracts the `Name: <value>` pairs of the CDDL `error-code = &( ... )` group.
inline std::vector<std::pair<std::uint32_t, std::string>> parseCddlErrorCode(const std::string& cddl)
{
    std::vector<std::pair<std::uint32_t, std::string>> out;
    for (const auto& e : parseCddlNumericGroup(cddl, "error-code")) {
        out.emplace_back(e.value, e.name);
    }
    return out;
}

// True when a parenthesised right-hand side is a NUMERIC VOCABULARY rather
// than a message declaration. Both are written `( ... )`; the difference is
// that a vocabulary's entries are all `Identifier: <integer>`, while a message
// carries type references (`card: handle`, `? force: bool`). Getting this
// wrong puts type names into the manifest as if they were members.
inline bool isNumericVocabularyBody(const std::string& body)
{
    const std::regex fieldRe(R"(([A-Za-z][A-Za-z0-9]*)\s*:\s*([^,)]+))");
    const std::regex intRe(R"(^\s*\d+\s*$)");
    bool sawOne = false;
    for (auto it = std::sregex_iterator(body.begin(), body.end(), fieldRe); it != std::sregex_iterator(); ++it) {
        if (!std::regex_match((*it)[2].str(), intRe)) {
            return false;
        }
        sawOne = true;
    }
    return sawOne;
}

// The '/'-separated alternatives of a right-hand side, each trimmed, with a
// '/' inside a quoted literal left alone. SPLITTING on the joiner rather than
// deleting it is what keeps `base / other` two references instead of one
// fused `baseother` -- the difference between a rule that names one group and
// a rule that names two.
inline std::vector<std::string> cddlAlternatives(const std::string& rhs)
{
    std::vector<std::string> alternatives;
    std::string current;
    bool quoted = false;
    const auto flush = [&]() {
        const std::size_t first = current.find_first_not_of(" \t\r\n");
        if (first != std::string::npos) {
            const std::size_t last = current.find_last_not_of(" \t\r\n");
            alternatives.push_back(current.substr(first, last - first + 1));
        }
        current.clear();
    };
    for (const char c : rhs) {
        if (c == '"') {
            quoted = !quoted;
        }
        if (c == '/' && !quoted) {
            flush();
            continue;
        }
        current += c;
    }
    flush();
    return alternatives;
}

// Every CLOSED vocabulary in the grammar, in the four shapes it actually
// uses: a numeric socket `= &( ... )`; a plain numeric group `= ( ... )` (how
// a .bits right-hand side is written); a rule whose right-hand side is
// nothing but quoted literals joined by '/'; or a UNION -- exactly one name of
// a closed token group plus at least one quoted literal, joined by '/'. A rule
// carrying any other bare type name (`tstr`, `uint`, two group names, a union
// of a union) is OPEN and deliberately NOT reported -- an open field's legal
// values live in prose, so no manifest can carry them and no gate can watch
// them.
//
// Two passes, so the result does not depend on where in the grammar the base
// group is defined: the first collects the numeric and token groups, the
// second resolves each remaining candidate's single name against them.
inline std::vector<DiscoveredGroup> discoverClosedGroups(const std::string& cddl)
{
    std::vector<DiscoveredGroup> groups;
    std::vector<std::pair<std::string, std::string>> undecided; // (rule, rhs)
    std::istringstream lines(cddl);
    std::string line;
    const std::regex defRe(R"(^\s*([A-Za-z][A-Za-z0-9-]*)\s*=)");

    while (std::getline(lines, line)) {
        const std::string stripped = line.substr(0, line.find(';'));
        std::smatch match;
        if (!std::regex_search(stripped, match, defRe)) {
            continue;
        }
        const std::string rule = match[1].str();
        const std::string rhs = cddlRuleRhs(cddl, rule);

        const std::size_t open = rhs.find('(');
        const std::size_t close = rhs.rfind(')');
        if (open != std::string::npos && close != std::string::npos && close > open) {
            const std::string body = rhs.substr(open + 1, close - open - 1);
            const bool socket = rhs.find("&(") != std::string::npos;
            if (socket || isNumericVocabularyBody(body)) {
                groups.push_back({rule, GroupKind::Numeric});
                continue;
            }
        }
        // Token alternation: strip every quoted literal and the '/' joiners; if
        // nothing but whitespace remains, the rule is closed.
        const std::string residue =
            std::regex_replace(std::regex_replace(rhs, std::regex(R"rx("[^"]*")rx"), ""), std::regex(R"([/\s])"), "");
        if (!residue.empty() || rhs.find('"') == std::string::npos) {
            undecided.emplace_back(rule, rhs);
            continue;
        }
        groups.push_back({rule, GroupKind::Token});
    }

    const std::regex nameRe(R"(^[A-Za-z][A-Za-z0-9-]*$)");
    const auto isLiteral = [](const std::string& alt) {
        return alt.size() >= 2 && alt.front() == '"' && alt.back() == '"';
    };
    const auto tokenGroupNamed = [&groups](const std::string& name) {
        return std::any_of(groups.begin(), groups.end(),
                           [&](const DiscoveredGroup& g) { return g.rule == name && g.kind == GroupKind::Token; });
    };
    for (const auto& [rule, rhs] : undecided) {
        std::string base;
        std::size_t names = 0;
        std::size_t literals = 0;
        const auto alternatives = cddlAlternatives(rhs);
        for (const auto& alt : alternatives) {
            if (isLiteral(alt)) {
                ++literals;
            } else if (std::regex_match(alt, nameRe)) {
                ++names;
                base = alt;
            }
        }
        if (names != 1 || literals == 0 || names + literals != alternatives.size() || !tokenGroupNamed(base)) {
            continue;
        }
        groups.push_back({rule, GroupKind::Union, base});
    }
    return groups;
}

// The quoted string literals of a CDDL string-alternation RHS ("a" / "b" / ...),
// in source order.
inline std::vector<std::string> cddlQuotedTokens(const std::string& rhs)
{
    std::vector<std::string> tokens;
    // Custom `rx` delimiter: the pattern itself contains the `)"` sequence, which
    // would prematurely close a default-delimiter raw string.
    const std::regex quoted(R"rx("([^"]*)")rx");
    for (auto it = std::sregex_iterator(rhs.begin(), rhs.end(), quoted); it != std::sregex_iterator(); ++it) {
        tokens.push_back((*it)[1].str());
    }
    return tokens;
}

// The members of a union group: its base group's literals first, then its own
// added literals, each run in grammar order. A sentinel that is also a base
// member shows up twice here, which firstDuplicateToken below turns into a
// generator refusal -- exactly the behaviour that check already has for an
// eroded rule boundary.
inline std::vector<std::string> unionTokens(const std::string& cddl, const DiscoveredGroup& group)
{
    std::vector<std::string> tokens = cddlQuotedTokens(cddlRuleRhs(cddl, group.base));
    const auto own = cddlQuotedTokens(cddlRuleRhs(cddl, group.rule));
    tokens.insert(tokens.end(), own.begin(), own.end());
    return tokens;
}

// The first token that appears more than once in a closed vocabulary's token
// list, or an empty string if every entry is unique. A closed vocabulary
// cannot legitimately list the same member twice, so a duplicate is the
// signature of a parse that ran past its own group's boundary and absorbed
// part of the next rule -- exactly what an eroded rule-name/'=' boundary
// produces (see the generator's use of this).
//
// What this catches: an erosion where the absorbed neighbour shares at
// least one token with the group it merged into. Every adjacent token
// vocabulary in the current grammar (cred-kind, cred-state, unblock-style,
// cred-recovery) shares the sentinel "unknown", so this fires today.
//
// What this does NOT catch: two adjacent token rules with no overlapping
// members at all -- e.g. `a = "x" / "y" / "z"` next to `b = "p" / "q"`. An
// erosion there concatenates into a plausible-looking, duplicate-free
// five-member group; this function finds nothing wrong, `a` ships with
// borrowed members, and `b` vanishes from the manifest with exit 0. No
// stronger structural check exists at this layer -- a text-only reader with
// no notion of the grammar's semantics cannot distinguish "five legitimate
// members" from "five members, two of them borrowed from the next rule",
// and a heuristic that tried would be worse than the honest limit.
//
// That remaining gap is closed one layer up, not here: the guard tests that
// read a NAMED rule directly (e.g. WireContractGuardTest's
// CddlCredentialRecordVocabMatchesAgentHelpers) and compare it against the
// upstream C++ enum's token set. A vanished rule reads back empty, which
// cannot match, and the gate fails before anything is committed. This
// function is one of two layers, not a complete guarantee by itself -- a
// future vocabulary added with no members in common with its neighbour, and
// with no guard test yet reading it directly, is not covered by either
// layer until one exists.
inline std::string firstDuplicateToken(const std::vector<std::string>& tokens)
{
    std::set<std::string> seen;
    for (const auto& token : tokens) {
        if (!seen.insert(token).second) {
            return token;
        }
    }
    return {};
}

// The map key names of a CDDL map-group RHS `{ key: type, ? key: type, ... }`,
// in declaration order. The `?` optional markers and the value types are
// ignored — only identifiers immediately followed by ':' are keys (the camelCase
// keys never contain '-', so the hyphenated type refs are not matched).
inline std::vector<std::string> cddlMapKeys(const std::string& rhs)
{
    std::vector<std::string> keys;
    const std::regex keyRe(R"(([A-Za-z][A-Za-z0-9]*)\s*:)");
    for (auto it = std::sregex_iterator(rhs.begin(), rhs.end(), keyRe); it != std::sregex_iterator(); ++it) {
        keys.push_back((*it)[1].str());
    }
    return keys;
}

} // namespace LibreSCRS::Wire::Tools
