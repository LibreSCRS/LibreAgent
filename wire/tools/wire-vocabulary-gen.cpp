// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Emits the machine-readable form of the closed vocabularies in the wire
// contract grammar. Structural validation only: contiguity, non-emptiness,
// well-formedness. Whether a vocabulary AGREES with the upstream enums is a
// semantic question, checked by the guard test, which links what it needs to
// answer it -- this tool deliberately links nothing.

#include <CddlVocabulary.h>

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <set>
#include <string>

namespace {

// The two vocabularies with no upstream enum to compare against: cred-verb
// is a bare string compared inline (PinChangeFlow.cpp's kVerbChange/
// kVerbUnblock/kVerbActivatePin), and settable-config-key's members are
// ConfigStore.cpp's kDefaultLevel/kTsaUrls/kTslSources/kDefaultReason/
// kDefaultLocation string constants -- neither is backed by a C++ enum.
const std::set<std::string> kCddlOnly = {"cred-verb", "settable-config-key"};

std::string jsonEscape(const std::string& s)
{
    std::string out;
    for (const char c : s) {
        const auto uc = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (uc <= 0x1F) {
            // RFC 8259 §7: control characters U+0000-U+001F MUST be escaped
            // in a JSON string. Harmless for today's identifier-only content
            // (CDDL rule and token names), but this tool publishes a
            // manifest another repository consumes verbatim, so well-formed
            // output is guaranteed here rather than assumed of the input.
            static const char hexDigits[] = "0123456789abcdef";
            out += "\\u00";
            out += hexDigits[(uc >> 4) & 0xF];
            out += hexDigits[uc & 0xF];
        } else {
            out += c;
        }
    }
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: wire-vocabulary-gen <path-to-cddl>\n";
        return 2;
    }
    const std::string cddl = LibreSCRS::Wire::Tools::slurp(argv[1]);
    if (cddl.empty()) {
        std::cerr << "error: contract grammar is empty or unreadable: " << argv[1] << "\n";
        return 2;
    }

    auto groups = LibreSCRS::Wire::Tools::discoverClosedGroups(cddl);
    if (groups.empty()) {
        std::cerr << "error: no closed vocabulary groups found -- the grammar was probably reformatted "
                     "past what the reader understands\n";
        return 2;
    }
    std::sort(groups.begin(), groups.end(), [](const auto& a, const auto& b) { return a.rule < b.rule; });

    std::cout << "{\n  \"schema\": 1,\n  \"vocabularies\": {\n";
    bool firstGroup = true;
    for (const auto& g : groups) {
        if (!firstGroup) {
            std::cout << ",\n";
        }
        firstGroup = false;

        if (g.kind == LibreSCRS::Wire::Tools::GroupKind::Numeric) {
            const auto entries = LibreSCRS::Wire::Tools::parseCddlNumericGroup(cddl, g.rule);
            if (entries.empty()) {
                std::cerr << "error: numeric group '" << g.rule << "' parsed to nothing\n";
                return 1;
            }
            // No separate duplicate check is needed on this branch: every
            // closed numeric vocabulary in this grammar starts at 0, so an
            // absorbed neighbour's entries restart at 0 mid-sequence and
            // break contiguity at that seam, before any duplicate value
            // could reach a reader unnoticed. See firstDuplicateToken's
            // doc comment for why the token branch below needs an explicit
            // check that has no equivalent here.
            for (std::size_t i = 0; i < entries.size(); ++i) {
                if (entries[i].value != i) {
                    std::cerr << "error: numeric group '" << g.rule << "' is not contiguous from 0 at entry " << i
                              << " (value " << entries[i].value << ") -- these vocabularies are "
                              << "append-only from 0 and are never renumbered\n";
                    return 1;
                }
            }
            std::cout << "    \"" << g.rule << "\": { \"kind\": \"numeric\", \"entries\": [";
            for (std::size_t i = 0; i < entries.size(); ++i) {
                std::cout << (i ? ", " : " ") << "{ \"value\": " << entries[i].value << ", \"name\": \""
                          << jsonEscape(entries[i].name) << "\" }";
            }
            std::cout << " ] }";
        } else {
            const auto tokens =
                LibreSCRS::Wire::Tools::cddlQuotedTokens(LibreSCRS::Wire::Tools::cddlRuleRhs(cddl, g.rule));
            if (tokens.empty()) {
                std::cerr << "error: token group '" << g.rule << "' parsed to nothing\n";
                return 1;
            }
            // Catches a boundary erosion where the absorbed neighbour shares
            // at least one token with this group -- see firstDuplicateToken's
            // doc comment for exactly what this does and does not catch. A
            // disjoint absorption (no shared members) is NOT detectable here
            // and is not this tool's job to catch: it is caught one layer
            // up, by the guard tests that read a NAMED rule directly and
            // compare it against the upstream C++ enum (e.g.
            // WireContractGuardTest's CddlCredentialRecordVocabMatchesAgentHelpers).
            const std::string duplicate = LibreSCRS::Wire::Tools::firstDuplicateToken(tokens);
            if (!duplicate.empty()) {
                std::cerr << "error: token group '" << g.rule << "' contains '" << duplicate
                          << "' twice -- a closed vocabulary cannot legitimately repeat a member, so the "
                             "parse likely ran past this rule's boundary and absorbed part of the next one\n";
                return 1;
            }
            std::cout << "    \"" << g.rule << "\": { \"kind\": \"token\"";
            if (kCddlOnly.count(g.rule) != 0) {
                std::cout << ", \"cddlOnly\": true";
            }
            std::cout << ", \"entries\": [";
            for (std::size_t i = 0; i < tokens.size(); ++i) {
                std::cout << (i ? ", " : " ") << "\"" << jsonEscape(tokens[i]) << "\"";
            }
            std::cout << " ] }";
        }
    }
    std::cout << "\n  }\n}\n";
    return 0;
}
