// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/ReaderLabels.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <iterator>
#include <map>
#include <set>
#include <string_view>
#include <utility>

namespace LibreSCRS::Agent {
namespace {

[[nodiscard]] char lowerAscii(char c) noexcept
{
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

[[nodiscard]] bool isAlnumAscii(char c) noexcept
{
    return std::isalnum(static_cast<unsigned char>(c)) != 0;
}

[[nodiscard]] bool isDigitAscii(char c) noexcept
{
    return std::isdigit(static_cast<unsigned char>(c)) != 0;
}

[[nodiscard]] bool equalsIgnoringCase(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size() &&
           std::ranges::equal(a, b, [](char x, char y) { return lowerAscii(x) == lowerAscii(y); });
}

[[nodiscard]] std::string trimmed(std::string_view s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) {
        s.remove_suffix(1);
    }
    return std::string{s};
}

// One run of spaces for every run of whitespace, none at either end.
[[nodiscard]] std::string squashed(std::string_view s)
{
    std::string out;
    for (const char c : s) {
        if (std::isspace(static_cast<unsigned char>(c)) != 0) {
            if (!out.empty() && out.back() != ' ') {
                out += ' ';
            }
        } else {
            out += c;
        }
    }
    return trimmed(out);
}

// pcsc-lite appends "<ifd> <slot>" to every name it publishes, each "%02X".
void stripSlotPair(std::string& s)
{
    const auto hex2 = [&s](std::size_t at) {
        return std::isxdigit(static_cast<unsigned char>(s[at])) != 0 &&
               std::isxdigit(static_cast<unsigned char>(s[at + 1])) != 0;
    };
    const std::size_t n = s.size();
    if (n >= 6 && s[n - 6] == ' ' && s[n - 3] == ' ' && hex2(n - 5) && hex2(n - 2)) {
        s = trimmed(std::string_view{s}.substr(0, n - 6));
    }
}

// A raw PC/SC name split into what names the product and the serial that
// names the physical unit: "Name [Product] (serial) 01 00" -> "Name
// [Product]" + "serial". One split serves the model, the dual-interface test
// and the collision suffix, so the three can never disagree about where the
// serial is. The slot pair is stripped on both sides of the serial, whichever
// order a name carries them in.
struct PcscName
{
    std::string base;
    std::string serial;
};

[[nodiscard]] PcscName splitPcscName(const std::string& raw)
{
    PcscName out{trimmed(raw), {}};
    stripSlotPair(out.base);
    if (!out.base.empty() && out.base.back() == ')') {
        const auto open = out.base.rfind('(');
        if (open != std::string::npos) {
            out.serial = trimmed(std::string_view{out.base}.substr(open + 1, out.base.size() - open - 2));
            out.base = trimmed(std::string_view{out.base}.substr(0, open));
        }
    }
    stripSlotPair(out.base);
    return out;
}

// Whether @p s, read case-insensitively, holds @p word as a whole word.
[[nodiscard]] bool containsWord(std::string_view s, std::string_view word)
{
    for (std::size_t at = 0; at + word.size() <= s.size(); ++at) {
        if (!equalsIgnoringCase(s.substr(at, word.size()), word)) {
            continue;
        }
        const bool startsWord = at == 0 || !isAlnumAscii(s[at - 1]);
        const bool endsWord = at + word.size() == s.size() || !isAlnumAscii(s[at + word.size()]);
        if (startsWord && endsWord) {
            return true;
        }
    }
    return false;
}

// "CL" as a token of its own ("5422 CL") or fused onto a model number
// ("5422CL") -- how a dual-interface unit marks its contactless slot.
[[nodiscard]] bool containsClMarker(std::string_view s)
{
    for (std::size_t at = 0; at + 2 <= s.size(); ++at) {
        if (!equalsIgnoringCase(s.substr(at, 2), "cl")) {
            continue;
        }
        const bool startsMarker = at == 0 || !isAlnumAscii(s[at - 1]) || isDigitAscii(s[at - 1]);
        const bool endsMarker = at + 2 == s.size() || !isAlnumAscii(s[at + 2]);
        if (startsMarker && endsMarker) {
            return true;
        }
    }
    return false;
}

// Whether the name says it is a contactless interface. Read over the whole
// name, product string included, so a marker the shortened model drops still
// classifies the slot.
[[nodiscard]] bool carriesContactlessMarker(std::string_view base)
{
    return containsWord(base, "contactless") || containsWord(base, "picc") || containsWord(base, "nfc") ||
           containsClMarker(base);
}

// Drop one trailing generic word or contactless marker, if there is one and
// something is left in front of it. Every marker removed here is one
// carriesContactlessMarker() recognises, so a stripped model can never hide a
// contactless slot.
[[nodiscard]] bool dropTrailingWord(std::string& model)
{
    // Longest first: "smart card reader" goes as one, before "reader" alone
    // could leave "smart card" behind as the model. "USB" is the bus, as
    // "CCID" is the protocol: neither names a model, and macOS hands over
    // bare product strings like "Gemalto USB SmartCard Reader".
    static constexpr std::string_view kWords[] = {
        "smart card reader", "smartcard reader", "smart card", "smartcard", "reader", "ccid", "usb",
        "interface",         "contactless",      "picc"};
    for (const auto word : kWords) {
        const std::size_t n = model.size();
        if (n > word.size() && model[n - word.size() - 1] == ' ' &&
            equalsIgnoringCase(std::string_view{model}.substr(n - word.size()), word)) {
            model = trimmed(std::string_view{model}.substr(0, n - word.size()));
            return true;
        }
    }
    const std::size_t n = model.size();
    if (n > 2 && equalsIgnoringCase(std::string_view{model}.substr(n - 2), "cl") &&
        (model[n - 3] == ' ' || isDigitAscii(model[n - 3]))) {
        model = trimmed(std::string_view{model}.substr(0, n - 2));
        return true;
    }
    return false;
}

// "OMNIKEY 5422CL Smartcard Reader" -> "OMNIKEY 5422". A bare generic word
// with nothing in front of it stays: "Reader" is still more than nothing.
[[nodiscard]] std::string shortModel(std::string_view text)
{
    std::string model = squashed(text);
    while (dropTrailingWord(model)) {
    }
    return model;
}

// The bracketed product string is the driver's own model name and is the
// better label when it names a model -- a digit or more than one word:
// "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader]"
// -> "OMNIKEY 5422". Otherwise the text in front of it.
[[nodiscard]] std::string modelOf(const std::string& base)
{
    const auto open = base.find('[');
    const auto close = open == std::string::npos ? std::string::npos : base.find(']', open);
    if (close == std::string::npos) {
        return shortModel(base);
    }
    const std::string product = shortModel(std::string_view{base}.substr(open + 1, close - open - 1));
    const std::string prefix = shortModel(std::string_view{base}.substr(0, open));
    const bool productNamesAModel =
        !product.empty() && (std::ranges::any_of(product, isDigitAscii) || product.find(' ') != std::string::npos);
    if (productNamesAModel || prefix.empty()) {
        return product;
    }
    return prefix;
}

} // namespace

std::vector<ReaderIdentity> readerIdentities(const std::vector<std::string>& rawNames)
{
    std::vector<PcscName> names;
    names.reserve(rawNames.size());
    for (const auto& raw : rawNames) {
        names.push_back(splitPcscName(raw));
    }

    // Which DISTINCT raw names share a serial. Counting raw OCCURRENCES
    // instead would let one physical reader enumerated twice (e.g. by a
    // caller that merged two identical PC/SC scans) masquerade as a
    // dual-interface pair, handing a single-interface reader a Contact
    // qualifier it has no business carrying.
    std::map<std::string, std::set<std::string>> slotsPerUnit;
    for (std::size_t i = 0; i < rawNames.size(); ++i) {
        if (!names[i].serial.empty()) {
            slotsPerUnit[names[i].serial].insert(rawNames[i]);
        }
    }

    std::vector<ReaderIdentity> out;
    out.reserve(rawNames.size());
    for (std::size_t i = 0; i < rawNames.size(); ++i) {
        ReaderIdentity id;
        id.full = rawNames[i];
        const std::string model = modelOf(names[i].base);
        id.model = model.empty() ? rawNames[i] : model;

        const bool contactless = carriesContactlessMarker(names[i].base);
        const bool dualInterfaceUnit = !names[i].serial.empty() && slotsPerUnit[names[i].serial].size() > 1;
        if (contactless) {
            id.iface = ReaderInterface::Contactless;
        } else if (dualInterfaceUnit) {
            id.iface = ReaderInterface::Contact;
        }
        out.push_back(std::move(id));
    }

    // Labels that still read alike for two DISTINCT names: the whole point of
    // a label is telling readers apart, so each such name takes its serial's
    // last four characters, or its 1-based position, until it is unique.
    using Label = std::pair<std::string, ReaderInterface>;
    std::map<Label, std::set<std::string>> namesPerLabel;
    std::set<Label> taken;
    for (std::size_t i = 0; i < out.size(); ++i) {
        namesPerLabel[{out[i].model, out[i].iface}].insert(rawNames[i]);
        taken.insert({out[i].model, out[i].iface});
    }
    std::map<std::string, std::string> settled; // raw name -> its disambiguated model
    for (std::size_t i = 0; i < out.size(); ++i) {
        if (const auto it = settled.find(rawNames[i]); it != settled.end()) {
            out[i].model = it->second; // the same reader listed again
            continue;
        }
        if (namesPerLabel[{out[i].model, out[i].iface}].size() <= 1) {
            continue;
        }
        const std::string& serial = names[i].serial;
        const std::string base = out[i].model;
        std::size_t position = i + 1;
        std::string candidate =
            base + " (" +
            (serial.empty() ? std::to_string(position++)
                            : serial.substr(serial.size() - std::min<std::size_t>(serial.size(), 4))) +
            ")";
        while (taken.contains({candidate, out[i].iface})) {
            candidate = base + " (" + std::to_string(position++) + ")";
        }
        taken.insert({candidate, out[i].iface});
        settled.emplace(rawNames[i], candidate);
        out[i].model = std::move(candidate);
    }
    return out;
}

ReaderIdentity identityForCardIn(const PresenceRoster& roster, const std::string& cardKey)
{
    if (cardKey.empty()) {
        return {};
    }
    const auto it = std::ranges::find(roster.cardKeys, cardKey);
    if (it == roster.cardKeys.end()) {
        return {};
    }
    const auto index = static_cast<std::size_t>(std::distance(roster.cardKeys.begin(), it));
    const auto identities = readerIdentities(roster.readerNames);
    return index < identities.size() ? identities[index] : ReaderIdentity{};
}

bool isContactSlotOfDualInterfaceUnit(const PresenceRoster& roster, const std::string& cardKey)
{
    return identityForCardIn(roster, cardKey).iface == ReaderInterface::Contact;
}

} // namespace LibreSCRS::Agent
