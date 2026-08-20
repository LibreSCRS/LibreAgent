// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/ReaderLabels.h>

#include <cctype>
#include <map>
#include <set>

namespace LibreSCRS::Agent {
namespace {

// Where the pcsc-lite " (serial) <ifd> <slot>" tail sits, if this name has
// one at all: a trailing parenthesized group where everything after the ')'
// is digits and spaces only.
//
// The stripper and the serial extractor must agree on what counts as this
// tail -- two independent rules here invite the same defect class as the CL
// marker above: one predicate now decides for both, so a non-numeric
// parenthetical can no longer look like a serial to one function and like
// plain trailing text to the other.
struct PcscTail
{
    std::size_t open = std::string::npos;
    std::size_t close = std::string::npos;
    [[nodiscard]] bool valid() const noexcept
    {
        return open != std::string::npos;
    }
};

[[nodiscard]] PcscTail findPcscTail(const std::string& s)
{
    const auto open = s.rfind('(');
    if (open == std::string::npos) {
        return {};
    }
    const auto close = s.find(')', open);
    if (close == std::string::npos) {
        return {};
    }
    for (std::size_t i = close + 1; i < s.size(); ++i) {
        if (std::isdigit(static_cast<unsigned char>(s[i])) == 0 && s[i] != ' ') {
            return {}; // not the pcsc-lite tail -- leave the name alone
        }
    }
    return {open, close};
}

// Strip the LAST pcsc-lite tail found by findPcscTail, if any.
[[nodiscard]] std::string stripPcscSuffix(std::string s)
{
    const auto tail = findPcscTail(s);
    if (!tail.valid()) {
        return s;
    }
    s.erase(tail.open);
    while (!s.empty() && s.back() == ' ') {
        s.pop_back();
    }
    return s;
}

// The bracketed product string is the driver's own model name and is the
// better label when present: "HID Global OMNIKEY 5422 Smartcard Reader
// [OMNIKEY 5422CL Smartcard Reader]" -> "OMNIKEY 5422CL Smartcard Reader".
[[nodiscard]] std::string preferBracketed(const std::string& s)
{
    const auto open = s.find('[');
    const auto close = s.rfind(']');
    if (open == std::string::npos || close == std::string::npos || close <= open + 1) {
        return s;
    }
    return s.substr(open + 1, close - open - 1);
}

// The serial in the pcsc-lite tail identifies the physical unit: two slots of
// one dual-interface reader share it. Uses the SAME tail predicate as
// stripPcscSuffix, so the two can never disagree about where the serial is.
[[nodiscard]] std::string unitSerial(const std::string& raw)
{
    const auto tail = findPcscTail(raw);
    if (!tail.valid()) {
        return {};
    }
    return raw.substr(tail.open + 1, tail.close - tail.open - 1);
}

// A dual-interface unit marks its contactless slot by FUSING "CL" onto the
// model number -- "OMNIKEY 5422CL" -- so the marker is a suffix, not a
// standalone token.
//
// One helper answers "is this the contactless slot?" AND defines what the
// stripper below removes. They must not be two independent rules: a
// token-boundary test would refuse "5422CL" while a suffix test stripped it,
// classifying a slot as Contact and then erasing the very marker that says
// otherwise. Both slots would then render identically -- the exact failure
// this function exists to prevent.
[[nodiscard]] bool endsWithContactlessMarker(const std::string& model)
{
    return model.size() > 2 && model.compare(model.size() - 2, 2, "CL") == 0;
}

// Drop the generic product-class suffix so two slots of one unit reduce to the
// same model string: "OMNIKEY 5422CL Smartcard Reader" -> "OMNIKEY 5422CL".
//
// Only the explicit "Smartcard Reader" spellings count as generic. A bare
// " Reader" is frequently part of the real product name -- "Gemalto PC Twin
// Reader" -- and stripping it would erase the identity being shown rather than
// shorten it.
[[nodiscard]] std::string dropGenericTail(std::string model)
{
    static constexpr const char* kTails[] = {" Smartcard Reader", " Smart Card Reader"};
    for (const auto* tail : kTails) {
        const std::string t{tail};
        if (model.size() > t.size() && model.compare(model.size() - t.size(), t.size(), t) == 0) {
            model.erase(model.size() - t.size());
            return model;
        }
    }
    return model;
}

// "OMNIKEY 5422CL" -> "OMNIKEY 5422": the interface marker moves OUT of the
// model string and INTO the structured field. Removes exactly what
// endsWithContactlessMarker matched.
[[nodiscard]] std::string dropContactlessMarker(std::string model)
{
    if (endsWithContactlessMarker(model)) {
        model.erase(model.size() - 2);
        while (!model.empty() && model.back() == ' ') {
            model.pop_back();
        }
    }
    return model;
}

} // namespace

std::vector<ReaderIdentity> readerIdentities(const std::vector<std::string>& rawNames)
{
    // Which DISTINCT raw names share a serial. Counting raw OCCURRENCES
    // instead would let one physical reader enumerated twice (e.g. by a
    // caller that merged two identical PC/SC scans) masquerade as a
    // dual-interface pair, handing a single-interface reader a Contact
    // qualifier it has no business carrying.
    std::map<std::string, std::set<std::string>> slotsPerUnit;
    for (const auto& raw : rawNames) {
        const auto serial = unitSerial(raw);
        if (!serial.empty()) {
            slotsPerUnit[serial].insert(raw);
        }
    }

    std::vector<ReaderIdentity> out;
    out.reserve(rawNames.size());
    for (const auto& raw : rawNames) {
        ReaderIdentity id;
        id.full = raw;

        std::string model = dropGenericTail(preferBracketed(stripPcscSuffix(raw)));
        const auto serial = unitSerial(raw);
        const bool dualInterfaceUnit = !serial.empty() && slotsPerUnit[serial].size() > 1;

        if (dualInterfaceUnit) {
            // Classify and strip off the SAME predicate, so the two can never
            // disagree about one string.
            id.iface = endsWithContactlessMarker(model) ? ReaderInterface::Contactless : ReaderInterface::Contact;
            model = dropContactlessMarker(std::move(model));
        }

        id.model = model.empty() ? raw : model;
        out.push_back(std::move(id));
    }
    return out;
}

} // namespace LibreSCRS::Agent
