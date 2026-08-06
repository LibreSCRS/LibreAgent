// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <array>
#include <cmath> // std::isfinite
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Agent-side, Qt-free signing-parameter vocabulary: the format magic-byte
// sniffer, the per-format default packaging, and the closed-set validators.
// Pure functions (no card, no LM, no bus) so the Card1.Sign method-entry
// resolution + the out-of-vocabulary rejection are unit-testable without a
// D-Bus round-trip.
namespace LibreSCRS::Agent::Operations::SignatureParams {

// Resolve format=auto to a concrete container from the document's leading
// bytes. Empty optional => unrecognised (Error.UnsupportedSignatureParameter).
//   %PDF -> pades, PK(zip) -> asice, '<' -> xades, '{' -> jades, 0x30 -> cades.
[[nodiscard]] inline std::optional<std::string> sniffFormat(const std::vector<std::uint8_t>& doc)
{
    if (doc.size() >= 4 && doc[0] == '%' && doc[1] == 'P' && doc[2] == 'D' && doc[3] == 'F') {
        return "pades";
    }
    if (doc.size() >= 2 && doc[0] == 'P' && doc[1] == 'K') {
        return "asice"; // ZIP container
    }
    // Skip leading ASCII whitespace for the text-format sniff.
    std::size_t i = 0;
    while (i < doc.size() && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\r' || doc[i] == '\n')) {
        ++i;
    }
    if (i < doc.size()) {
        if (doc[i] == '<') {
            return "xades";
        }
        if (doc[i] == '{') {
            return "jades";
        }
        if (doc[i] == 0x30) {
            return "cades"; // DER SEQUENCE
        }
    }
    return std::nullopt;
}

// Default packaging per resolved format: PAdES/ASiC-E envelope; the detached
// CMS/XML/JSON families default to detached.
[[nodiscard]] inline std::string defaultPackagingFor(const std::string& format)
{
    if (format == "pades" || format == "asice") {
        return "enveloped";
    }
    return "detached";
}

// The three CLOSED sign-option vocabularies, as ENUMERABLE lists rather than
// as chained comparisons. Each is the resolved form: `sign-format`,
// `sign-level` and `packaging-mode` in wire/librescrs-agent.cddl, whose
// requested-* counterparts add the "auto" sentinel a client may ask for and a
// result can never report.
//
// Enumerable is the point. These were four separate hand-written comparison
// chains -- here, in the grammar, in ConfigStore's own level check and in the
// client's token map -- and nothing compared them, so a member added to one
// was added to the others only by whoever remembered. WireContractGuardTest
// now reads the grammar's groups and compares them to these arrays entry by
// entry, which no chain of `||` could have been compared against.
inline constexpr std::array<std::string_view, 5> kSignFormats{"pades", "cades", "xades", "jades", "asice"};
inline constexpr std::array<std::string_view, 4> kSignLevels{"b-b", "b-t", "b-lt", "b-lta"};
inline constexpr std::array<std::string_view, 2> kPackagingModes{"enveloped", "detached"};

template <std::size_t N>
[[nodiscard]] constexpr bool isMemberOf(const std::array<std::string_view, N>& vocabulary,
                                        std::string_view token) noexcept
{
    for (const auto entry : vocabulary) {
        if (entry == token) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] inline bool isKnownFormat(std::string_view f) noexcept
{
    return isMemberOf(kSignFormats, f);
}

[[nodiscard]] inline bool isKnownLevel(std::string_view l) noexcept
{
    return isMemberOf(kSignLevels, l);
}

[[nodiscard]] inline bool isKnownPackaging(std::string_view p) noexcept
{
    return isMemberOf(kPackagingModes, p);
}

// True for the timestamped / long-term family (b-t/b-lt/b-lta), false for the
// baseline b-b. Drives the expired-cert gate's qualified-family rule and the
// declarative timestamping phase emission. An unknown string is treated as
// non-qualified (the closed-set validators reject it earlier).
[[nodiscard]] inline bool isQualifiedSignLevel(const std::string& level) noexcept
{
    return level == "b-t" || level == "b-lt" || level == "b-lta";
}

// Honest derivation of "a timestamp was actually applied to this signature",
// for the Sign1.meta tsaUsed flag. The installed LM SigningResult carries no
// per-token tsaUsed flag, so this is derived: a timestamp was applied iff the
// sign SUCCEEDED at a qualified level AND a TSA was configured (so the LM had a
// non-empty TsaProvider to contact). This replaces an earlier level-only guess
// that reported true for any qualified level even with no TSA configured.
[[nodiscard]] inline bool timestampWasApplied(bool signOk, const std::string& level, bool hasTsa) noexcept
{
    return signOk && hasTsa && isQualifiedSignLevel(level);
}

// Signature levels this release actually produces: the whole baseline family.
// b-b and b-t are self-contained; b-lt/b-lta have the LM complete the chain from
// the configured Trusted List and embed revocation, failing closed (ChainIncomplete
// / RevocationFetchFailed, surfaced on the Operation) when the issuing CA or fresh
// revocation cannot be obtained. The Card1.Sign scope gate admits all four;
// anything outside the closed vocabulary is never implemented.
//
// SINGLE SOURCE: the gate predicate isImplementedSignLevel and the human
// rejection message implementedSignLevelsDisplay both derive from this list, so
// they can never drift (the historical bug: the predicate widened to b-lt/b-lta
// but the message still said "only b-b and b-t").
//
// It IS the vocabulary, not a copy of it: this release implements every level
// the wire admits. Kept as a distinct name because the two ideas are distinct
// -- "in the vocabulary" and "this release produces it" -- so if a level is
// ever added to the grammar ahead of its implementation, this becomes its own
// array again and only the one place that must change does.
inline constexpr const auto& kImplementedSignLevels = kSignLevels;

[[nodiscard]] inline bool isImplementedSignLevel(std::string_view level) noexcept
{
    for (const auto l : kImplementedSignLevels) {
        if (level == l) {
            return true;
        }
    }
    return false;
}

// Comma-separated rendering of kImplementedSignLevels for client-facing
// rejection messages — DRIVEN by the same list as the gate predicate above.
[[nodiscard]] inline std::string implementedSignLevelsDisplay()
{
    std::string out;
    for (const auto l : kImplementedSignLevels) {
        if (!out.empty()) {
            out += ", ";
        }
        out += l;
    }
    return out;
}

// The "let the agent decide" sentinel for a requested level, in ONE place so
// the D-Bus and socket frontends cannot drift apart -- they used to open-code
// this differently, and had: one accepted "auto", the other only an absent
// key. Empty or "auto" => nullopt, which resolveSignLevel below reads as
// "apply the configured default". "" is tolerated for robustness but is NOT
// contractual: the CDDL's requested-level group does not admit it and no
// client in this stack emits it. Anything else passes through verbatim for
// isKnownLevel / isImplementedSignLevel to judge.
[[nodiscard]] inline std::optional<std::string> requestedLevelFrom(std::string_view level)
{
    if (level.empty() || level == "auto") {
        return std::nullopt;
    }
    return std::string{level};
}

// Resolve the effective per-request signing level. An explicit @p requested
// level always wins. Otherwise the agent's configured default is used as-is,
// EXCEPT that a defaulted "b-b" upgrades to "b-t" when a timestamp authority is
// configured (@p hasTsa) — so a site that configures a TSA gets timestamped
// signatures by default without ever mutating the stored DefaultLevel property.
[[nodiscard]] inline std::string resolveSignLevel(const std::optional<std::string>& requested,
                                                  const std::string& configuredDefault, bool hasTsa)
{
    if (requested.has_value()) {
        return *requested;
    }
    if (configuredDefault == "b-b" && hasTsa) {
        return "b-t";
    }
    return configuredDefault;
}

// A lightweight pre-flight filter for a per-request `tsaUrl` sign option
// (mirrors LM's own `staticTsaChecked`, but https-ONLY -- this wire never
// permits a plaintext TSA endpoint, unlike LM's http-tolerant factory):
// non-empty, begins with "https://", and a non-empty host token follows the
// scheme before the next '/' (or end of string). Rejects "https:///path"
// (empty host) and anything without the scheme. Full RFC 3986 validation is
// NOT attempted here -- libcurl does that at transport time; this only
// catches the obvious method-entry mistakes (wrong/missing scheme, empty
// host) the same way the other closed-set validators above do.
[[nodiscard]] inline bool isValidTsaUrl(const std::string& url) noexcept
{
    constexpr std::string_view kPrefix = "https://";
    if (url.size() <= kPrefix.size() || url.compare(0, kPrefix.size(), kPrefix) != 0) {
        return false;
    }
    const std::string_view rest{url.data() + kPrefix.size(), url.size() - kPrefix.size()};
    const auto hostEnd = rest.find('/');
    const std::string_view host = rest.substr(0, hostEnd);
    return !host.empty();
}

// Geometry gate for any visual-signature-appearance RECTANGLE this wire
// carries -- shared by both the per-request `Sign` option's `visualSignature`
// box (below) and the card-independent `Manager1.LayoutVisualSignature`
// box: a strictly positive width/height, and ALL FOUR of x/y/width/height
// finite (mirrors LM's own `VisualSignatureParams::Builder::rect`
// precondition, which throws `std::invalid_argument` for the same
// violations) -- checked at method entry so a malformed rectangle is a clean
// method-entry rejection, never an exception (or UB) surfacing out of LM. The
// finite check matters beyond mere sanity: both call sites narrow these
// doubles into LM's integer `Rect` via `static_cast<int>(std::lround(...))`,
// and `std::lround` on +-inf/NaN is unspecified behaviour, with the
// subsequent narrowing cast of an out-of-range double to `int` being
// undefined behaviour -- both CBOR (both daemons) and D-Bus's `d` type carry
// +-inf/NaN canonically, so this must be rejected here, at the one shared
// entry point every daemon calls through, rather than trusted to be finite
// downstream.
[[nodiscard]] inline bool isValidLayoutRect(double x, double y, double width, double height) noexcept
{
    return std::isfinite(x) && std::isfinite(y) && std::isfinite(width) && std::isfinite(height) && width > 0.0 &&
           height > 0.0;
}

// Sign's `visualSignature` option additionally carries a non-negative
// zero-based page index alongside the rectangle above.
[[nodiscard]] inline bool isValidVisualGeometry(std::int64_t page, double x, double y, double width,
                                                double height) noexcept
{
    return page >= 0 && isValidLayoutRect(x, y, width, height);
}

} // namespace LibreSCRS::Agent::Operations::SignatureParams
