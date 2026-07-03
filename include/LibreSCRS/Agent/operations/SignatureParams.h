// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <array>
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

[[nodiscard]] inline bool isKnownFormat(const std::string& f) noexcept
{
    return f == "pades" || f == "cades" || f == "xades" || f == "jades" || f == "asice";
}

[[nodiscard]] inline bool isKnownLevel(const std::string& l) noexcept
{
    return l == "b-b" || l == "b-t" || l == "b-lt" || l == "b-lta";
}

[[nodiscard]] inline bool isKnownPackaging(const std::string& p) noexcept
{
    return p == "enveloped" || p == "detached";
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
inline constexpr std::array<std::string_view, 4> kImplementedSignLevels{"b-b", "b-t", "b-lt", "b-lta"};

[[nodiscard]] inline bool isImplementedSignLevel(const std::string& level) noexcept
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

} // namespace LibreSCRS::Agent::Operations::SignatureParams
