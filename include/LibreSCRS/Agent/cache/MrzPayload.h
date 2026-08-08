// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief THE canonical prompter MRZ payload contract: parse the prompter's
///        3-line MRZ payload into the union of credential parts BOTH LM
///        activation branches consume. Single definition, reused by the
///        renegotiation deposit later.

#include <LibreSCRS/Secure/String.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace LibreSCRS::Agent {

/// @brief The four parts a canonical MRZ payload yields.
///
/// The prompter's payload is exactly three lines:
///   docNo+cd '\n' dob+cd '\n' doe+cd
///   - field 1: EXACTLY [A-Z0-9<]{9} then one decimal check digit (10 chars) —
///     the producing widget's regex VERBATIM (MrzInputWidget.cpp:58-60,
///     ^[A-Z0-9<]{9}[0-9]$); short document numbers arrive '<'-padded to 9 BY
///     THE WIDGET. The {9} (not {1,9}) grammar is deliberate: an unpadded shape
///     the widget cannot emit would key PACE and BAC to DIFFERENT
///     MRZ_information (silent asymmetric failure).
///   - fields 2,3: [0-9]{6} then one decimal check digit (exactly 7 chars).
///   - STRICT: exactly two '\n', no trailing newline, uppercase only, no other
///     characters.
///
/// Check digits are VERIFIED: the parser recomputes all three via the ICAO
/// 9303 Part 3 §4.9 (7-3-1) scheme — the same algorithm LM's
/// buildMrzInformation uses (crypto_utils.cpp:79-114) — and REJECTS on any
/// mismatch.
///
/// PRIMARY INVARIANT (single source of truth): for every accepted payload
///   mrzInfo == buildMrzInformation(documentNumber, dateOfBirth, dateOfExpiry)
/// holds BY CONSTRUCTION — mrzInfo is the three transported fields concatenated
/// (the exact-9 docNo kept verbatim, the check digits verified), so PACE (which
/// hashes the transported mrzInfo) and BAC (which recomputes from the trio) can
/// never key differently.
struct MrzParts
{
    /// @brief == MRZ_information: the three fields concatenated WITH their check
    ///        digits and no separators (PACE cache slot "mrz"; SHA-1'd in full
    ///        by derivePaceKpiSeed).
    LibreSCRS::Secure::String mrzInfo;
    /// @brief Document number, check digit STRIPPED. The '<' padding is kept
    ///        VERBATIM — LM's buildMrzInformation re-pads a short docNo to 9,
    ///        which is a no-op on the already-9 field.
    LibreSCRS::Secure::String documentNumber;
    /// @brief Date of birth, YYMMDD, check digit STRIPPED (6 digits).
    LibreSCRS::Secure::String dateOfBirth;
    /// @brief Date of expiry, YYMMDD, check digit STRIPPED (6 digits).
    LibreSCRS::Secure::String dateOfExpiry;
};

namespace detail {

/// @brief ICAO 9303 Part 3 §4.9 check digit (weights 7,3,1 repeating).
///
/// Computed over a @c std::string_view directly (D14: no intermediate
/// @c std::string scratch of the secret bytes). Returns -1 on any character
/// outside [A-Z0-9<] (a malformed field already rejected by the grammar
/// checks, but guarded here so a stray byte can never yield a spurious digit).
[[nodiscard]] inline int mrzCheckDigit(std::string_view field) noexcept
{
    static constexpr int weights[3] = {7, 3, 1};
    int sum = 0;
    for (std::size_t i = 0; i < field.size(); ++i) {
        const char c = field[i];
        int value = 0;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'A' && c <= 'Z') {
            value = c - 'A' + 10;
        } else if (c == '<') {
            value = 0;
        } else {
            return -1;
        }
        sum += value * weights[i % 3];
    }
    return sum % 10;
}

/// @brief Field 1 grammar: EXACTLY ^[A-Z0-9<]{9}[0-9]$ (10 chars).
[[nodiscard]] inline bool isDocNumberField(std::string_view f) noexcept
{
    if (f.size() != 10) {
        return false;
    }
    for (std::size_t i = 0; i < 9; ++i) {
        const char c = f[i];
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '<';
        if (!ok) {
            return false;
        }
    }
    return f[9] >= '0' && f[9] <= '9';
}

/// @brief Date field grammar: EXACTLY ^[0-9]{6}[0-9]$ == 7 decimal digits.
[[nodiscard]] inline bool isDateField(std::string_view f) noexcept
{
    if (f.size() != 7) {
        return false;
    }
    for (const char c : f) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

/// @brief The field's trailing char is the transported check digit; verify it
///        against the ICAO 7-3-1 recomputation over the field body (all but the
///        last char). Computed over views only — no std::string scratch.
[[nodiscard]] inline bool checkDigitVerifies(std::string_view field) noexcept
{
    const std::string_view body = field.substr(0, field.size() - 1);
    const int recomputed = mrzCheckDigit(body);
    if (recomputed < 0) {
        return false;
    }
    return field.back() == static_cast<char>('0' + recomputed);
}

} // namespace detail

/// @brief Parse the canonical 3-line MRZ payload into its four parts.
///
/// @return An @ref MrzParts on a payload that satisfies the grammar AND whose
///         three transported check digits all verify; @c std::nullopt on ANY
///         grammar violation or check-digit mismatch.
///
/// Never materialises a plain (un-cleansed) @c std::string copy of the secret
/// bytes: the grammar and check-digit work runs over @c Secure::String views;
/// the four parts are built via @c Secure::String views (the trio, contiguous
/// sub-views of the payload) and the adopt-and-cleanse rvalue ctor (mrzInfo,
/// whose scratch is zeroised by the constructor on every exit path — mirroring
/// buildMrzInfo, emrtd_card_plugin.cpp:104-108).
[[nodiscard]] inline std::optional<MrzParts> parseMrzPayload(const LibreSCRS::Secure::String& payload)
{
    const std::string_view v = payload.view();

    // Exactly two '\n' and no trailing newline: split into exactly three
    // fields. A third '\n' anywhere (trailing newline OR a fourth field) is a
    // rejection.
    const std::size_t nl1 = v.find('\n');
    if (nl1 == std::string_view::npos) {
        return std::nullopt;
    }
    const std::size_t nl2 = v.find('\n', nl1 + 1);
    if (nl2 == std::string_view::npos) {
        return std::nullopt;
    }
    if (v.find('\n', nl2 + 1) != std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view f1 = v.substr(0, nl1);
    const std::string_view f2 = v.substr(nl1 + 1, nl2 - (nl1 + 1));
    const std::string_view f3 = v.substr(nl2 + 1);

    if (!detail::isDocNumberField(f1) || !detail::isDateField(f2) || !detail::isDateField(f3)) {
        return std::nullopt;
    }
    if (!detail::checkDigitVerifies(f1) || !detail::checkDigitVerifies(f2) || !detail::checkDigitVerifies(f3)) {
        return std::nullopt;
    }

    MrzParts parts;
    // Trio: contiguous sub-views, check digit stripped, '<' padding VERBATIM.
    // The string_view ctor copies into cleansing storage from the payload's own
    // (already cleansing) storage — no plain std::string is created.
    parts.documentNumber = LibreSCRS::Secure::String{f1.substr(0, 9)};
    parts.dateOfBirth = LibreSCRS::Secure::String{f2.substr(0, 6)};
    parts.dateOfExpiry = LibreSCRS::Secure::String{f3.substr(0, 6)};

    // mrzInfo = f1 + f2 + f3 (the payload with the two '\n' removed, check
    // digits kept). Assembled via adopt-and-cleanse: the scratch is zeroised by
    // the Secure::String rvalue ctor on every exit path, so no plain std::string
    // copy of the secret survives.
    {
        std::string scratch;
        scratch.reserve(f1.size() + f2.size() + f3.size());
        scratch.append(f1).append(f2).append(f3);
        parts.mrzInfo = LibreSCRS::Secure::String{std::move(scratch)};
    }

    return parts;
}

} // namespace LibreSCRS::Agent
