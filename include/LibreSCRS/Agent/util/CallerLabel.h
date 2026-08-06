// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace LibreSCRS::Agent {

// Platform-neutral caller-label shaping for the consent prompt's client-chrome
// area ("Requested by: <x>"). A backend resolves a calling process
// to an executable path however its OS allows (Linux: pidfd-pinned
// /proc/<pid>/exe; macOS: audit token), then feeds the basename through
// sanitizeLabel() before it reaches the prompter. Hosting the shaping here means
// every backend renders caller labels through ONE anti-spoofing guard rather
// than re-implementing it per platform.

// Upper bound on the rendered label length. A pathological executable name must
// not be able to flood the prompter's client-chrome area.
inline constexpr std::size_t kMaxCallerLabelLength = 128;

// Final path component of an executable path. Pure; no I/O. Returns the input's
// filename component ("/usr/bin/seahorse" -> "seahorse"). Empty in, empty out.
[[nodiscard]] inline std::string exeBasename(const std::filesystem::path& exePath)
{
    // filename() yields the final path component; for a bare "plain" with no
    // separators it returns "plain", and for an empty path it returns "".
    return exePath.filename().string();
}

// Render an untrusted, client-derived string safe for display as a single inert
// line: every C0 control byte (newline, CR, tab, ESC, ...) and DEL collapses to
// a space, as does every multi-byte Unicode separator or direction control that
// a text engine would honour as a line break or bidi reordering, and the result
// is truncated to kMaxCallerLabelLength without splitting a UTF-8 code point.
// This is the anti-spoofing guard for the prompter's client-chrome area — a
// hostile exe name cannot forge extra lines, inject terminal escapes, or
// visually reorder the surrounding prompt text.
[[nodiscard]] inline std::string sanitizeLabel(std::string raw)
{
    for (char& ch : raw) {
        // Treat the byte as unsigned for the control-character test; a signed
        // char with the high bit set is a valid UTF-8 continuation byte and must
        // pass through unaltered so non-ASCII executable names survive.
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte == 0x7f) {
            // C0 control byte or DEL — collapse to a space so the label can only
            // ever render as one inert line (no forged newlines/escapes).
            ch = ' ';
        }
    }
    // Text engines also honour multi-byte Unicode characters the byte-wise pass
    // above cannot catch: U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR and
    // U+0085 NEXT LINE break lines, and the bidi marks (U+200E/U+200F),
    // embeddings/overrides (U+202A..U+202E) and isolates (U+2066..U+2069)
    // visually reorder neighbouring text. Collapse each to one space, the same
    // policy as newline/CR above.
    static constexpr std::string_view kForbiddenSequences[] = {
        "\xE2\x80\xA8", // U+2028 LINE SEPARATOR
        "\xE2\x80\xA9", // U+2029 PARAGRAPH SEPARATOR
        "\xC2\x85",     // U+0085 NEXT LINE
        "\xE2\x80\x8E", // U+200E LEFT-TO-RIGHT MARK
        "\xE2\x80\x8F", // U+200F RIGHT-TO-LEFT MARK
        "\xE2\x80\xAA", // U+202A LEFT-TO-RIGHT EMBEDDING
        "\xE2\x80\xAB", // U+202B RIGHT-TO-LEFT EMBEDDING
        "\xE2\x80\xAC", // U+202C POP DIRECTIONAL FORMATTING
        "\xE2\x80\xAD", // U+202D LEFT-TO-RIGHT OVERRIDE
        "\xE2\x80\xAE", // U+202E RIGHT-TO-LEFT OVERRIDE
        "\xE2\x81\xA6", // U+2066 LEFT-TO-RIGHT ISOLATE
        "\xE2\x81\xA7", // U+2067 RIGHT-TO-LEFT ISOLATE
        "\xE2\x81\xA8", // U+2068 FIRST STRONG ISOLATE
        "\xE2\x81\xA9", // U+2069 POP DIRECTIONAL ISOLATE
    };
    for (const std::string_view seq : kForbiddenSequences) {
        for (std::size_t pos = 0; (pos = raw.find(seq, pos)) != std::string::npos; ++pos) {
            raw.replace(pos, seq.size(), " ");
        }
    }
    if (raw.size() > kMaxCallerLabelLength) {
        // Back off any UTF-8 continuation bytes at the cut so truncation cannot
        // split a multi-byte code point and leave a mojibake tail.
        std::size_t cut = kMaxCallerLabelLength;
        while (cut > 0 && (static_cast<unsigned char>(raw[cut]) & 0xC0) == 0x80) {
            --cut;
        }
        raw.resize(cut);
    }
    return raw;
}

} // namespace LibreSCRS::Agent
