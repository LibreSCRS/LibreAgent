// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstddef>
#include <filesystem>
#include <string>

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
// a space, and the result is truncated to kMaxCallerLabelLength. This is the
// anti-spoofing guard for the prompter's client-chrome area — a hostile exe
// name cannot forge extra lines or inject terminal escapes.
[[nodiscard]] inline std::string sanitizeLabel(std::string raw)
{
    std::string out;
    out.reserve(raw.size() < kMaxCallerLabelLength ? raw.size() : kMaxCallerLabelLength);
    for (const char ch : raw) {
        if (out.size() >= kMaxCallerLabelLength) {
            break;
        }
        // Treat the byte as unsigned for the control-character test; a signed
        // char with the high bit set is a valid UTF-8 continuation byte and must
        // pass through unaltered so non-ASCII executable names survive.
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte == 0x7f) {
            // C0 control byte or DEL — collapse to a space so the label can only
            // ever render as one inert line (no forged newlines/escapes).
            out.push_back(' ');
            continue;
        }
        out.push_back(ch);
    }
    return out;
}

} // namespace LibreSCRS::Agent
