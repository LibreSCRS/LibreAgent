// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <span>

namespace LibreSCRS::Agent {

// Is this byte sequence renderable as GUI label text? True only for
// well-formed UTF-8 (multi-byte included — never reject real text) with no
// C0 control characters and no DEL. Rejects structurally invalid sequences,
// overlong encodings, UTF-16 surrogates, and beyond-Unicode code points —
// Qt would render those as U+FFFD mojibake.
//
// The display-safety companion of HexEncode.h's toHex: a value that fails
// this check is shown hex-formatted instead (see LmSeams.cpp's mapFields —
// e.g. a pkcs15 EF(TokenInfo) BCD serialNumber, whose raw bytes LM
// deliberately preserves per card-data integrity).
[[nodiscard]] inline bool isDisplayableUtf8(std::span<const std::uint8_t> bytes) noexcept
{
    for (std::size_t i = 0; i < bytes.size();) {
        const std::uint8_t c = bytes[i];
        if (c < 0x20 || c == 0x7F) {
            return false; // C0 controls / DEL — not renderable label text
        }
        if (c < 0x80) {
            ++i;
            continue;
        }
        std::size_t cont = 0;
        std::uint32_t cp = 0;
        if ((c & 0xE0) == 0xC0) {
            cont = 1;
            cp = c & 0x1FU;
        } else if ((c & 0xF0) == 0xE0) {
            cont = 2;
            cp = c & 0x0FU;
        } else if ((c & 0xF8) == 0xF0) {
            cont = 3;
            cp = c & 0x07U;
        } else {
            return false; // stray continuation or invalid lead byte
        }
        if (i + cont >= bytes.size()) {
            return false; // truncated sequence
        }
        for (std::size_t k = 1; k <= cont; ++k) {
            if ((bytes[i + k] & 0xC0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (bytes[i + k] & 0x3FU);
        }
        // Overlong encodings, UTF-16 surrogates, and beyond-Unicode code
        // points are not text even when structurally well-formed.
        static constexpr std::uint32_t kMinCp[] = {0x80, 0x800, 0x10000};
        if (cp < kMinCp[cont - 1] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += cont + 1;
    }
    return true;
}

} // namespace LibreSCRS::Agent
