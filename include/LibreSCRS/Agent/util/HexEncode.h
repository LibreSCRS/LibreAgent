// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <span>
#include <string>

namespace LibreSCRS::Agent {

// Byte -> hex string. The single agent-internal hex encoder behind the
// certificate serial (colon-separated, upper), the key-id / fingerprint
// presentation (upper, no separator), and the SHA-256 cert-id (lower, no
// separator).
//
// @p separator is inserted between bytes when non-NUL ('\0' = none).
// @p upper selects upper- vs lower-case nibbles.
//
// LM's own formatHex is unexported across the .so boundary, so consolidating
// here (agent-internal) is correct rather than reaching into LM.
[[nodiscard]] inline std::string toHex(std::span<const std::uint8_t> bytes, char separator = '\0', bool upper = true)
{
    static constexpr char kUpper[] = "0123456789ABCDEF";
    static constexpr char kLower[] = "0123456789abcdef";
    const char* const tbl = upper ? kUpper : kLower;

    std::string out;
    out.reserve(bytes.size() * (separator != '\0' ? 3 : 2));
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (separator != '\0' && i != 0) {
            out.push_back(separator);
        }
        out.push_back(tbl[(bytes[i] >> 4) & 0x0F]);
        out.push_back(tbl[bytes[i] & 0x0F]);
    }
    return out;
}

} // namespace LibreSCRS::Agent
