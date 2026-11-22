// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "presence/ContactlessAtr.h"

#include <cstddef>
#include <optional>

namespace LibreSCRS::Agent {
namespace {

std::optional<unsigned> nibble(char c) noexcept
{
    if (c >= '0' && c <= '9') {
        return static_cast<unsigned>(c - '0');
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<unsigned>(c - 'A' + 10);
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<unsigned>(c - 'a' + 10);
    }
    return std::nullopt;
}

std::optional<unsigned> byteAt(std::string_view hex, std::size_t index) noexcept
{
    const auto hi = nibble(hex[2 * index]);
    const auto lo = nibble(hex[2 * index + 1]);
    if (!hi || !lo) {
        return std::nullopt;
    }
    return (*hi << 4) | *lo;
}

} // namespace

bool isContactlessPseudoAtr(std::string_view atrHex) noexcept
{
    // TS 3B, T0 8n (only TD1 follows, n historical bytes), TD1 80 (TD2 follows,
    // protocol T=0), TD2 01 (T=1, nothing follows), then the historical bytes
    // and TCK: 5 + n bytes in all.
    if (atrHex.size() % 2 != 0 || atrHex.size() < 2 * 5) {
        return false;
    }
    for (const char c : atrHex) {
        if (!nibble(c)) {
            return false;
        }
    }
    const auto ts = byteAt(atrHex, 0);
    const auto t0 = byteAt(atrHex, 1);
    const auto td1 = byteAt(atrHex, 2);
    const auto td2 = byteAt(atrHex, 3);
    if (*ts != 0x3B || (*t0 & 0xF0U) != 0x80 || *td1 != 0x80 || *td2 != 0x01) {
        return false;
    }
    const std::size_t historical = *t0 & 0x0FU;
    return atrHex.size() / 2 == 5 + historical;
}

} // namespace LibreSCRS::Agent
