// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <string_view>

namespace LibreSCRS::Agent {

// Whether @p atrHex is the pseudo-ATR a PC/SC reader builds for a card it
// reaches through its antenna (PC/SC Part 3: 3B 8n 80 01, n historical bytes,
// TCK -- exactly 5 + n bytes). Hex of either case, as PresenceModel writes it.
// A contact ATR, or anything that is not a well-formed hex ATR, is not one.
[[nodiscard]] bool isContactlessPseudoAtr(std::string_view atrHex) noexcept;

} // namespace LibreSCRS::Agent
