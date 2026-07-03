// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <span>
#include <string>
namespace LibreSCRS::Agent {

// Lowercase-hex SHA-256 over arbitrary bytes. Used to derive the certificate
// certId from its DER encoding. Total: zero-byte input yields SHA-256("").
[[nodiscard]] std::string sha256Hex(std::span<const std::uint8_t> bytes);

} // namespace LibreSCRS::Agent
