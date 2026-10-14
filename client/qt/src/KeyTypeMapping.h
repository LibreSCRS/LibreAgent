// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// The agent's key-type vocabulary as this library's public one, for both
// transports' decoders.
#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <string_view>

namespace LibreSCRS::AgentClient::detail {

[[nodiscard]] constexpr KeyType toClientKeyType(LibreSCRS::Agent::KeyType t) noexcept
{
    switch (t) {
    case LibreSCRS::Agent::KeyType::Rsa:
        return KeyType::Rsa;
    case LibreSCRS::Agent::KeyType::Ec:
        return KeyType::Ec;
    case LibreSCRS::Agent::KeyType::Other:
        break;
    }
    return KeyType::Other;
}

/// The D-Bus `s keyType` token; an unknown one reads as Other.
[[nodiscard]] constexpr KeyType keyTypeFromWireToken(std::string_view token) noexcept
{
    return toClientKeyType(LibreSCRS::Agent::keyTypeFromToken(token));
}

} // namespace LibreSCRS::AgentClient::detail
