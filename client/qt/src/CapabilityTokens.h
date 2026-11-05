// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — not client API, never installed. The token spelling of a
// capability bitfield, as `AgentCard::capabilities()` hands it back; the
// inverse, `capabilityBits()`, is public in `AgentCapabilities.h`.
#include <LibreSCRS/AgentClient/AgentCapabilities.h>

#include <QStringList>

#include <cstdint>

namespace LibreSCRS::AgentClient {

/// @brief The token list for @p caps, in ascending bit order. Known bits use
///        their contract names ("Pki", "IdentityData", "EmrtdCrypto",
///        "PinManagement"); an unknown bit i (a future, appended capability)
///        round-trips as "bit<i>" instead of being silently dropped.
[[nodiscard]] inline QStringList capabilityTokens(std::uint32_t caps)
{
    QStringList tokens;
    for (unsigned int bit = 0; bit < 32U; ++bit) {
        const std::uint32_t flag = std::uint32_t{1} << bit;
        if (!has(caps, flag)) {
            continue;
        }
        switch (flag) {
        case Cap::Pki:
            tokens.append(QStringLiteral("Pki"));
            break;
        case Cap::IdentityData:
            tokens.append(QStringLiteral("IdentityData"));
            break;
        case Cap::EmrtdCrypto:
            tokens.append(QStringLiteral("EmrtdCrypto"));
            break;
        case Cap::PinManagement:
            tokens.append(QStringLiteral("PinManagement"));
            break;
        default:
            tokens.append(QStringLiteral("bit%1").arg(bit));
            break;
        }
    }
    return tokens;
}

} // namespace LibreSCRS::AgentClient
