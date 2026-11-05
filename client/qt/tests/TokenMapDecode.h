// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// The inverse of src/TokenMap.h's encoders, for the test alone: the library
// sends these tokens and never parses one back, so a decoder in it would be
// code only a test calls. Built by searching the encoder over every
// enumerator, which makes a round trip through it a statement about the
// encoder: every token distinct, and an empty one (SignatureLevel::Auto has no
// token) never read back as a value.
#include "../src/TokenMap.h"

#include <array>
#include <cstddef>
#include <optional>
#include <string_view>

namespace LibreSCRS::AgentClient::detail {

template <typename E, std::size_t N>
[[nodiscard]] std::optional<E> fromToken(std::string_view token, const std::array<E, N>& every) noexcept
{
    if (token.empty()) {
        return std::nullopt;
    }
    for (const E value : every) {
        if (toToken(value) == token) {
            return value;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<SignatureFormat> signatureFormatFromToken(std::string_view token) noexcept
{
    return fromToken(token, std::array{SignatureFormat::PAdES, SignatureFormat::CAdES, SignatureFormat::XAdES,
                                       SignatureFormat::JAdES, SignatureFormat::ASiCe});
}

[[nodiscard]] inline std::optional<SignatureLevel> signatureLevelFromToken(std::string_view token) noexcept
{
    return fromToken(token, std::array{SignatureLevel::BB, SignatureLevel::BT, SignatureLevel::BLT,
                                       SignatureLevel::BLTA, SignatureLevel::Auto});
}

[[nodiscard]] inline std::optional<Packaging> packagingFromToken(std::string_view token) noexcept
{
    return fromToken(token, std::array{Packaging::Enveloped, Packaging::Detached});
}

[[nodiscard]] inline std::optional<PinVerb> pinVerbFromToken(std::string_view token) noexcept
{
    return fromToken(token, std::array{PinVerb::Change, PinVerb::Unblock, PinVerb::ActivatePin});
}

} // namespace LibreSCRS::AgentClient::detail
