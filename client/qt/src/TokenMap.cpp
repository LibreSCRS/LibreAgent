// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "TokenMap.h"

namespace LibreSCRS::AgentClient::detail {

std::string_view toToken(SignatureFormat format) noexcept
{
    switch (format) {
    case SignatureFormat::PAdES:
        return "pades";
    case SignatureFormat::CAdES:
        return "cades";
    case SignatureFormat::XAdES:
        return "xades";
    case SignatureFormat::JAdES:
        return "jades";
    case SignatureFormat::ASiCe:
        return "asice";
    }
    return {}; // unreachable for a valid enumerator -- -Wswitch catches an appended one
}

std::string_view toToken(SignatureLevel level) noexcept
{
    switch (level) {
    case SignatureLevel::BB:
        return "b-b";
    case SignatureLevel::BT:
        return "b-t";
    case SignatureLevel::BLT:
        return "b-lt";
    case SignatureLevel::BLTA:
        return "b-lta";
    }
    return {};
}

std::string_view toToken(Packaging packaging) noexcept
{
    switch (packaging) {
    case Packaging::Enveloped:
        return "enveloped";
    case Packaging::Enveloping:
        return "enveloping";
    case Packaging::Detached:
        return "detached";
    }
    return {};
}

std::string_view toToken(PinVerb verb) noexcept
{
    switch (verb) {
    case PinVerb::Change:
        return "change";
    case PinVerb::Unblock:
        return "unblock";
    case PinVerb::ActivatePin:
        return "activate_pin";
    }
    return {};
}

std::optional<SignatureFormat> signatureFormatFromToken(std::string_view token) noexcept
{
    if (token == "pades") {
        return SignatureFormat::PAdES;
    }
    if (token == "cades") {
        return SignatureFormat::CAdES;
    }
    if (token == "xades") {
        return SignatureFormat::XAdES;
    }
    if (token == "jades") {
        return SignatureFormat::JAdES;
    }
    if (token == "asice") {
        return SignatureFormat::ASiCe;
    }
    return std::nullopt;
}

std::optional<SignatureLevel> signatureLevelFromToken(std::string_view token) noexcept
{
    if (token == "b-b") {
        return SignatureLevel::BB;
    }
    if (token == "b-t") {
        return SignatureLevel::BT;
    }
    if (token == "b-lt") {
        return SignatureLevel::BLT;
    }
    if (token == "b-lta") {
        return SignatureLevel::BLTA;
    }
    return std::nullopt;
}

std::optional<Packaging> packagingFromToken(std::string_view token) noexcept
{
    if (token == "enveloped") {
        return Packaging::Enveloped;
    }
    if (token == "enveloping") {
        return Packaging::Enveloping;
    }
    if (token == "detached") {
        return Packaging::Detached;
    }
    return std::nullopt;
}

std::optional<PinVerb> pinVerbFromToken(std::string_view token) noexcept
{
    if (token == "change") {
        return PinVerb::Change;
    }
    if (token == "unblock") {
        return PinVerb::Unblock;
    }
    if (token == "activate_pin") {
        return PinVerb::ActivatePin;
    }
    return std::nullopt;
}

} // namespace LibreSCRS::AgentClient::detail
