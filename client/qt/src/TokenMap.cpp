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
    case SignatureLevel::Auto:
        // No wire token: AgentCard omits the "level" key for Auto and the
        // socket transport materialises the "auto" sentinel in its place.
        // Reaching this arm means a caller bypassed that path.
        return {};
    }
    return {};
}

std::string_view toToken(Packaging packaging) noexcept
{
    switch (packaging) {
    case Packaging::Enveloped:
        return "enveloped";
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

} // namespace LibreSCRS::AgentClient::detail
