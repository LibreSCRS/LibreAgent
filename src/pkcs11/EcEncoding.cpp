// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/pkcs11/EcEncoding.h>

#include <LibreSCRS/Agent/KeyType.h> // the NIST curve table

#include <cstddef>

namespace LibreSCRS::Pkcs11Agent {

namespace {

// A DER definite length below 64 KiB: short form, or 0x81 / 0x82 long form.
void appendDerLength(std::vector<std::uint8_t>& out, std::size_t n)
{
    if (n < 0x80) {
        out.push_back(static_cast<std::uint8_t>(n));
    } else if (n <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(n));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(n >> 8));
        out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    }
}

} // namespace

std::span<const std::uint8_t> ecParamsDerFor(std::uint32_t keyBits) noexcept
{
    const LibreSCRS::Agent::NistCurve* c = LibreSCRS::Agent::nistCurveByBits(keyBits);
    return c != nullptr ? c->oidDer : std::span<const std::uint8_t>{};
}

bool isNamedCurvePoint(std::string_view crv, std::span<const std::uint8_t> x, std::span<const std::uint8_t> y) noexcept
{
    const LibreSCRS::Agent::NistCurve* c = LibreSCRS::Agent::nistCurveByName(crv);
    return c != nullptr && x.size() == c->fieldBytes && y.size() == c->fieldBytes;
}

bool isPointOfKey(std::uint32_t keyBits, std::string_view crv, std::span<const std::uint8_t> x,
                  std::span<const std::uint8_t> y) noexcept
{
    const LibreSCRS::Agent::NistCurve* c = LibreSCRS::Agent::nistCurveByBits(keyBits);
    return c != nullptr && c->crv == crv && isNamedCurvePoint(crv, x, y);
}

std::vector<std::uint8_t> ecPointOctetString(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y)
{
    if (x.empty() || x.size() != y.size()) {
        return {};
    }
    const std::size_t pointLen = 1 + x.size() + y.size();
    std::vector<std::uint8_t> out;
    out.reserve(pointLen + 4);
    out.push_back(0x04); // OCTET STRING
    appendDerLength(out, pointLen);
    out.push_back(0x04); // uncompressed point
    out.insert(out.end(), x.begin(), x.end());
    out.insert(out.end(), y.begin(), y.end());
    return out;
}

} // namespace LibreSCRS::Pkcs11Agent
