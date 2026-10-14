// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The DER the module serves for an EC key with no crypto library of its own:
// the named curve's OID (CKA_EC_PARAMS) and the point as an OCTET STRING
// (CKA_EC_POINT), on each of the three curves the agent reports.
#include <LibreSCRS/Agent/pkcs11/EcEncoding.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace LibreSCRS::Pkcs11Agent;

TEST(EcEncoding, ParamsAreTheNamedCurvesOid)
{
    const auto p256 = ecParamsDerFor(256);
    EXPECT_EQ(std::vector<std::uint8_t>(p256.begin(), p256.end()),
              (std::vector<std::uint8_t>{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}));
    const auto p384 = ecParamsDerFor(384);
    EXPECT_EQ(std::vector<std::uint8_t>(p384.begin(), p384.end()),
              (std::vector<std::uint8_t>{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}));
    const auto p521 = ecParamsDerFor(521);
    EXPECT_EQ(std::vector<std::uint8_t>(p521.begin(), p521.end()),
              (std::vector<std::uint8_t>{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}));
    EXPECT_TRUE(ecParamsDerFor(0).empty());
    EXPECT_TRUE(ecParamsDerFor(2048).empty());
}

// The point is wrapped in an OCTET STRING whose length takes the long form on
// P-521 (133 bytes), where a short-form-only encoder would emit garbage.
TEST(EcEncoding, ThePointIsAnOctetStringOnEveryCurve)
{
    for (const auto& [width, header] : std::vector<std::pair<std::size_t, std::vector<std::uint8_t>>>{
             {32, {0x04, 0x41}}, {48, {0x04, 0x61}}, {66, {0x04, 0x81, 0x85}}}) {
        const std::vector<std::uint8_t> x(width, 0x11);
        const std::vector<std::uint8_t> y(width, 0x22);
        const auto der = ecPointOctetString(x, y);
        ASSERT_EQ(der.size(), header.size() + 1 + 2 * width) << width;
        EXPECT_TRUE(std::equal(header.begin(), header.end(), der.begin())) << width;
        EXPECT_EQ(der[header.size()], 0x04) << "uncompressed point";
        EXPECT_EQ(der[header.size() + 1], 0x11);
        EXPECT_EQ(der.back(), 0x22);
    }
}

TEST(EcEncoding, AMalformedPointIsNotEncoded)
{
    EXPECT_TRUE(ecPointOctetString({}, {}).empty());
    EXPECT_TRUE(ecPointOctetString(std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(31, 0x22)).empty());
}

// Only a point on one of the three curves, at that curve's width, is served.
TEST(EcEncoding, OnlyANamedCurvePointAtItsWidthIsServable)
{
    const std::vector<std::uint8_t> w32(32, 0x11);
    const std::vector<std::uint8_t> w48(48, 0x11);
    const std::vector<std::uint8_t> w66(66, 0x11);
    EXPECT_TRUE(isNamedCurvePoint("P-256", w32, w32));
    EXPECT_TRUE(isNamedCurvePoint("P-384", w48, w48));
    EXPECT_TRUE(isNamedCurvePoint("P-521", w66, w66));
    EXPECT_FALSE(isNamedCurvePoint("P-384", w32, w32)) << "a P-256 width under the P-384 name";
    EXPECT_FALSE(isNamedCurvePoint("P-384", w48, w32)) << "uneven halves";
    EXPECT_FALSE(isNamedCurvePoint("P-384", {}, {})) << "no point";
    EXPECT_FALSE(isNamedCurvePoint("P-192", std::vector<std::uint8_t>(24, 0x11), std::vector<std::uint8_t>(24, 0x11)));
    EXPECT_FALSE(isNamedCurvePoint("", w32, w32));
}

// The served point lies on the curve CKA_EC_PARAMS names for the key's size.
TEST(EcEncoding, APointIsTheKeysOnlyOnTheKeysCurve)
{
    const std::vector<std::uint8_t> w32(32, 0x11);
    const std::vector<std::uint8_t> w48(48, 0x11);
    EXPECT_TRUE(isPointOfKey(384, "P-384", w48, w48));
    EXPECT_TRUE(isPointOfKey(256, "P-256", w32, w32));
    EXPECT_FALSE(isPointOfKey(384, "P-256", w32, w32)) << "a well-formed point on another curve";
    EXPECT_FALSE(isPointOfKey(256, "P-384", w48, w48));
    EXPECT_FALSE(isPointOfKey(0, "P-384", w48, w48)) << "a key of no known size";
    EXPECT_FALSE(isPointOfKey(384, "P-384", w32, w32)) << "the width is checked too";
}

// pPublicData is the raw point or the same point in a DER OCTET STRING
// (pkcs11-tool --derive-pass-der); the length and the header decide which, on
// every curve, and only an uncompressed point is accepted either way.
TEST(EcEncoding, ThePeersPointIsRawOrDerOnEveryCurve)
{
    for (const auto& [bits, width] :
         std::vector<std::pair<std::uint32_t, std::size_t>>{{256, 32}, {384, 48}, {521, 66}}) {
        const std::vector<std::uint8_t> x(width, 0x11);
        const std::vector<std::uint8_t> y(width, 0x22);
        const auto der = ecPointOctetString(x, y);
        const std::vector<std::uint8_t> raw(der.end() - static_cast<std::ptrdiff_t>(1 + 2 * width), der.end());
        EXPECT_EQ(peerPointFromPublicData(raw, bits), raw) << bits;
        EXPECT_EQ(peerPointFromPublicData(der, bits), raw) << bits;
        auto compressed = raw;
        compressed[0] = 0x02;
        EXPECT_FALSE(peerPointFromPublicData(compressed, bits).has_value()) << bits;
        auto badHeader = der;
        badHeader[0] = 0x03;
        EXPECT_FALSE(peerPointFromPublicData(badHeader, bits).has_value()) << bits;
        EXPECT_FALSE(
            peerPointFromPublicData(std::span<const std::uint8_t>{raw.data(), raw.size() - 1}, bits).has_value());
    }
    EXPECT_FALSE(peerPointFromPublicData(std::vector<std::uint8_t>(65, 0x04), 0).has_value());
}

// Property: for random coordinates, wrapping then unwrapping gives the point back.
TEST(EcEncoding, WrappingAndUnwrappingAPointIsTheIdentity)
{
    std::mt19937 rng{2026};
    std::uniform_int_distribution<int> byte{0, 255};
    for (int i = 0; i < 1000; ++i) {
        for (const auto& [bits, width] :
             std::vector<std::pair<std::uint32_t, std::size_t>>{{256, 32}, {384, 48}, {521, 66}}) {
            std::vector<std::uint8_t> x(width);
            std::vector<std::uint8_t> y(width);
            for (auto& b : x)
                b = static_cast<std::uint8_t>(byte(rng));
            for (auto& b : y)
                b = static_cast<std::uint8_t>(byte(rng));
            const auto point = peerPointFromPublicData(ecPointOctetString(x, y), bits);
            ASSERT_TRUE(point.has_value());
            ASSERT_EQ(point->size(), 1 + 2 * width);
            EXPECT_TRUE(std::equal(x.begin(), x.end(), point->begin() + 1));
            EXPECT_TRUE(std::equal(y.begin(), y.end(), point->begin() + 1 + static_cast<std::ptrdiff_t>(width)));
        }
    }
}
