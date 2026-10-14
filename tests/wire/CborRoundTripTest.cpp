// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Byte-stable canonical CBOR round-trips + fail-closed rejection of
// non-canonical / malformed input (the untrusted-parser contract).
#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Agent/wire/Cbor.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using LibreSCRS::Agent::Wire::CborError;
using LibreSCRS::Agent::Wire::CborValue;
using LibreSCRS::Agent::Wire::decode;

namespace {

// encode -> decode -> value-equal AND encode(decoded) byte-equal to encode(v).
void expectStableRoundTrip(const CborValue& v)
{
    const std::vector<std::uint8_t> bytes = v.encode();
    const auto decoded = decode(bytes);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, v);
    EXPECT_EQ(decoded->encode(), bytes); // byte-stable
}

TEST(CborRoundTrip, Scalars)
{
    expectStableRoundTrip(CborValue(nullptr));
    expectStableRoundTrip(CborValue(true));
    expectStableRoundTrip(CborValue(false));
    expectStableRoundTrip(CborValue::uint(0));
    expectStableRoundTrip(CborValue::uint(23));
    expectStableRoundTrip(CborValue::uint(1000000));
    expectStableRoundTrip(CborValue(static_cast<std::int64_t>(-17)));
    expectStableRoundTrip(CborValue(std::string("Hello")));
    expectStableRoundTrip(CborValue(std::string{}));
    expectStableRoundTrip(CborValue(CborValue::Bytes{0xDE, 0xAD, 0xBE, 0xEF}));
    expectStableRoundTrip(CborValue(1.5));
}

TEST(CborRoundTrip, NestedMapAndArray)
{
    CborValue::Map inner;
    inner.emplace("given_name", CborValue(std::string("Ana")));
    inner.emplace("age", CborValue::uint(42));

    CborValue::Array certs;
    certs.push_back(CborValue(std::string("certA")));
    certs.push_back(CborValue(std::string("certB")));

    CborValue::Map root;
    root.emplace("t", CborValue(std::string("ReadIdentity")));
    root.emplace("req", CborValue::uint(7));
    root.emplace("fields", CborValue(std::move(inner)));
    root.emplace("certs", CborValue(std::move(certs)));

    expectStableRoundTrip(CborValue(std::move(root)));
}

TEST(CborRoundTrip, MapKeyOrderIsCanonicalRegardlessOfInsertionOrder)
{
    CborValue::Map a;
    a.emplace("bb", CborValue::uint(2));
    a.emplace("a", CborValue::uint(1));
    a.emplace("ccc", CborValue::uint(3));

    CborValue::Map b;
    b.emplace("ccc", CborValue::uint(3));
    b.emplace("a", CborValue::uint(1));
    b.emplace("bb", CborValue::uint(2));

    // Same entries -> identical canonical bytes (shorter keys first, then bytewise).
    EXPECT_EQ(CborValue(std::move(a)).encode(), CborValue(std::move(b)).encode());
}

TEST(CborRoundTrip, RejectsNonShortestInteger)
{
    // 0 encoded as a 1-byte-follows uint (0x18 0x00) instead of 0x00.
    const std::vector<std::uint8_t> nonShortest{0x18, 0x00};
    const auto r = decode(nonShortest);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsIndefiniteLengthArray)
{
    // 0x9f ... 0xff = indefinite-length array [1].
    const std::vector<std::uint8_t> indefinite{0x9f, 0x01, 0xff};
    const auto r = decode(indefinite);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsUnsortedMapKeys)
{
    // map(2){ "b":1, "a":2 } — keys out of canonical order.
    const std::vector<std::uint8_t> unsorted{0xa2, 0x61, 'b', 0x01, 0x61, 'a', 0x02};
    const auto r = decode(unsorted);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsDuplicateMapKeys)
{
    // map(2){ "a":1, "a":2 }.
    const std::vector<std::uint8_t> dup{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02};
    const auto r = decode(dup);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsTrailingBytes)
{
    std::vector<std::uint8_t> bytes = CborValue::uint(1).encode(); // {0x01}
    bytes.push_back(0x02);                                         // trailing
    const auto r = decode(bytes);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::TrailingBytes);
}

TEST(CborRoundTrip, EncodesFloatInShortestPreferredForm)
{
    // RFC 8949 §4.2 preferred float: 1.5 MUST encode as CBOR float16
    // (0xf9 0x3e 0x00), not float32/64. Locks QCBOR v1.6.1 preferred
    // serialization (a regression / QCBOR bump that stops shortening would break
    // the "§4.2 canonical" guarantee for the only wire float, op-progress).
    const std::vector<std::uint8_t> half{0xf9, 0x3e, 0x00};
    EXPECT_EQ(CborValue(1.5).encode(), half);
}

TEST(CborRoundTrip, RejectsNonShortestFloat)
{
    // 1.5 as float64 (0xfb 3ff8000000000000) is non-canonical -> rejected by the
    // re-encode-and-compare guard (our canonical form is the shortest float16).
    const std::vector<std::uint8_t> asDouble{0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const auto r = decode(asDouble);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, FloatsThatDoNotShortenRoundTripInTheirOwnWidth)
{
    // Each input is the canonical encoding of its value, so decode() must accept
    // it and the re-encode must reproduce it byte for byte. QCBOR's preferred-
    // float reduction shifts by an out-of-range amount for each of the first
    // seven (0.1 alone gives -93): undefined behaviour, which a
    // -fsanitize=undefined build of this test reports. The last four sit in
    // the subnormal ranges, where the reduction really runs and must still
    // pick the shortest form.
    const std::vector<std::vector<std::uint8_t>> canonical{
        {0xfa, 0x02, 0x03, 0x20, 0x05},                         // float32, far below the half range
        {0xfa, 0x47, 0xc3, 0x50, 0x00},                         // 100000.0f, above the half range
        {0xfa, 0x3f, 0x8c, 0xcc, 0xcd},                         // 1.1f, half exponent but too many bits
        {0xfa, 0x7f, 0x7f, 0xff, 0xff},                         // largest float32
        {0xfb, 0x3f, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a}, // 0.1
        {0xfb, 0x09, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 2^-867, far below the float32 range
        {0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c}, // 1e300
        {0xf9, 0x00, 0x01},                                     // 2^-24, smallest half subnormal
        {0xfa, 0x33, 0xc0, 0x00, 0x00},                         // 1.5 * 2^-24, no half subnormal
        {0xfa, 0x00, 0x00, 0x00, 0x01},                         // 2^-149, smallest float32 subnormal
        {0xfb, 0x36, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 1.5 * 2^-149, no float32 subnormal
    };
    for (std::size_t i = 0; i < canonical.size(); ++i) {
        SCOPED_TRACE(i);
        const auto decoded = decode(canonical[i]);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->encode(), canonical[i]);
    }
    EXPECT_EQ(CborValue(0.1).encode(), canonical[4]);
    EXPECT_EQ(CborValue(100000.0).encode(), canonical[1]);
}

// The other end of each window the reduction runs in: exponent -15 is the
// highest half subnormal candidate, -127 the highest float32 one. A value there
// that shortens must still shorten, and one that does not must keep its width.
TEST(CborRoundTrip, FloatsAtTheTopOfEachSubnormalWindowKeepTheirShortestForm)
{
    const std::vector<std::vector<std::uint8_t>> canonical{
        {0xf9, 0x02, 0x00},                                     // 2^-15, a half subnormal
        {0xfa, 0x38, 0x00, 0x00, 0x01},                         // (1 + 2^-23) * 2^-15, no half subnormal
        {0xfa, 0x00, 0x40, 0x00, 0x00},                         // 2^-127, a float32 subnormal
        {0xfb, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // (1 + 2^-52) * 2^-127, no float32 subnormal
    };
    for (std::size_t i = 0; i < canonical.size(); ++i) {
        SCOPED_TRACE(i);
        const auto decoded = decode(canonical[i]);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->encode(), canonical[i]);
    }
    EXPECT_EQ(CborValue(0x1p-15).encode(), canonical[0]);
    EXPECT_EQ(CborValue(0x1p-127).encode(), canonical[2]);
}

TEST(CborRoundTrip, MalformedInputNeverCrashes)
{
    // A spread of malformed byte strings must each return an error, never crash.
    const std::vector<std::vector<std::uint8_t>> corpus{
        {}, {0xff}, {0xa1}, {0x9f}, {0x1b, 0x00}, {0x62, 'a'}, {0x82, 0x01}, {0xa2, 0x61, 'a', 0x01}};
    for (const auto& bytes : corpus) {
        const auto r = decode(bytes);
        EXPECT_FALSE(r.has_value());
    }
}

// The one zeroization routine the agent, the facade and both transports share:
// every byte of the span is zero afterwards, and nothing past it is touched.
TEST(CborRoundTrip, SecureZeroClearsExactlyTheSpan)
{
    std::vector<std::uint8_t> buf{0x11, 0x22, 0x33, 0x44, 0x55};
    LibreSCRS::Agent::secureZero(std::span<std::uint8_t>{buf.data() + 1, 3});
    EXPECT_EQ(buf, (std::vector<std::uint8_t>{0x11, 0x00, 0x00, 0x00, 0x55}));
}

} // namespace
