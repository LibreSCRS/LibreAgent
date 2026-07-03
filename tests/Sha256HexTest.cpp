// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/util/Sha256Hex.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;

TEST(Sha256Hex, EmptyInputYieldsSha256OfEmptyInput)
{
    // SHA-256("") — well-known constant. The helper is total so call sites do
    // not need bespoke error handling for zero-byte input.
    const std::vector<std::uint8_t> empty;
    EXPECT_EQ(sha256Hex(empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256Hex, DistinctInputsYieldDistinctDigests)
{
    const std::vector<std::uint8_t> a{0x3B, 0x9F, 0x96, 0x80};
    const std::vector<std::uint8_t> b{0x3B, 0xDB, 0x96, 0x00};
    EXPECT_NE(sha256Hex(a), sha256Hex(b));
}

TEST(Sha256Hex, SameInputYieldsSameDigestAcrossCalls)
{
    const std::vector<std::uint8_t> data{0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31, 0xA0, 0x73, 0xBE};
    const std::string first = sha256Hex(data);
    const std::string second = sha256Hex(data);
    EXPECT_EQ(first, second);
    // SHA-256 hex is 64 lowercase chars.
    EXPECT_EQ(first.size(), 64u);
    for (char c : first) {
        const bool isHexChar = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        EXPECT_TRUE(isHexChar) << "non-lowercase-hex char in digest: " << c;
    }
}
