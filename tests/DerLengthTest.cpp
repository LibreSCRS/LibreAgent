// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one rule the agent reads a DER length by: the PKCS#11 facade cutting a
// certificate's fields, and the CSCA import recognising a published list.
#include <LibreSCRS/Agent/util/DerLength.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace {

using LibreSCRS::Agent::readDerLength;

// The length at offset 1 of @p bytes (offset 0 stands in for the tag).
std::optional<std::pair<std::size_t, std::size_t>> lengthOf(const std::vector<std::uint8_t>& bytes)
{
    const auto r = readDerLength(bytes, 1);
    if (!r) {
        return std::nullopt;
    }
    return std::pair{r->length, r->lengthOctets};
}

// A tag, the given length octets, then @p contentBytes zero octets.
std::vector<std::uint8_t> tlv(std::vector<std::uint8_t> lengthOctets, std::size_t contentBytes)
{
    std::vector<std::uint8_t> out{0x30};
    out.insert(out.end(), lengthOctets.begin(), lengthOctets.end());
    out.resize(out.size() + contentBytes, 0x00);
    return out;
}

TEST(DerLength, TheShortFormIsOneOctetUpTo127)
{
    EXPECT_EQ(lengthOf(tlv({0x00}, 0)), (std::pair<std::size_t, std::size_t>{0, 1}));
    EXPECT_EQ(lengthOf(tlv({0x7F}, 0x7F)), (std::pair<std::size_t, std::size_t>{0x7F, 1}));
}

TEST(DerLength, TheLongFormCountsItsOwnOctets)
{
    EXPECT_EQ(lengthOf(tlv({0x81, 0x80}, 0x80)), (std::pair<std::size_t, std::size_t>{0x80, 2}));
    EXPECT_EQ(lengthOf(tlv({0x81, 0xFF}, 0xFF)), (std::pair<std::size_t, std::size_t>{0xFF, 2}));
    EXPECT_EQ(lengthOf(tlv({0x82, 0x01, 0x00}, 0x100)), (std::pair<std::size_t, std::size_t>{0x100, 3}));
    EXPECT_EQ(lengthOf(tlv({0x82, 0xFF, 0xFF}, 0xFFFF)), (std::pair<std::size_t, std::size_t>{0xFFFF, 3}));
    // Four octets is the most accepted, whatever the value.
    EXPECT_EQ(lengthOf(tlv({0x84, 0x00, 0x00, 0x00, 0x02}, 2)), (std::pair<std::size_t, std::size_t>{2, 5}));
}

TEST(DerLength, MoreThanFourLengthOctetsIsRefused)
{
    // Both used to be accepted by the facade's own decoder, which took up to
    // eight; the import took four. One rule now.
    EXPECT_EQ(lengthOf(tlv({0x85, 0x00, 0x00, 0x00, 0x00, 0x02}, 2)), std::nullopt);
    EXPECT_EQ(lengthOf(tlv({0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, 2)), std::nullopt);
}

TEST(DerLength, TheIndefiniteFormIsNotALength)
{
    EXPECT_EQ(lengthOf(tlv({0x80}, 4)), std::nullopt);
}

TEST(DerLength, ALengthPastTheDataIsRefused)
{
    EXPECT_EQ(lengthOf(tlv({0x05}, 4)), std::nullopt);
    EXPECT_EQ(lengthOf(tlv({0x82, 0x01, 0x00}, 0xFF)), std::nullopt);
    // A length that would wrap an offset when added to it.
    EXPECT_EQ(lengthOf(tlv({0x84, 0xFF, 0xFF, 0xFF, 0xFF}, 8)), std::nullopt);
}

TEST(DerLength, TruncatedLengthOctetsAreRefused)
{
    EXPECT_EQ(lengthOf({0x30}), std::nullopt);             // no length at all
    EXPECT_EQ(lengthOf({0x30, 0x82, 0x01}), std::nullopt); // one of two octets
    EXPECT_EQ(lengthOf({0x30, 0x81}), std::nullopt);       // none of one
}

TEST(DerLength, ExtraBytesAfterTheValueAreTheCallersToJudge)
{
    // The rule says the value fits; whether anything may follow it (a
    // certificate field does, a whole published list does not) is the
    // caller's question.
    EXPECT_EQ(lengthOf(tlv({0x02}, 5)), (std::pair<std::size_t, std::size_t>{2, 1}));
}

} // namespace
