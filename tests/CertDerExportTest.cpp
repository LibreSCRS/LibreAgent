// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CertDerExport.h>
#include <LibreSCRS/Agent/util/Sha256Hex.h> // sha256Hex
#include <gtest/gtest.h>
#include <vector>

using namespace LibreSCRS::Agent;

TEST(CertDerExport, MatchesByCertIdSha256)
{
    std::vector<std::uint8_t> derA{0xde, 0xad, 0xbe, 0xef};
    std::vector<std::uint8_t> derB{0x01, 0x02, 0x03};
    std::vector<std::vector<std::uint8_t>> certs{derA, derB};
    const std::string idB = sha256Hex(derB);

    auto found = Operations::matchCertDer(certs, idB);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, derB);

    EXPECT_FALSE(Operations::matchCertDer(certs, "0000").has_value());
    EXPECT_FALSE(Operations::matchCertDer({}, idB).has_value());
}
