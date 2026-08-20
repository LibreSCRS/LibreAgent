// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/ReaderLabels.h>
#include <gtest/gtest.h>

using LibreSCRS::Agent::readerIdentities;
using LibreSCRS::Agent::ReaderIdentity;
using LibreSCRS::Agent::ReaderInterface;

namespace {
// The owner's actual desk, 2026-08-19. The OMNIKEY pair shares serial
// IM0O2C00NF10456904 and differs only by the bracketed product string and
// the slot number -- the exact trap the spec's requirement 3 exists to stop.
const std::vector<std::string> kDesk{
    "Gemalto PC Twin Reader (69988A87) 02 00",
    "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00",
    "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00",
};
} // namespace

TEST(ReaderLabels, StripsPcscBoilerplateAndKeepsTheModel)
{
    const auto ids = readerIdentities(kDesk);
    ASSERT_EQ(ids.size(), 3u);
    EXPECT_EQ(ids[0].model, "Gemalto PC Twin Reader");
    EXPECT_EQ(ids[1].model, "OMNIKEY 5422");
    EXPECT_EQ(ids[2].model, "OMNIKEY 5422");
}

TEST(ReaderLabels, TheDualInterfacePairIsDistinguishedByInterfaceNotByModel)
{
    const auto ids = readerIdentities(kDesk);
    ASSERT_EQ(ids.size(), 3u);
    // Same model string on both slots -- so the DISTINCTION must live in the
    // structured field, which is the whole point of returning structure.
    EXPECT_EQ(ids[1].model, ids[2].model);
    EXPECT_EQ(ids[1].iface, ReaderInterface::Contact);
    EXPECT_EQ(ids[2].iface, ReaderInterface::Contactless);
    // And the pair must not be equal as a whole.
    EXPECT_NE(ids[1], ids[2]);
}

TEST(ReaderLabels, ASingleInterfaceReaderIsNotGivenAQualifierItDoesNotNeed)
{
    const auto ids = readerIdentities(kDesk);
    EXPECT_EQ(ids[0].iface, ReaderInterface::Unknown);
}

TEST(ReaderLabels, TheRawNameSurvivesVerbatim)
{
    const auto ids = readerIdentities(kDesk);
    for (std::size_t i = 0; i < kDesk.size(); ++i) {
        EXPECT_EQ(ids[i].full, kDesk[i]);
    }
}

TEST(ReaderLabels, ComposesNoHumanSentence)
{
    // The M-1 contract: no output field may contain interface wording. If a
    // future edit re-introduces a composed suffix, this fails.
    const auto ids = readerIdentities(kDesk);
    for (const auto& id : ids) {
        EXPECT_EQ(id.model.find("contactless"), std::string::npos);
        EXPECT_EQ(id.model.find("contact"), std::string::npos);
        EXPECT_EQ(id.model.find("\xE2\x80\x94"), std::string::npos); // em dash
    }
}

TEST(ReaderLabels, AnUnparseableNameFallsBackToItselfRatherThanToEmpty)
{
    const auto ids = readerIdentities({"weird-reader"});
    ASSERT_EQ(ids.size(), 1u);
    EXPECT_EQ(ids[0].model, "weird-reader");
    EXPECT_EQ(ids[0].full, "weird-reader");
}

TEST(ReaderLabels, IdenticalRawNamesStayIndexAlignedAndDoNotCollapse)
{
    const auto ids = readerIdentities({kDesk[0], kDesk[0]});
    ASSERT_EQ(ids.size(), 2u);
    EXPECT_EQ(ids[0], ids[1]);
    // kDesk[0] is a single-interface reader duplicated in the roster, not a
    // dual-interface unit's two slots. Counting raw OCCURRENCES per serial
    // (instead of distinct raw names) would make this duplicate look like a
    // second slot and hand both entries a Contact qualifier they must not
    // carry -- and the EXPECT_EQ above cannot catch that, since it only
    // checks the two entries against each other and is trivially true for a
    // pure function fed identical input either way.
    EXPECT_EQ(ids[0].iface, ReaderInterface::Unknown);
    EXPECT_EQ(ids[1].iface, ReaderInterface::Unknown);
}
