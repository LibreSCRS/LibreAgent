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
    // A trailing generic "Reader" goes, the product name stays.
    EXPECT_EQ(ids[0].model, "Gemalto PC Twin");
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

// The reader holding a card, found by the card's key and labelled against the
// whole roster: the contact slot is told from its CL twin only because both
// are in it.
TEST(ReaderLabels, TheCardsReaderIsFoundByItsKeyAndLabelledAgainstTheRoster)
{
    const LibreSCRS::Agent::PresenceRoster roster{.readerNames = kDesk, .cardKeys = {"11", "12", "13"}};
    const auto contact = LibreSCRS::Agent::identityForCardIn(roster, "12");
    EXPECT_EQ(contact.iface, ReaderInterface::Contact);
    EXPECT_EQ(contact.full, kDesk[1]);
    EXPECT_EQ(LibreSCRS::Agent::identityForCardIn(roster, "13").iface, ReaderInterface::Contactless);
    EXPECT_EQ(LibreSCRS::Agent::identityForCardIn(roster, "11").full, kDesk[0]);
    EXPECT_EQ(LibreSCRS::Agent::identityForCardIn(roster, "99"), ReaderIdentity{}) << "a card that is gone";

    EXPECT_TRUE(LibreSCRS::Agent::isContactSlotOfDualInterfaceUnit(roster, "12"));
    EXPECT_FALSE(LibreSCRS::Agent::isContactSlotOfDualInterfaceUnit(roster, "13"));
    EXPECT_FALSE(LibreSCRS::Agent::isContactSlotOfDualInterfaceUnit(roster, "11"));
}

// An empty key names no reader. Without the guard it would match the first
// reader that holds no card, and every unresolvable prompt would borrow that
// reader's name.
TEST(ReaderLabels, AnEmptyCardKeyNamesNoReader)
{
    const LibreSCRS::Agent::PresenceRoster roster{.readerNames = kDesk, .cardKeys = {"", "12", ""}};
    EXPECT_EQ(LibreSCRS::Agent::identityForCardIn(roster, ""), ReaderIdentity{});
    EXPECT_FALSE(LibreSCRS::Agent::isContactSlotOfDualInterfaceUnit(roster, ""));
}

// A roster whose two lists disagree in length names no reader past the
// shorter one, rather than reading out of range.
TEST(ReaderLabels, AShortReaderListNamesNoReaderPastIt)
{
    const LibreSCRS::Agent::PresenceRoster roster{.readerNames = {kDesk[0]}, .cardKeys = {"11", "12"}};
    EXPECT_EQ(LibreSCRS::Agent::identityForCardIn(roster, "11").full, kDesk[0]);
    EXPECT_EQ(LibreSCRS::Agent::identityForCardIn(roster, "12"), ReaderIdentity{});
}

namespace {
struct Labelled
{
    std::string model;
    ReaderInterface iface;
};

std::vector<Labelled> labelsOf(const std::vector<std::string>& raw)
{
    std::vector<Labelled> out;
    for (const auto& id : readerIdentities(raw)) {
        out.push_back({id.model, id.iface});
    }
    return out;
}

void expectLabels(const std::vector<std::string>& raw, const std::vector<Labelled>& expected)
{
    const auto got = labelsOf(raw);
    ASSERT_EQ(got.size(), expected.size());
    for (std::size_t i = 0; i < got.size(); ++i) {
        EXPECT_EQ(got[i].model, expected[i].model) << raw[i];
        EXPECT_EQ(got[i].iface, expected[i].iface) << raw[i];
    }
}

constexpr auto kUnknown = ReaderInterface::Unknown;
constexpr auto kContact = ReaderInterface::Contact;
constexpr auto kContactless = ReaderInterface::Contactless;
} // namespace

// The reader-name cases the desktop clients labelled on their own before the
// agent published a label, one roster per row: what each showed is what the
// agent now publishes, model and interface apart.
TEST(ReaderLabels, ADualInterfaceUnitIsOneModelOnTwoInterfaces)
{
    expectLabels(
        {"HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00",
         "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00",
         "Gemalto PC Twin Reader (69988A87) 02 00"},
        {{"OMNIKEY 5422", kContact}, {"OMNIKEY 5422", kContactless}, {"Gemalto PC Twin", kUnknown}});
    // A shorter product string, and "CL" as a word of its own in the name.
    expectLabels({"HID OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (0000) 00 00",
                  "HID OMNIKEY 5422 CL Reader [OMNIKEY 5422CL Reader] (0000) 01 00"},
                 {{"OMNIKEY 5422", kContact}, {"OMNIKEY 5422", kContactless}});
}

TEST(ReaderLabels, AContactlessReaderIsContactlessOnItsOwn)
{
    expectLabels({"HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (SER) 00 00"},
                 {{"OMNIKEY 5422", kContactless}});
    expectLabels({"ACS ACR122U PICC Interface (00) 00 00"}, {{"ACS ACR122U", kContactless}});
    expectLabels({"Some NFC Reader 00 00"}, {{"Some NFC", kContactless}});
    expectLabels({"Generic Contactless Reader 00 00"}, {{"Generic", kContactless}});
}

TEST(ReaderLabels, ALoneContactReaderCarriesNoQualifier)
{
    expectLabels({"HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (SER) 01 00"},
                 {{"OMNIKEY 5422", kUnknown}});
    expectLabels({"Gemalto PC Twin Reader 00 00"}, {{"Gemalto PC Twin", kUnknown}});
    // macOS publishes the bare USB product string: no serial, no slot pair.
    // The bus is no more a model than the protocol is.
    expectLabels({"Gemalto USB SmartCard Reader"}, {{"Gemalto", kUnknown}});
    expectLabels({"SCM Microsystems Inc. SCR 3310 USB Smart Card Reader 00 00"},
                 {{"SCM Microsystems Inc. SCR 3310", kUnknown}});
    expectLabels({"Generic USB CCID Reader"}, {{"Generic", kUnknown}});
}

// Without a serial the two names cannot be shown to be one unit, and only a
// Contact slot is ever held powered: a contact slot is not guessed from a
// matching model.
TEST(ReaderLabels, AModelMatchWithoutASharedSerialIsNoContactSlot)
{
    expectLabels({"HID Global OMNIKEY 5422 Smartcard Reader", "HID Global OMNIKEY 5422CL Smartcard Reader"},
                 {{"HID Global OMNIKEY 5422", kUnknown}, {"HID Global OMNIKEY 5422", kContactless}});
}

TEST(ReaderLabels, TwoReadersOfOneModelAreToldApartByTheirSerials)
{
    expectLabels({"Gemalto PC Twin Reader (AAAA1111) 00 00", "Gemalto PC Twin Reader (BBBB2222) 01 00"},
                 {{"Gemalto PC Twin (1111)", kUnknown}, {"Gemalto PC Twin (2222)", kUnknown}});
    expectLabels({"ACME Card Reader (1234) 00 00", "ACME Card Reader (5678) 00 00"},
                 {{"ACME Card (1234)", kUnknown}, {"ACME Card (5678)", kUnknown}});
    // Two units of a dual-interface model: each slot has a twin of its kind.
    expectLabels({"HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (SERIALAAAA) 01 00",
                  "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (SERIALAAAA) 00 00",
                  "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (SERIALBBBB) 03 00",
                  "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (SERIALBBBB) 02 00"},
                 {{"OMNIKEY 5422 (AAAA)", kContact},
                  {"OMNIKEY 5422 (AAAA)", kContactless},
                  {"OMNIKEY 5422 (BBBB)", kContact},
                  {"OMNIKEY 5422 (BBBB)", kContactless}});
}

// Two names reporting one serial: the serial suffix collides for the second,
// and its position would reproduce the label the first one took -- the
// suffix is re-checked until it is unique.
TEST(ReaderLabels, ADisambiguatingSuffixIsItselfKeptUnique)
{
    const auto labels = labelsOf({"Alpha (2) 00 00", "Alpha (2) 01 00"});
    ASSERT_EQ(labels.size(), 2u);
    EXPECT_NE(labels[0].model, labels[1].model);
    EXPECT_EQ(labels[0].model, "Alpha (2)");
    EXPECT_EQ(labels[1].model, "Alpha (3)");
    // Without any serial the suffix is the reader's position.
    expectLabels({"Plain Box 00 00", "Plain Box 01 00"}, {{"Plain Box (1)", kUnknown}, {"Plain Box (2)", kUnknown}});
}

TEST(ReaderLabels, ANameThatShortensToNothingStaysWhole)
{
    expectLabels({"Reader"}, {{"Reader", kUnknown}});
    expectLabels({"USB"}, {{"USB", kUnknown}});
    EXPECT_TRUE(readerIdentities({}).empty());
}

// pcsc-lite prints the slot pair as "%02X %02X": a reader past the tenth
// carries a hex digit, and its serial and model are still found.
TEST(ReaderLabels, AHexSlotPairIsStillTheSlotPair)
{
    const auto ids = readerIdentities({"Gemalto PC Twin Reader (69988A87) 0A 00"});
    ASSERT_EQ(ids.size(), 1u);
    EXPECT_EQ(ids[0].model, "Gemalto PC Twin");
}

// Every model above, checked for the M-1 contract: interface wording lives in
// the structured field only.
TEST(ReaderLabels, NoModelInTheTableCarriesInterfaceWording)
{
    const std::vector<std::string> names{
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (SER) 00 00",
        "ACS ACR122U PICC Interface (00) 00 00", "Generic Contactless Reader 00 00",
        "HID OMNIKEY 5422 CL Reader [OMNIKEY 5422CL Reader] (0000) 01 00"};
    for (const auto& id : readerIdentities(names)) {
        EXPECT_FALSE(id.model.ends_with("CL")) << id.model;
        EXPECT_EQ(id.model.find("PICC"), std::string::npos) << id.model;
        EXPECT_EQ(id.model.find("ontactless"), std::string::npos) << id.model;
    }
}
