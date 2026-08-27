// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/operations/PromptContext.h>
#include <gtest/gtest.h>

using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::ReaderIdentity;
using LibreSCRS::Agent::ReaderInterface;
using LibreSCRS::Agent::Operations::deadlineFor;
using LibreSCRS::Agent::Operations::kLongestDeadline;
using LibreSCRS::Agent::Operations::PromptContext;
using LibreSCRS::Agent::Operations::PromptIdMinter;
using LibreSCRS::Agent::Operations::PromptKind;
using LibreSCRS::Agent::Operations::stampPrompt;

TEST(PromptStamp, TheNewFieldsAreInertUntilSomethingStampsThem)
{
    // The fields land before anything stamps them, and the hosts marshal them
    // later still. Until then a default-constructed options object must behave
    // exactly as before, or every existing prompt silently changes shape.
    const PromptOptions opts;
    EXPECT_TRUE(opts.promptId.empty());
    EXPECT_TRUE(opts.reader.model.empty());
    EXPECT_TRUE(opts.reader.full.empty());
    EXPECT_EQ(opts.reader.iface, ReaderInterface::Unknown);
    EXPECT_EQ(opts.deadlineMs, 0u);
}

TEST(PromptStamp, ADeadlineOfZeroMeansNoDeadlineWasSet)
{
    // A prompter reading 0 must not start a zero-length timer and close the
    // window instantly. Zero is the "unset" sentinel, checked by the hosts.
    PromptOptions opts;
    EXPECT_EQ(opts.deadlineMs, 0u);
    opts.deadlineMs = 120'000;
    EXPECT_NE(opts.deadlineMs, 0u);
}

TEST(PromptStamp, StampingFillsIdentityReaderAndDeadlineTogether)
{
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"OMNIKEY 5422", ReaderInterface::Contactless, "raw name"}, minter};

    PromptOptions opts;
    stampPrompt(opts, ctx, PromptKind::Can);

    EXPECT_EQ(opts.promptId, "nonce:1");
    EXPECT_EQ(opts.reader.model, "OMNIKEY 5422");
    EXPECT_EQ(opts.reader.iface, ReaderInterface::Contactless);
    EXPECT_EQ(opts.reader.full, "raw name");
    EXPECT_EQ(opts.deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Can).count()));
}

TEST(PromptStamp, EveryStampMintsAFreshIdSoARePromptIsSeparatelyAddressable)
{
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"m", ReaderInterface::Unknown, "f"}, minter};

    PromptOptions first;
    PromptOptions second;
    stampPrompt(first, ctx, PromptKind::Can);
    stampPrompt(second, ctx, PromptKind::Can);

    EXPECT_NE(first.promptId, second.promptId);
}

TEST(PromptStamp, EachKindGetsItsOwnDeadline)
{
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"m", ReaderInterface::Unknown, "f"}, minter};

    PromptOptions pin;
    PromptOptions mrz;
    stampPrompt(pin, ctx, PromptKind::Pin);
    stampPrompt(mrz, ctx, PromptKind::Mrz);

    EXPECT_EQ(pin.deadlineMs, 60'000u);
    EXPECT_EQ(mrz.deadlineMs, 300'000u);
}

TEST(PromptStamp, StampingLeavesEveryPreExistingFieldAlone)
{
    // The stamper must be additive: a flow sets requester/artifact/description
    // BEFORE stamping, and a stamper that reset the struct would silently strip
    // the trusted artifact token off the consent dialog.
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"m", ReaderInterface::Unknown, "f"}, minter};

    PromptOptions opts;
    opts.requester = "org.librescrs.LibreCelik";
    opts.artifact = "signature";
    opts.minLength = 6;
    stampPrompt(opts, ctx, PromptKind::Pin);

    EXPECT_EQ(opts.requester, "org.librescrs.LibreCelik");
    EXPECT_EQ(opts.artifact, "signature");
    EXPECT_EQ(opts.minLength, 6u);
}

// A CAN is six digits printed on the card, which is what 120 s buys. The moment
// the same window ALSO offers the MRZ form it may end up collecting two lines
// of 44 characters transcribed by hand — the 300 s the MRZ kind gets when it is
// what was asked for. So the alternative's budget has to travel with the offer:
// without it the dialog re-frames the form and says nothing to the clock, and
// whoever switches at 0:40 has 40 s to copy a document number, a birth date and
// an expiry date.
TEST(PromptStamp, AnOfferedAlternativeCarriesItsOwnDeadline)
{
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"m", ReaderInterface::Unknown, "f"}, minter};

    PromptOptions offered;
    offered.altKinds = {LibreSCRS::PrompterWire::kKindMrz};
    stampPrompt(offered, ctx, PromptKind::Can);

    EXPECT_EQ(offered.deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Can).count()))
        << "the requested kind still gets its own budget";
    EXPECT_EQ(offered.altDeadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Mrz).count()))
        << "the offer has to say what the alternative form is worth";
}

// The overwhelming majority of prompts offer nothing, and their dictionary must
// stay byte-identical: an absent key is what makes the rollout additive in both
// directions.
TEST(PromptStamp, APromptThatOffersNoAlternativeCarriesNoAlternativeDeadline)
{
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"m", ReaderInterface::Unknown, "f"}, minter};

    PromptOptions plain;
    stampPrompt(plain, ctx, PromptKind::Can);
    EXPECT_EQ(plain.altDeadlineMs, 0u);

    // An alternative nobody has a budget for is not an alternative: an unknown
    // member is ignored here exactly as the prompter ignores it when rendering.
    PromptOptions unknown;
    unknown.altKinds = {"semaphore"};
    stampPrompt(unknown, ctx, PromptKind::Can);
    EXPECT_EQ(unknown.altDeadlineMs, 0u);
}

// The transport carrying a prompt is pinned to outlive kLongestDeadline, so a
// switch that pushed the window past it would leave a dialog standing with no
// consumer left to answer — the defect the deadline exists to remove. Both
// budgets are measured from the moment the window is SHOWN, so the longest a
// switched window can live is the larger of the two, never their sum.
TEST(PromptStamp, NeitherBudgetOnAnOfferedSwitchOutlivesTheLongestDeadline)
{
    PromptIdMinter minter{"nonce"};
    const PromptContext ctx{ReaderIdentity{"m", ReaderInterface::Unknown, "f"}, minter};

    PromptOptions offered;
    offered.altKinds = {LibreSCRS::PrompterWire::kKindMrz};
    stampPrompt(offered, ctx, PromptKind::Can);

    EXPECT_LE(offered.deadlineMs, static_cast<std::uint32_t>(kLongestDeadline.count()));
    EXPECT_LE(offered.altDeadlineMs, static_cast<std::uint32_t>(kLongestDeadline.count()));
}
