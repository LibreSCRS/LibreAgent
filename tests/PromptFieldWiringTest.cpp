// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Every prompt must carry an id and a deadline by the time it reaches the
// prompter. These drive the real gate decorator, not a copy of its logic.

#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/operations/PromptPolicy.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/CancelToken.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

using LibreSCRS::Agent::PinChangePromptResult;
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::ReaderIdentity;
using LibreSCRS::Agent::ReaderInterface;
using LibreSCRS::Agent::Operations::deadlineFor;
using LibreSCRS::Agent::Operations::PrompterClientBase;
using LibreSCRS::Agent::Operations::PromptKind;
using LibreSCRS::Agent::Operations::PromptSerializer;
using LibreSCRS::Agent::Operations::SerializingPrompter;

namespace {

// Records the options each prompt actually arrived with -- the only way to
// assert what the prompter was ASKED, rather than what a flow intended.
class CapturingPrompter final : public PrompterClientBase
{
public:
    std::vector<PromptOptions> seen;

    [[nodiscard]] PromptResult requestPin(const PromptOptions& o) override
    {
        return record(o);
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions& o) override
    {
        return record(o);
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions& o) override
    {
        return record(o);
    }
    [[nodiscard]] PinChangePromptResult requestPinChange(const PromptOptions& o) override
    {
        seen.push_back(o);
        PinChangePromptResult r;
        r.status = PromptStatus::Cancelled;
        return r;
    }

private:
    PromptResult record(const PromptOptions& o)
    {
        seen.push_back(o);
        // Cancelled rather than Ok: these tests assert on what was asked, and
        // nothing here should look like a collected secret.
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
};

} // namespace

TEST(PromptFieldWiring, APromptReachesThePrompterCarryingAnIdAndADeadline)
{
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    static_cast<void>(gated.requestCan(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 1u);
    EXPECT_FALSE(inner.seen[0].promptId.empty()) << "a dialog no cancel can name";
    EXPECT_EQ(inner.seen[0].deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Can).count()));
}

TEST(PromptFieldWiring, EachKindCarriesItsOwnKindsDeadline)
{
    // The kind comes from the method the request arrived on, so no call site can
    // pass the wrong one.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    static_cast<void>(gated.requestPin(PromptOptions{}));
    static_cast<void>(gated.requestCan(PromptOptions{}));
    static_cast<void>(gated.requestMrz(PromptOptions{}));
    static_cast<void>(gated.requestPinChange(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 4u);
    EXPECT_EQ(inner.seen[0].deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Pin).count()));
    EXPECT_EQ(inner.seen[1].deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Can).count()));
    EXPECT_EQ(inner.seen[2].deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::Mrz).count()));
    EXPECT_EQ(inner.seen[3].deadlineMs, static_cast<std::uint32_t>(deadlineFor(PromptKind::ChangePin).count()));
}

TEST(PromptFieldWiring, TheChangePinPromptIsStampedToo)
{
    // The change modal takes a different route through the gate, so a stamp
    // added only to the shared path would leave it anonymous.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    static_cast<void>(gated.requestPinChange(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 1u);
    EXPECT_FALSE(inner.seen[0].promptId.empty());
}

TEST(PromptFieldWiring, EveryRaisedPromptGetsItsOwnIdRatherThanReusingTheOperationsFirst)
{
    // A re-prompt after a wrong CAN must be separately addressable, or a cancel
    // meant for the second dialog would close the first.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    static_cast<void>(gated.requestCan(PromptOptions{}));
    static_cast<void>(gated.requestCan(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 2u);
    EXPECT_NE(inner.seen[0].promptId, inner.seen[1].promptId);
}

TEST(PromptFieldWiring, TwoCardsNeverShareAPromptId)
{
    // One agent-lifetime minter, so ids are unique across cards -- and two
    // dialogs at once is the whole point of the per-card gate.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter cardA{serializer, inner, src.token(), "card-A"};
    SerializingPrompter cardB{serializer, inner, src.token(), "card-B"};

    static_cast<void>(cardA.requestCan(PromptOptions{}));
    static_cast<void>(cardB.requestPin(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 2u);
    EXPECT_NE(inner.seen[0].promptId, inner.seen[1].promptId);
}

TEST(PromptFieldWiring, StampingLeavesTheFieldsTheFlowAlreadySetAlone)
{
    // A stamp that reset the struct would strip the trusted artifact token off
    // the consent dialog -- what tells the holder what they are authorizing.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    PromptOptions opts;
    opts.requester = "org.librescrs.LibreCelik";
    opts.artifact = "signature";
    opts.minLength = 6;
    static_cast<void>(gated.requestPin(opts));

    ASSERT_EQ(inner.seen.size(), 1u);
    EXPECT_EQ(inner.seen[0].requester, "org.librescrs.LibreCelik");
    EXPECT_EQ(inner.seen[0].artifact, "signature");
    EXPECT_EQ(inner.seen[0].minLength, 6u);
}

TEST(PromptFieldWiring, TheCallersOwnOptionsObjectIsNotMutated)
{
    // The stamp works on a copy. A flow that reuses one options object across a
    // retry must not carry the previous attempt's id into the next dialog.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    PromptOptions opts;
    static_cast<void>(gated.requestCan(opts));

    EXPECT_TRUE(opts.promptId.empty());
    EXPECT_EQ(opts.deadlineMs, 0u);
}

TEST(PromptFieldWiring, APromptCarriesTheIdentityOfTheReaderHoldingItsCard)
{
    // Two dialogs can stand at once, so each has to say which reader is asking.
    // The gate is keyed by exactly the card key the lookup needs, which is why
    // the resolver hangs here and no flow or prompt site changed.
    PromptSerializer serializer;
    serializer.setReaderIdentityResolver([](const std::string& cardKey) {
        if (cardKey == "card-A") {
            return ReaderIdentity{"OMNIKEY 5422", ReaderInterface::Contactless,
                                  "HID Global OMNIKEY 5422 Smartcard Reader "
                                  "[OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00"};
        }
        return ReaderIdentity{};
    });

    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    static_cast<void>(gated.requestCan(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 1u);
    EXPECT_EQ(inner.seen[0].reader.model, "OMNIKEY 5422");
    EXPECT_EQ(inner.seen[0].reader.iface, ReaderInterface::Contactless);
    EXPECT_FALSE(inner.seen[0].reader.full.empty());
}

TEST(PromptFieldWiring, TwoCardsGetTheIdentitiesOfTheirOwnReaders)
{
    // The failure this prevents: a dual-interface unit surfaces two slots that
    // share a serial, so a prompt resolved against the wrong key produces two
    // identical dialogs -- the exact ambiguity the qualifier exists to remove.
    PromptSerializer serializer;
    serializer.setReaderIdentityResolver([](const std::string& cardKey) {
        return cardKey == "card-A" ? ReaderIdentity{"OMNIKEY 5422", ReaderInterface::Contact, "raw contact"}
                                   : ReaderIdentity{"OMNIKEY 5422", ReaderInterface::Contactless, "raw contactless"};
    });

    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter cardA{serializer, inner, src.token(), "card-A"};
    SerializingPrompter cardB{serializer, inner, src.token(), "card-B"};

    static_cast<void>(cardA.requestPin(PromptOptions{}));
    static_cast<void>(cardB.requestCan(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 2u);
    EXPECT_EQ(inner.seen[0].reader.iface, ReaderInterface::Contact);
    EXPECT_EQ(inner.seen[1].reader.iface, ReaderInterface::Contactless);
    EXPECT_NE(inner.seen[0].reader.full, inner.seen[1].reader.full);
}

TEST(PromptFieldWiring, WithNoResolverThePromptIsUnnamedRatherThanWrong)
{
    // A backend that has not wired the seam still gets a usable prompt. An
    // unnamed dialog is honest; a stale or borrowed name is the failure.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    static_cast<void>(gated.requestPin(PromptOptions{}));

    ASSERT_EQ(inner.seen.size(), 1u);
    EXPECT_EQ(inner.seen[0].reader, ReaderIdentity{});
}

TEST(PromptFieldWiring, AQueuedWorkerCancelledBeforeItsTurnNeverBurnsAnId)
{
    // Minting inside the gate is what keeps an id from being spent on a dialog
    // nobody ever saw.
    PromptSerializer serializer;
    CapturingPrompter inner;
    LibreSCRS::CancelSource src;
    src.requestCancel();
    SerializingPrompter gated{serializer, inner, src.token(), "card-A"};

    const auto result = gated.requestCan(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Cancelled);
    EXPECT_TRUE(inner.seen.empty()) << "a cancelled-while-queued worker raised a dialog";
}
