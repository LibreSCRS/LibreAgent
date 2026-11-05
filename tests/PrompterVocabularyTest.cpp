// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The prompter vocabulary every host and every prompter shares. The
// expectations are literals: a prompter built from another tree speaks these
// exact words, so the test must not derive them from the code under test.
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include "operations/PromptContext.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string_view>
#include <utility>

namespace {

using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::promptStatusFor;
using LibreSCRS::Agent::Operations::PromptKind;
using LibreSCRS::PrompterWire::PromptReplyStatus;
using namespace std::string_view_literals;

namespace PW = LibreSCRS::PrompterWire;

TEST(PrompterVocabulary, ASecretIsBoundedAtEightKibibytes)
{
    EXPECT_EQ(PW::kMaxSecretBytes, 8U * 1024U);
}

TEST(PrompterVocabulary, EveryReplyStatusHasItsWordAndBack)
{
    constexpr std::array table{
        std::pair{PromptReplyStatus::Ok, "ok"sv},
        std::pair{PromptReplyStatus::Cancelled, "cancelled"sv},
        std::pair{PromptReplyStatus::Error, "error"sv},
        std::pair{PromptReplyStatus::Unauthorized, "unauthorized"sv},
        std::pair{PromptReplyStatus::Timeout, "timeout"sv},
        std::pair{PromptReplyStatus::OkMrz, "ok_mrz"sv},
    };
    ASSERT_EQ(table.size(), static_cast<std::size_t>(PromptReplyStatus::OkMrz) + 1) << "a status is missing";
    for (std::size_t i = 0; i < table.size(); ++i) {
        const auto [status, word] = table[i];
        EXPECT_EQ(static_cast<std::size_t>(status), i) << "row " << i << " is out of order";
        EXPECT_EQ(PW::replyStatusToken(status), word);
        EXPECT_EQ(PW::replyStatusFromToken(word), status) << word;
    }
}

TEST(PrompterVocabulary, AWordNobodyDefinedIsNoStatus)
{
    EXPECT_EQ(PW::replyStatusFromToken("OK"), std::nullopt);
    EXPECT_EQ(PW::replyStatusFromToken(""), std::nullopt);
    EXPECT_EQ(PW::replyStatusFromToken("ok_can"), std::nullopt);
}

TEST(PrompterVocabulary, EveryKindHasItsWordAndBack)
{
    constexpr std::array table{
        std::pair{PromptKind::Pin, "pin"sv},
        std::pair{PromptKind::Can, "can"sv},
        std::pair{PromptKind::Mrz, "mrz"sv},
        std::pair{PromptKind::ChangePin, "change_pin"sv},
    };
    ASSERT_EQ(table.size(), static_cast<std::size_t>(PromptKind::ChangePin) + 1) << "a kind is missing";
    for (const auto& [kind, word] : table) {
        EXPECT_EQ(PW::kindToken(kind), word);
        EXPECT_EQ(PW::kindFromToken(word), kind) << word;
    }
    EXPECT_EQ(PW::kindFromToken("passport"), std::nullopt);
    // An unknown alternative kind grants no time, rather than some default.
    EXPECT_EQ(LibreSCRS::Agent::Operations::deadlineForWireKind("passport"), 0U);
    EXPECT_EQ(LibreSCRS::Agent::Operations::deadlineForWireKind("mrz"), 300'000U);
}

TEST(PrompterVocabulary, EveryReplyMeansOneOutcome)
{
    struct Row
    {
        PromptReplyStatus reply;
        bool mrzOffered;
        PromptStatus want;
    };
    constexpr std::array table{
        Row{PromptReplyStatus::Ok, false, PromptStatus::Ok},
        Row{PromptReplyStatus::Ok, true, PromptStatus::Ok},
        Row{PromptReplyStatus::Cancelled, false, PromptStatus::Cancelled},
        Row{PromptReplyStatus::Error, false, PromptStatus::Error},
        // The prompter refusing the agent is a misconfiguration, not success.
        Row{PromptReplyStatus::Unauthorized, false, PromptStatus::Error},
        // The clock, not the holder.
        Row{PromptReplyStatus::Timeout, false, PromptStatus::Timeout},
        Row{PromptReplyStatus::OkMrz, true, PromptStatus::Ok},
        // Nobody offered the MRZ form, so there is no slot for an MRZ.
        Row{PromptReplyStatus::OkMrz, false, PromptStatus::Error},
    };
    for (const auto& row : table) {
        EXPECT_EQ(promptStatusFor(row.reply, row.mrzOffered), row.want)
            << PW::replyStatusToken(row.reply) << " offered=" << row.mrzOffered;
    }
}

} // namespace
