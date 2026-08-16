// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Secure/String.h>

#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Programmable recording double over the frozen Prompter (PrompterClientBase)
// interface. Each request* returns the pre-seeded result for its kind and
// records that it was asked; cancel() bumps a counter. Tests seed pinResult /
// canResult / mrzResult / pinChangeResult, then assert on the recorded call
// sequence.
struct FakePrompter final : PrompterClientBase
{
    PromptResult pinResult{PromptStatus::Error, std::nullopt, "unseeded"};
    PromptResult canResult{PromptStatus::Error, std::nullopt, "unseeded"};
    PromptResult mrzResult{PromptStatus::Error, std::nullopt, "unseeded"};
    PinChangePromptResult pinChangeResult{PromptStatus::Error, std::nullopt, std::nullopt, "unseeded"};

    enum class Kind { Pin, Can, Mrz, PinChange };
    std::vector<Kind> calls;
    int cancels{0};
    // Options as received by the change-PIN modal; tests assert the display
    // metadata (card/pin labels, action title, per-role bounds) reached the
    // prompter seam.
    PromptOptions lastChangePromptOptions;
    // Options as received by the CAN prompt; tests assert the alternative
    // kinds a caller advertised (altKinds) reached the prompter seam.
    PromptOptions lastCanPromptOptions;

    // Script the reply a prompter gives when the user took the in-dialog
    // switch to MRZ on a CAN request: an Ok carrying the MRZ payload and the
    // kind actually collected.
    void answerCanWithMrz(LibreSCRS::Secure::String payload)
    {
        canResult = PromptResult{PromptStatus::Ok, std::move(payload), "", LibreSCRS::Auth::PaceSecretKind::Mrz};
    }

    [[nodiscard]] PromptResult requestPin(const PromptOptions&) override
    {
        calls.push_back(Kind::Pin);
        return pinResult;
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions& options) override
    {
        calls.push_back(Kind::Can);
        lastCanPromptOptions = options;
        return canResult;
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions&) override
    {
        calls.push_back(Kind::Mrz);
        return mrzResult;
    }
    [[nodiscard]] PinChangePromptResult requestPinChange(const PromptOptions& options) override
    {
        calls.push_back(Kind::PinChange);
        lastChangePromptOptions = options;
        return pinChangeResult;
    }
    void cancel() noexcept override
    {
        ++cancels;
    }
};

} // namespace LibreSCRS::Agent::Operations
