// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/operations/PromptIdMinter.h>
#include <LibreSCRS/Agent/operations/PromptPolicy.h>
#include <LibreSCRS/Agent/value/ReaderLabels.h>

#include <algorithm>
#include <cstdint>
#include <string_view>

namespace LibreSCRS::Agent::Operations {

/// What every prompt site needs in order to say which reader is asking and how
/// long the holder has.
///
/// Held by reference in each flow's deps struct, the same way
/// `PrompterClientBase& prompter` already is. The reader identity is captured
/// when the operation is published, from the roster live at that moment; a
/// reader plugged in mid-operation therefore does not re-qualify a label on an
/// operation already running, which is deliberate — re-deriving under a running
/// prompt would change the words in front of the holder mid-entry.
///
/// @since 4.3
struct PromptContext
{
    LibreSCRS::Agent::ReaderIdentity reader;
    PromptIdMinter& minter;
};

/// The entry budget the neutral wire kind @p kind is worth, in milliseconds, or
/// 0 for a name no policy covers.
///
/// The alt_kinds vocabulary is OPEN at the wire — a member this build has no
/// name for is ignored rather than defaulted, so a form nobody can render also
/// grants nobody any time.
///
/// @since 4.3
[[nodiscard]] constexpr std::uint32_t deadlineForWireKind(std::string_view kind) noexcept
{
    const auto ms = [](PromptKind k) { return static_cast<std::uint32_t>(deadlineFor(k).count()); };
    if (kind == LibreSCRS::PrompterWire::kKindPin) {
        return ms(PromptKind::Pin);
    }
    if (kind == LibreSCRS::PrompterWire::kKindCan) {
        return ms(PromptKind::Can);
    }
    if (kind == LibreSCRS::PrompterWire::kKindMrz) {
        return ms(PromptKind::Mrz);
    }
    if (kind == LibreSCRS::PrompterWire::kKindChangePin) {
        return ms(PromptKind::ChangePin);
    }
    return 0;
}

/// Stamp @p opts with a freshly minted id, @p ctx's reader identity, and the
/// deadline for @p kind — plus the budget of any alternative kind @p opts
/// already offers. ADDITIVE: every field the caller already set is left
/// untouched.
///
/// This is the ONLY writer of those three members. PromptOptions is built at
/// six sites (FlowPrelude, SignFlow, RawCryptoFlow, BatchSignFlow,
/// KeyActivationFlow, PinChangeFlow); a site that filled them by hand and got
/// one wrong would ship a dialog that names no reader and never expires, and
/// nothing would say so.
///
/// A fresh id per call, not per operation: a re-prompt after a wrong CAN must
/// be separately addressable, or a cancel meant for the second dialog would
/// close the first.
///
/// @since 4.3
inline void stampPrompt(LibreSCRS::Agent::PromptOptions& opts, const PromptContext& ctx, PromptKind kind)
{
    opts.promptId = ctx.minter.mint();
    opts.reader = ctx.reader;
    opts.deadlineMs = static_cast<std::uint32_t>(deadlineFor(kind).count());
    // What the switch this prompt offers is worth, so the dialog can re-base
    // its clock on taking it instead of leaving the holder the budget sized for
    // the form they just left. The LARGEST of the offered kinds: a switch may
    // lengthen the window, never shorten it. Both budgets run from the moment
    // the window is shown, so a switched window lives the longer of the two --
    // never their sum, which is what keeps it inside kLongestDeadline.
    std::uint32_t alternative = 0;
    for (const std::string& offered : opts.altKinds) {
        alternative = std::max(alternative, deadlineForWireKind(offered));
    }
    opts.altDeadlineMs = alternative;
}

} // namespace LibreSCRS::Agent::Operations
