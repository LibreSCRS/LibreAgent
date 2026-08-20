// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <chrono>
#include <cstdint>

namespace LibreSCRS::Agent::Operations {

/// The secret a prompt collects. Drives the entry deadline only; the wire
/// kind strings live in PrompterWire.h and are unaffected.
///
/// @since 4.3
enum class PromptKind : std::uint8_t { Pin, Can, Mrz, ChangePin };

/// How long the holder gets to type, measured from the moment the prompter
/// shows the window. Absolute, not idle-based: an idle timer has no upper
/// bound on how long one dialog holds its card's slot, and a countdown that
/// keeps resetting cannot be displayed honestly.
///
/// MRZ is the outlier because it is two lines of 44 characters, usually
/// transcribed by hand from the document.
///
/// @since 4.3
[[nodiscard]] constexpr std::chrono::milliseconds deadlineFor(PromptKind kind) noexcept
{
    using namespace std::chrono_literals;
    switch (kind) {
    case PromptKind::Pin:
        return 60'000ms;
    case PromptKind::Can:
        return 120'000ms;
    case PromptKind::Mrz:
        return 300'000ms;
    case PromptKind::ChangePin:
        return 180'000ms;
    }
    return 60'000ms;
}

/// The longest deadline any kind can ask for. A transport that carries a
/// prompt must outlive this, or its own call timeout would fire first and
/// leave a window standing with no consumer -- the defect this design exists
/// to remove. Phase 2 pins that with a static assertion on the consumer side.
///
/// @since 4.3
inline constexpr std::chrono::milliseconds kLongestDeadline{300'000};

/// How many times a CAN or MRZ may be collected and rejected before the
/// operation gives up.
///
/// This applies to PACE secrets ONLY. A PIN is counted by the CARD, and a
/// software cap that disagreed with the card's counter would be worse than no
/// cap: it would tell the holder "too many attempts" while the card still had
/// tries left, or the reverse. The placement enforces this by construction --
/// the cap lives in CredentialCache::requestCredential, through which a PIN
/// never passes.
///
/// @since 4.3
inline constexpr std::uint32_t kMaxPaceAttempts = 3;

} // namespace LibreSCRS::Agent::Operations
