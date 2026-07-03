// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <cstdint>
namespace LibreSCRS::Agent {
// Non-secret, session-free facts about an inserted card.
struct CardInfo
{
    std::uint32_t capabilities = 0; // LibreSCRS::Plugin::CardCapabilities bitfield value

    // Pre-read unlock the card demands before any data-group read, as reported
    // by the matched plugin's profile-derived preReadAuth(session). Resolved
    // during the same transient capability-resolution session that yields the
    // capabilities above, so a client can pre-warn "this will ask for your CAN"
    // before issuing ReadIdentity. Defaults to None when no plugin matches or
    // the card needs no pre-read unlock.
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::None;
};
} // namespace LibreSCRS::Agent
