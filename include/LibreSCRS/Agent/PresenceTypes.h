// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Auth/AuthRequirement.h> // PreReadAuthMethod
#include <cstdint>
#include <string>

namespace LibreSCRS::Agent {

// One published reader (Reader1: Name / HasCard / Card).
struct ReaderState
{
    ObjectId id;
    std::string name;
    bool hasCard{false};
    ObjectId card; // default/invalid == no card
};

// One published card insertion (Card1: Capabilities / Reader / PreReadAuthMethod).
// Carries the neutral LM enum, NOT the wire string — the AgentTransport backend stringifies it.
struct CardState
{
    ObjectId id;
    ObjectId reader;
    std::uint32_t capabilities{0};
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth{LibreSCRS::Auth::PreReadAuthMethod::None};
};

// The only in-place property mutation the agent emits: a reader's card-presence
// flipping on insert/remove. Replaces ObjectRegistry::update(path,iface,PropertyMap).
struct PropertyDelta
{
    bool hasCard{false};
    ObjectId card; // default/invalid when hasCard == false
};

} // namespace LibreSCRS::Agent
