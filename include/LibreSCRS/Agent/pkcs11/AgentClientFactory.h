// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one seam between the Cryptoki core and the transport underneath it.
//
// The core CALLS this; it never defines it. Exactly one translation unit in the
// host that builds a module defines it, and that TU is not part of any exported
// library — a second definition arriving from a shipped archive would either
// refuse to link or, worse, be the one that wins and look for the agent in the
// wrong place. Keeping it link-time also keeps it out of any global registry,
// which is the singleton the module would otherwise need.

#pragma once

#include <LibreSCRS/Agent/pkcs11/AgentClient.h>

#include <memory>

namespace LibreSCRS::Pkcs11Agent {

/// @brief Produce the one AgentClient this module talks over.
/// @return Never null. A client whose transport is unreachable still answers;
///         connected() reports it and every call returns Status::DeviceRemoved.
[[nodiscard]] std::unique_ptr<AgentClient> makeAgentClient();

} // namespace LibreSCRS::Pkcs11Agent
