// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

namespace LibreSCRS::Agent::Operations {

// Wire-stable Phase values; match org.librescrs.Agent.Operation1.xml. Append-only.
enum class OperationPhase : std::uint32_t {
    Created = 0,
    Connecting = 1,
    AwaitingConsent = 2,
    Authenticating = 3,
    Reading = 4,
    Signing = 5,
    Timestamping = 6,
    Done = 7,
};

enum class OperationStatus : std::uint32_t {
    Ok = 0,
    Cancelled = 1,
    Error = 2,
};

} // namespace LibreSCRS::Agent::Operations
