// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// Re-export of the shared, std-only, wire-stable Operation1 phase/status
// enums -- see LibreSCRS::Agent::Operations::OperationPhase's own doc
// comment (both enums are declared in the one upstream header and are
// always carried together on the operation-finished path, so both are
// re-exported here rather than splitting them across two client headers).
// Adds no new declarations; see ErrorCode.h in this same directory for why
// this repo re-exports rather than aliases-by-typedef-only.
#include <LibreSCRS/Agent/OperationPhase.h>

namespace LibreSCRS::AgentClient {

using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::Agent::Operations::OperationStatus;

} // namespace LibreSCRS::AgentClient
