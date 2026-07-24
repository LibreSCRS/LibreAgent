// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Re-export of the shared, std-only, wire-stable Operation1
///        phase/status enums under the `LibreSCRS::AgentClient` namespace.
///
/// See `LibreSCRS::Agent::Operations::OperationPhase`'s own doc comment
/// (both enums are declared in the one upstream header and are always
/// carried together on the operation-finished path, so both are re-exported
/// here rather than splitting them across two client headers). Adds no new
/// declarations; see ErrorCode.h in this same directory for why this
/// library re-exports rather than aliases-by-typedef-only.
#include <LibreSCRS/Agent/OperationPhase.h>

namespace LibreSCRS::AgentClient {

/// @brief Progress phase of an in-flight operation (see
///        `LibreSCRS::Agent::Operations::OperationPhase`). Reported via
///        `AgentOperation::phase()` / `AgentOperation::phaseChanged()`.
using LibreSCRS::Agent::Operations::OperationPhase;
/// @brief Terminal outcome of an operation (see
///        `LibreSCRS::Agent::Operations::OperationStatus`). Reported via
///        `AgentOperation::status()`.
using LibreSCRS::Agent::Operations::OperationStatus;

} // namespace LibreSCRS::AgentClient
