// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Re-export of the shared, std-only, wire-frozen agent error
///        taxonomy under the `LibreSCRS::AgentClient` namespace.
///
/// See `LibreSCRS::Agent::ErrorCode`'s own doc comment (wire/ErrorCode.h)
/// for the append-only freeze policy and the list of out-of-repo mirrors
/// that must stay in lockstep with it. This header adds no new declarations
/// of its own; it exists so Qt client code can spell the wire-stable type as
/// `LibreSCRS::AgentClient::ErrorCode` without reaching across into the
/// `LibreSCRS::Agent` namespace, and so this value type is discoverable
/// under the same `client/qt/include/LibreSCRS/AgentClient/` public-header
/// tree as every other `AgentClient` type.
///
/// @note Append-tolerant on the client's decode path: an `ErrorCode` numeric
///       value this build does not (yet) know — one a newer agent appended
///       past this build's last known code — decodes through verbatim
///       instead of being rejected. Client code that switches on `ErrorCode`
///       MUST therefore keep a `default:` arm for a forward-compatible
///       agent; treat an unrecognised value as opaque display/log data, not
///       as a decode failure.
#include <LibreSCRS/Agent/wire/ErrorCode.h>

namespace LibreSCRS::AgentClient {

/// @brief The agent's wire-frozen, append-only error taxonomy (see
///        `LibreSCRS::Agent::ErrorCode`), spelled under this library's own
///        namespace. Carried on a finished operation via
///        `AgentOperation::errorCode()`; contrast `CallError`, which covers
///        failures that never reached the agent at all.
using LibreSCRS::Agent::ErrorCode;

} // namespace LibreSCRS::AgentClient
