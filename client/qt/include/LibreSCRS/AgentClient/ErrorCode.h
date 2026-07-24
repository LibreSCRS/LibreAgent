// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// Re-export of the shared, std-only, wire-frozen error taxonomy -- see
// LibreSCRS::Agent::ErrorCode's own doc comment for the append-only freeze
// policy and the list of out-of-repo mirrors that must stay in lockstep with
// it. This header adds no new declarations of its own; it exists so Qt
// client code can spell the wire-stable type as LibreSCRS::AgentClient::ErrorCode
// without reaching across into the LibreSCRS::Agent namespace, and so this
// value type is discoverable under the same client/qt/include/LibreSCRS/AgentClient/
// public-header tree as every other AgentClient type.
#include <LibreSCRS/Agent/wire/ErrorCode.h>

namespace LibreSCRS::AgentClient {

using LibreSCRS::Agent::ErrorCode;

} // namespace LibreSCRS::AgentClient
