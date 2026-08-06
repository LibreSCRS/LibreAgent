// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Re-export of the shared, std-only, named synchronous-method error
///        vocabulary under the `LibreSCRS::AgentClient` namespace.
///
/// See `LibreSCRS::Agent::Wire::SyncError`'s own doc comment (wire/SyncError.h)
/// for what the vocabulary is and how it relates to the CDDL group both wires
/// carry. This header adds no new declarations of its own; it exists so Qt
/// client code can spell the wire-stable type as
/// `LibreSCRS::AgentClient::SyncError` without reaching across into the
/// `LibreSCRS::Agent::Wire` namespace, and so this value type is discoverable
/// under the same `client/qt/include/LibreSCRS/AgentClient/` public-header tree
/// as every other `AgentClient` type. See ErrorCode.h in this same directory
/// for why this library re-exports rather than aliases-by-typedef-only.
///
/// @note Deliberately re-exports the TYPE only. The two conversion functions
///       declared in the upstream header (`syncErrorName()` /
///       `decodeSyncError()`) become visible here transitively, but they are
///       the wire library's symbols, not this library's — the wire library is a
///       PRIVATE link of this one, so a consumer that links only this library
///       must not call them. Consumers branch on the enumerator; nothing in
///       this library's own API needs the token spelling, and this library
///       never renders text for display in any case.
///
///       Being unsupported does not make them invisible, and the two facts
///       are tracked separately on purpose. This header declares them and the
///       shared library exports their definitions, so a consumer CAN bind to
///       them by accident — which is exactly why the ABI baseline records
///       them (`CLIENTQT_WIRE_PUBLIC` in ci/scripts/abi-snapshot.sh). That
///       recording makes a removal or signature change visible; it is not a
///       promise of support, and does not soften the warning above. The rest
///       of that namespace is NOT exported — the wire library compiles hidden,
///       and these two are annotated back in precisely because this header
///       declares them.
#include <LibreSCRS/Agent/wire/SyncError.h>

namespace LibreSCRS::AgentClient {

/// @brief The named synchronous-method error the agent (or, for the handful of
///        refusals this client decides locally in that same vocabulary, this
///        client) answered a method-entry call or a public-data fetch with —
///        see `LibreSCRS::Agent::Wire::SyncError`. Carried on a finished
///        operation via `AgentOperation::syncError()`.
///
/// This is the THIRD, orthogonal axis of a failed operation, and it exists
/// because the other two are lossy by design: `CallError` and `ErrorCode` are
/// small closed classifications that several distinct wire names collapse onto
/// (`InvalidRequest` and `UnknownCredential` both land on
/// `CallError::InvalidArguments`, for instance), and a consumer whose recovery
/// differs per name cannot reconstruct which one it was. `syncError()` carries
/// the name itself, as an enumerator, without changing what the other two
/// report.
using LibreSCRS::Agent::Wire::SyncError;

} // namespace LibreSCRS::AgentClient
