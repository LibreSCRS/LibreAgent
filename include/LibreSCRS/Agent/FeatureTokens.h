// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <array>
#include <string_view>

/// @file
/// @brief Single source of truth for the agent's optional feature-token
///        vocabulary — served verbatim on both wires (D-Bus `Manager1.Features`,
///        socket `HelloAck.features`) and consumed by the Qt client
///        (`AgentClient::features()` / `hasFeature()`).
///
/// Std-only by design (no LM, no Qt, no sdbus-c++): reachable from a
/// `LIBREAGENT_BUILD_CORE=OFF, LIBREAGENT_BUILD_WIRE=ON` configuration and from
/// the LibreDarwin socket daemon (a Core consumer, via FetchContent) alike, the
/// same dependency-light rule `wire/PreReadAuth.h` and `wire/OperationPhase.h`
/// follow. It sits directly under `include/LibreSCRS/Agent/` (not `wire/`)
/// because it is not itself a wire-shape mirror — it is the CATALOG both wires
/// and the client read from — but it ships in the same physical `include/`
/// tree Core/Wire/ClientQt already share, so no extra install-rule plumbing is
/// needed for it to reach any of them (see cmake/InstallExport.cmake).

namespace LibreSCRS::Agent {

/// @brief The feature tokens THIS build actually serves — i.e. the token's
///        serving surface exists in this repo (or, for a token another repo
///        serves, that repo re-points at this header instead of a local
///        literal). ONLY a token whose surface exists may appear here: a task
///        that lands a new surface moves its token from the `kPlannedFeatures`
///        list below into this array, in the SAME commit that lands the
///        surface — never advertise a capability before it exists.
///
/// Append-only, order not wire-significant (both wires carry it as an
/// unordered set; a client checks membership via `hasFeature()`, never
/// position). Kept in lockstep with the CDDL comment documenting the same
/// vocabulary (`wire/librescrs-agent.cddl`, near `hello-ack`) by a guard test
/// (`tests/wire/FeatureTokensGuardTest.cpp`) — update both together.
inline constexpr std::array<std::string_view, 9> kAgentFeatures{
    "credentials", "card-type",      "token-info",      "trust-status", "tsa-url",
    "visual-sign", "layout-preview", "identity-stream", "batch-sign",
};

// kPlannedFeatures — reserved tokens with NO serving surface yet, so they are
// deliberately NOT compiled into kAgentFeatures above (pre-advertising a
// capability before its surface exists would let a client believe a request
// family works when the agent would still refuse it). Each entry moves into
// kAgentFeatures in the same commit that lands its serving surface.
//
// Empty today — every token this catalog has ever named has a serving
// surface. When a future increment reserves a new token ahead of its
// surface, it is declared here the SAME way (a same-sized
// std::array<std::string_view, N> literal), moved into kAgentFeatures once
// the surface lands.

} // namespace LibreSCRS::Agent
