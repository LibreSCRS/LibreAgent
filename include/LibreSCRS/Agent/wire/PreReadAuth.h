// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>

/// @file
/// @brief Std-only mirror of the card's pre-read unlock requirement.

namespace LibreSCRS::Agent::Wire {

/// @brief Std-only mirror of the authoritative `LibreSCRS::Auth::PreReadAuthMethod`
///        enum (declared alongside `AuthRequirement` in the middleware's
///        auth headers). Messages.h needs the pre-read-unlock-method
///        vocabulary on the wire without pulling in LM's auth/plugin/
///        smartcard headers just for a 3-value enum — this header has no
///        include beyond `<cstdint>`, so it stays reachable from a
///        `LIBREAGENT_BUILD_CORE=OFF, LIBREAGENT_BUILD_WIRE=ON` configuration.
///
/// This mirror is NOT self-certifying: `src/wire/WireParityChecks.cpp`
/// (core-gated, so it sees both this header and the LM original) statically
/// asserts every enumerator's underlying value stays in lockstep with LM's.
/// An append, rename, or renumber on the LM side fails THIS repo's build
/// until the mirror is updated to match — never edit one side without the
/// other.
///
/// Each value names the *credential* the host must collect, not the
/// protocol run against the card — a plugin may use either BAC or PACE to
/// consume an MRZ-derived secret, and which protocol is actually selected
/// is plugin business, not something this enum encodes.
enum class PreReadAuth : std::uint8_t {
    None = 0, ///< No pre-read authentication required.
    Mrz = 1,  ///< MRZ-derived secret (ICAO 9303 Basic Access Control or PACE).
    Can = 2,  ///< Card Access Number (PACE).
};

} // namespace LibreSCRS::Agent::Wire
