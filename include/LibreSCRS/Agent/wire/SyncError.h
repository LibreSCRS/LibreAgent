// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <string_view>

/// @file
/// @brief The named synchronous-method error vocabulary shared by both agent
///        wires, plus BOTH halves of its name conversion.

namespace LibreSCRS::Agent::Wire {

/// @brief Named synchronous-method errors — the spellings the socket wire
///        carries in `err-info`'s `name` field (`sync-error` in
///        wire/librescrs-agent.cddl) and the D-Bus wire carries as the tail of
///        `org.librescrs.Agent.Error.*`. Distinct from the numeric
///        `ErrorCode`, which is the ASYNCHRONOUS operation taxonomy.
///
/// The underlying integers are NOT wire-significant: the wire carries the
/// NAME, so this enum may be reordered without breaking a peer (unlike
/// `ErrorCode`, whose integers are frozen). What must stay in lockstep is the
/// SET of names — see `syncErrorName()`.
enum class SyncError : std::uint8_t {
    UnknownCard,
    KeyNotFound,
    NotAuthorized,
    UserNotLoggedIn,
    UnknownConfigKey,
    ReadOnlyConfig,
    InvalidConfigValue,
    UnsupportedProtocol,
    AuthFailed,
    CommunicationError,
    NotSupported,
    UnsupportedOnThisCard,
    UnsupportedSignatureParameter,
    InputTooLarge,
    RateLimited,
    UnknownCredential,
    InvalidRequest,
    /// GetSignResult has nothing to serve for the requested op: the op never
    /// reached a retained Sign result (wrong kind, never completed, or the
    /// recovery grace window already elapsed), OR the requester does not own
    /// it -- the two are deliberately indistinguishable on the wire (an
    /// IDOR-safe agent must answer a not-mine op exactly like an absent one,
    /// never a distinct "not yours" error that would let op ids be enumerated
    /// for ownership). Previously served ad hoc (a borrowed InvalidRequest/
    /// KeyNotFound stand-in, depending on which host); this is the dedicated
    /// name both hosts serve now.
    NoResult,
};

/// @brief The wire name for a `SyncError` (== the literal enumerated by the
///        CDDL `sync-error` group). Never empty.
///
/// Implemented as an exhaustive switch, so appending an enumerator above is a
/// `-Wswitch` build failure here until it is named — and a stale CDDL is a
/// separate test failure (tests/wire/WireContractGuardTest.cpp compares the
/// two as sets).
[[nodiscard]] std::string_view syncErrorName(SyncError e) noexcept;

/// @brief The inverse of `syncErrorName()`: a wire name back to its enumerator.
///
/// @warning This NEVER fails, and that is a deliberate degrade rather than a
///          convenience. `sync-error` is a TEXT-token closed enum: unlike the
///          numeric vocabularies on this wire there is no matching-width
///          concept that could bound an unrecognised token, so a token this
///          build does not know maps to `SyncError::CommunicationError` — the
///          same generic-protocol-error bucket an unrecognised D-Bus error
///          name already degrades to on the other transport, so both wires
///          converge on one outcome. The original token is NOT retained on
///          that path, so a caller cannot tell "the peer said
///          CommunicationError" from "the peer said something newer than this
///          build". A caller that must distinguish the two has to inspect the
///          token itself before calling this.
///
/// Round-trip: `decodeSyncError(syncErrorName(e)) == e` for every enumerator
/// (pinned by tests/wire/WireContractGuardTest.cpp). The reverse does not hold
/// for an unrecognised token, per the degrade above.
[[nodiscard]] SyncError decodeSyncError(std::string_view name) noexcept;

} // namespace LibreSCRS::Agent::Wire
