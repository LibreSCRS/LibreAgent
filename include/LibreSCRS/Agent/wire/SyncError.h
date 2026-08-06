// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <string_view>

/// @file
/// @brief The named synchronous-method error vocabulary shared by both agent
///        wires, plus BOTH halves of its name conversion.

// Keeps a function exported from a shared library this archive is folded into.
// The library compiles hidden; the two below are the exception, because a
// public client header re-exports their declarations and the definitions must
// stay reachable. ci/scripts/check-wire-exports.sh proves both halves.
//
// Defined here, not in an export header: this is one of the leaf headers the
// client's public surface re-exports, and client/qt/CMakeLists.txt fails the
// configure if one of them includes another first-party header.
//
// Plain `//`, not `///`: a DOCUMENTED #define is published as public API even
// when Doxyfile.publicapi predefines it away.
#define LIBRESCRS_AGENTWIRE_EXPORT __attribute__((visibility("default")))

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
/// Each enumerator below notes, after its meaning, which coarse bucket the Qt
/// client's classification collapses it onto — the whole reason this axis is
/// carried separately is that several distinct names share one bucket, so the
/// bucket alone cannot tell a caller which refusal it actually got.
enum class SyncError : std::uint8_t {
    /// The card id the request named is not one the agent exports right now —
    /// it was never known, or the card has left the reader since the id was
    /// handed out. (Bucket: unsupported card.)
    UnknownCard,
    /// The card is known, but it carries no key or certificate under the id
    /// the request named. (Bucket: key not found.)
    KeyNotFound,
    /// The caller is not permitted to make this request at all. (Bucket:
    /// access denied — shared with `UserNotLoggedIn`.)
    NotAuthorized,
    /// The request needs an authenticated session on the token and none is
    /// open. Distinct from `NotAuthorized`: this one is recoverable by
    /// authenticating, that one is not. (Bucket: access denied.)
    UserNotLoggedIn,
    /// The configuration key the request named is not one this agent knows.
    /// (Bucket: invalid arguments — shared with the two below,
    /// `InvalidRequest`, `UnknownCredential` and
    /// `UnsupportedSignatureParameter`.)
    UnknownConfigKey,
    /// The configuration key exists but cannot be written at run time.
    /// (Bucket: invalid arguments.)
    ReadOnlyConfig,
    /// The configuration key exists and is writable, but the supplied value is
    /// outside what it accepts. (Bucket: invalid arguments.)
    InvalidConfigValue,
    /// The peer asked to speak a protocol version this agent does not.
    /// (Bucket: protocol error — the only name in it.)
    UnsupportedProtocol,
    /// Authentication against the card itself failed — a wrong or refused
    /// credential, not a malformed request. (Bucket: authentication failed.)
    AuthFailed,
    /// The exchange broke in a way the peer could only describe generically.
    ///
    /// @warning This value is ALSO where an unrecognised name lands, because
    ///          the vocabulary has no room to carry one forward — see
    ///          `decodeSyncError()`'s own warning. Reading it as a positive
    ///          identification of this specific failure is therefore unsound.
    ///          (Bucket: communication error.)
    CommunicationError,
    /// The request names something this agent build does not implement at all,
    /// for any card. (Bucket: capability missing — shared with
    /// `UnsupportedOnThisCard`.)
    NotSupported,
    /// The request is implemented, but not for the card it was aimed at. The
    /// distinction from `NotSupported` is agent-build versus this-card, and it
    /// is exactly the one the shared bucket loses. (Bucket: capability
    /// missing.)
    UnsupportedOnThisCard,
    /// A signature parameter the request carried is not one the agent accepts
    /// (an unsupported format/level/packaging combination). (Bucket: invalid
    /// arguments.)
    UnsupportedSignatureParameter,
    /// The request's payload is larger than the agent accepts. (Bucket:
    /// invalid document.)
    InputTooLarge,
    /// Refused because this caller is issuing the request too often; the same
    /// request may succeed later. (Bucket: rate limited.)
    RateLimited,
    /// The credential id the request named is not in the most recent listing
    /// for that card — typically a stale id, so the fix is to re-list and
    /// retry rather than to change the request's shape. (Bucket: invalid
    /// arguments.)
    UnknownCredential,
    /// The request is malformed or self-inconsistent as sent. (Bucket: invalid
    /// arguments.)
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
[[nodiscard]] LIBRESCRS_AGENTWIRE_EXPORT std::string_view syncErrorName(SyncError e) noexcept;

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
[[nodiscard]] LIBRESCRS_AGENTWIRE_EXPORT SyncError decodeSyncError(std::string_view name) noexcept;

} // namespace LibreSCRS::Agent::Wire
