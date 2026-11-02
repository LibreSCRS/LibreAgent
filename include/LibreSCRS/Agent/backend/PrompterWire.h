// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The prompter vocabulary every agent host and every prompter shares: the
// secret-KIND strings, the reply STATUS words, and the largest secret a
// prompter may hand back.
//
// "pin"/"can"/"mrz" ARE the CredentialEntry field identifiers the LM Auth
// surface matches against AuthRequirement keys (see
// LibreSCRS::Auth::CredentialResult::find) — the prompter kind and the
// credential key are the same vocabulary by design, so CredentialCache and
// SignFlow key their entries off this table. The multi-secret change_pin kind
// is request vocabulary only (a PIN is never a cache/credential key).
//
// The status words and the secret bound are here, and not in each host,
// because both hosts spoke the same words and enforced the same bound from
// copies of their own, with nothing tying the copies together. What stays with
// a host is its transport: the D-Bus option-dict keys, the socket's CBOR map
// keys, and how a status word travels.
//
// Header-only, dependency-free (no Qt, no backend transport, no LM), so a
// prompter that links none of the card stack can include it.

#pragma once

#include <LibreSCRS/Agent/operations/PromptPolicy.h> // PromptKind

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace LibreSCRS::PrompterWire {

// Secret kind the credential plumbing requests; ALSO the CredentialEntry field
// identifier the LM Auth surface matches.
inline constexpr const char* kKindPin = "pin";
inline constexpr const char* kKindCan = "can";
inline constexpr const char* kKindMrz = "mrz";

// Two-secret PIN-change prompt kind (current + new PIN in one modal). Request
// vocabulary ONLY — never a CredentialEntry/cache key: a PIN pair is prompted
// per use and never cached.
inline constexpr const char* kKindChangePin = "change_pin";

/// The wire kind of @p kind.
///
/// @since 5.0
[[nodiscard]] constexpr std::string_view kindToken(LibreSCRS::Agent::Operations::PromptKind kind) noexcept
{
    using LibreSCRS::Agent::Operations::PromptKind;
    switch (kind) {
    case PromptKind::Pin:
        return kKindPin;
    case PromptKind::Can:
        return kKindCan;
    case PromptKind::Mrz:
        return kKindMrz;
    case PromptKind::ChangePin:
        return kKindChangePin;
    }
    return kKindPin;
}

/// The kind a wire kind names, or nullopt for a word this build does not know.
/// The kind vocabulary is OPEN at the wire (an alt_kinds member may be newer
/// than this build), so an unknown word is not an error here; the caller
/// decides.
///
/// @since 5.0
[[nodiscard]] constexpr std::optional<LibreSCRS::Agent::Operations::PromptKind>
kindFromToken(std::string_view token) noexcept
{
    using LibreSCRS::Agent::Operations::PromptKind;
    for (const auto kind : {PromptKind::Pin, PromptKind::Can, PromptKind::Mrz, PromptKind::ChangePin}) {
        if (token == kindToken(kind)) {
            return kind;
        }
    }
    return std::nullopt;
}

/// The largest secret an agent accepts back from a prompter. Far above any
/// real PIN, CAN or MRZ, and small enough that a hostile prompter cannot make
/// the agent allocate without bound. Every host's reader enforces it.
///
/// @since 5.0
inline constexpr std::size_t kMaxSecretBytes = 8 * 1024;

/// What a prompter answers a secret request with. A CLOSED vocabulary: a word
/// this build does not know is read as `Error`, never as success.
///
/// APPEND new values, never insert: the integers are compiled into every
/// consumer of this header.
///
/// @since 5.0
enum class PromptReplyStatus : std::uint8_t {
    /// The holder entered the secret and confirmed it.
    Ok,
    /// The holder dismissed the window.
    Cancelled,
    /// The prompter failed.
    Error,
    /// The prompter refused the caller: it is not the agent. The agent never
    /// legitimately receives this; it is part of the vocabulary because the
    /// prompter sends it.
    Unauthorized,
    /// The window closed itself because the holder's entry time ran out.
    /// Distinct from Cancelled deliberately: telling someone they cancelled
    /// what the clock took from them is the confusion this word removes.
    Timeout,
    /// `Ok`, but the holder switched a CAN request to the MRZ form the request
    /// offered, so the secret is an MRZ. Meaningful only to a caller that made
    /// that offer; any other caller must treat it as an error.
    OkMrz,
};

/// The wire word of @p status.
///
/// @since 5.0
[[nodiscard]] constexpr std::string_view replyStatusToken(PromptReplyStatus status) noexcept
{
    switch (status) {
    case PromptReplyStatus::Ok:
        return "ok";
    case PromptReplyStatus::Cancelled:
        return "cancelled";
    case PromptReplyStatus::Error:
        return "error";
    case PromptReplyStatus::Unauthorized:
        return "unauthorized";
    case PromptReplyStatus::Timeout:
        return "timeout";
    case PromptReplyStatus::OkMrz:
        return "ok_mrz";
    }
    return "error";
}

/// The status a wire word names, or nullopt for a word this build does not
/// know -- which a host reads as `Error`.
///
/// @since 5.0
[[nodiscard]] constexpr std::optional<PromptReplyStatus> replyStatusFromToken(std::string_view token) noexcept
{
    for (const auto status : {PromptReplyStatus::Ok, PromptReplyStatus::Cancelled, PromptReplyStatus::Error,
                              PromptReplyStatus::Unauthorized, PromptReplyStatus::Timeout, PromptReplyStatus::OkMrz}) {
        if (token == replyStatusToken(status)) {
            return status;
        }
    }
    return std::nullopt;
}

} // namespace LibreSCRS::PrompterWire
