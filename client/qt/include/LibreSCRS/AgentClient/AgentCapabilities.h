// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Agent/wire/PreReadAuth.h>

#include <QString>
#include <QStringList>
#include <QStringView>

#include <cstdint>
#include <optional>

/// @file
/// @brief Plain-constant mirror of the agent's card-capability bitfield plus
///        the UI-state grouping helper and the public token vocabulary.
///
/// The bit values are a deliberate, hand-checked copy of the agent's wire
/// contract (`capability-bit` in wire/librescrs-agent.cddl, itself anchored to
/// LibreMiddleware's `CardCapabilities`) — the agent builds the card
/// capability field straight from that enum, so the wire values match on both
/// transports. Mirroring them here as a pure `uint32_t` keeps this client
/// library middleware-free: a thin agent client links no card core.

namespace LibreSCRS::AgentClient {

/// @brief Pre-read unlock the card demands. Re-export of the std-only wire
///        mirror (parity-asserted against the middleware original) rather than
///        a third hand copy — see LibreSCRS/Agent/wire/PreReadAuth.h.
using LibreSCRS::Agent::Wire::PreReadAuth;

/// @brief Capability bits as carried on the agent's card `Capabilities` field.
///
/// @note Values mirror the wire contract exactly — do not renumber.
namespace Cap {
inline constexpr std::uint32_t None = 0;                ///< No capability bits set.
inline constexpr std::uint32_t Pki = 1U << 0;           ///< readCertificates + verifyPIN + sign + discoverKeys.
inline constexpr std::uint32_t IdentityData = 1U << 1;  ///< readCard returns identity/document fields.
inline constexpr std::uint32_t EmrtdCrypto = 1U << 2;   ///< eMRTD-family crypto (BAC/PACE/PA/AA/CA).
inline constexpr std::uint32_t PinManagement = 1U << 3; ///< verifyPIN/changePIN/unblockPIN.
} // namespace Cap

/// @brief Coarse UI states a surface renders from a card's capability set.
///
/// The 2×2 IdentityData×PKI grouping: a card that reads
/// identity data AND signs is `Hybrid`; identity-only and PKI-only collapse to
/// their single surface; ancillary-only / empty capability sets have no
/// user-visible surface and map to `None`.
enum class UiState : std::uint32_t {
    None,            ///< No useful capability (sentinel returned only by uiStateFor()).
    NoCard,          ///< No card present (caller-supplied, never produced by uiStateFor).
    PreAuthRequired, ///< Card present but a pre-read unlock is required first.
    IdentityOnly,    ///< IdentityData without PKI.
    PkiOnly,         ///< PKI without IdentityData.
    Hybrid,          ///< Both IdentityData and PKI.
    Error,           ///< Resolution failed / capabilities unusable (ancillary-only).
    UnknownCard,     ///< Card present but the agent matched no plugin (empty capability set).
};

/// @brief True when @p flag is present in @p caps.
[[nodiscard]] constexpr bool has(std::uint32_t caps, std::uint32_t flag) noexcept
{
    return (caps & flag) != 0U;
}

/// @brief Map a capability bitfield to its coarse UI grouping.
///
/// Pure 2×2 over {IdentityData, PKI}; everything else (EmrtdCrypto,
/// PinManagement) is ancillary and does not, on its own, create a surface.
[[nodiscard]] constexpr UiState uiStateFor(std::uint32_t caps) noexcept
{
    const bool identity = has(caps, Cap::IdentityData);
    const bool pki = has(caps, Cap::Pki);
    if (identity && pki) {
        return UiState::Hybrid;
    }
    if (identity) {
        return UiState::IdentityOnly;
    }
    if (pki) {
        return UiState::PkiOnly;
    }
    return UiState::None;
}

/// @brief Resolve a card's full UI state, owning the latch logic every surface
///        would otherwise re-implement.
///
/// The single pure source of truth for "what does the user see for this card":
///   - not present                       -> NoCard
///   - present, a pre-read unlock is required AND identity not yet read
///                                        -> PreAuthRequired (the surface must
///                                           prompt for the CAN/MRZ first)
///   - otherwise the coarse uiStateFor grouping, with a None split by cause:
///     an EMPTY capability set (no plugin matched) becomes UnknownCard, while
///     an ancillary-only set (no user surface) becomes Error — both distinct
///     from "no card at all".
///
/// @param caps          The card's capability bitfield.
/// @param preAuth       The card's pre-read unlock requirement.
/// @param present       Whether a card is present in the reader.
/// @param identityRead  Whether identity has already been read (clears the
///                      pre-auth latch once the unlock succeeded).
[[nodiscard]] constexpr UiState resolveCardState(std::uint32_t caps, PreReadAuth preAuth, bool present,
                                                 bool identityRead) noexcept
{
    if (!present) {
        return UiState::NoCard;
    }
    if (preAuth != PreReadAuth::None && !identityRead) {
        return UiState::PreAuthRequired;
    }
    const UiState grouped = uiStateFor(caps);
    if (grouped == UiState::None) {
        // A present card the agent matched no plugin for (empty capability set) is
        // a calm "unrecognized card", distinct from an ancillary-only card (e.g.
        // eMRTD-crypto / PIN-management with no IdentityData or PKI) which has no
        // user surface and is a genuine error to the user.
        return caps == 0U ? UiState::UnknownCard : UiState::Error;
    }
    return grouped;
}

// ---- public token vocabulary --------------------------------------------------
//
// AgentCard::capabilities() and AgentCard::preReadAuth() hand back the STABLE
// TOKEN spellings of the wire contract (the `capability-bit` group names and
// the `pre-read-auth` names in wire/librescrs-agent.cddl) rather than raw
// integers, so the public API survives append-only wire growth without an ABI
// event. `capabilityBits()` converts the token form back to the bitfield the
// pure resolvers above take.

/// @brief The bitfield for @p tokens — the exact inverse of the token list
///        `AgentCard::capabilities()` returns (including the "bit<i>" spelling
///        for unknown bits). Unrecognized
///        tokens are ignored, so a FUTURE named capability this build does not
///        know cannot corrupt the bits it does.
[[nodiscard]] inline std::uint32_t capabilityBits(const QStringList& tokens)
{
    std::uint32_t caps = Cap::None;
    for (const QString& token : tokens) {
        if (token == QLatin1String("Pki")) {
            caps |= Cap::Pki;
        } else if (token == QLatin1String("IdentityData")) {
            caps |= Cap::IdentityData;
        } else if (token == QLatin1String("EmrtdCrypto")) {
            caps |= Cap::EmrtdCrypto;
        } else if (token == QLatin1String("PinManagement")) {
            caps |= Cap::PinManagement;
        } else if (token.startsWith(QLatin1String("bit"))) {
            bool ok = false;
            const unsigned int bit = token.mid(3).toUInt(&ok);
            if (ok && bit < 32U) {
                caps |= std::uint32_t{1} << bit;
            }
        }
    }
    return caps;
}

/// @brief Decode the verbatim pre-read-auth wire token AgentCard::preReadAuth()
///        forwards ("None" / "Mrz" / "Can").
///
/// An EMPTY token (an agent predating the property) decodes to
/// PreReadAuth::None. Any other token this build does not name -- a method
/// appended to the wire later -- decodes to std::nullopt: the card wants
/// SOMETHING before it can be read, this client just cannot say what. Treat
/// that as "unlock required" (preReadUnlockRequired()), never as None, which
/// would read the card without unlocking it.
[[nodiscard]] inline std::optional<PreReadAuth> preReadAuthFromToken(QStringView token) noexcept
{
    if (token.isEmpty() || token == QLatin1String("None")) {
        return PreReadAuth::None;
    }
    if (token == QLatin1String("Mrz")) {
        return PreReadAuth::Mrz;
    }
    if (token == QLatin1String("Can")) {
        return PreReadAuth::Can;
    }
    return std::nullopt;
}

/// @brief Whether a card with pre-read-auth @p token must be unlocked before
///        its data is read: every method, known or not, except None.
[[nodiscard]] inline bool preReadUnlockRequired(QStringView token) noexcept
{
    const std::optional<PreReadAuth> method = preReadAuthFromToken(token);
    return !method || *method != PreReadAuth::None;
}

} // namespace LibreSCRS::AgentClient
