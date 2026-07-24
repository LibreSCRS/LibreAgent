// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Agent/wire/PreReadAuth.h>

#include <QString>
#include <QStringList>
#include <QStringView>

#include <cstdint>

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
inline constexpr std::uint32_t None = 0;
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
// event. These helpers convert between the token form and the bitfield/enum
// form the pure resolvers above take.

/// @brief The token list for @p caps, in ascending bit order. Known bits use
///        their contract names ("Pki", "IdentityData", "EmrtdCrypto",
///        "PinManagement"); an unknown bit i (a future, appended capability)
///        round-trips as "bit<i>" instead of being silently dropped.
[[nodiscard]] inline QStringList capabilityTokens(std::uint32_t caps)
{
    QStringList tokens;
    for (unsigned int bit = 0; bit < 32U; ++bit) {
        const std::uint32_t flag = std::uint32_t{1} << bit;
        if (!has(caps, flag)) {
            continue;
        }
        switch (flag) {
        case Cap::Pki:
            tokens.append(QStringLiteral("Pki"));
            break;
        case Cap::IdentityData:
            tokens.append(QStringLiteral("IdentityData"));
            break;
        case Cap::EmrtdCrypto:
            tokens.append(QStringLiteral("EmrtdCrypto"));
            break;
        case Cap::PinManagement:
            tokens.append(QStringLiteral("PinManagement"));
            break;
        default:
            tokens.append(QStringLiteral("bit%1").arg(bit));
            break;
        }
    }
    return tokens;
}

/// @brief The bitfield for @p tokens — the exact inverse of capabilityTokens()
///        (including the "bit<i>" spelling for unknown bits). Unrecognized
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
///        forwards ("None" / "BacMrz" / "PaceCan"). Anything unrecognized —
///        including a future appended method — decodes to PreReadAuth::None,
///        matching the lifted client's lenient parse.
[[nodiscard]] inline PreReadAuth preReadAuthFromToken(QStringView token) noexcept
{
    if (token == QLatin1String("BacMrz")) {
        return PreReadAuth::BacMrz;
    }
    if (token == QLatin1String("PaceCan")) {
        return PreReadAuth::PaceCan;
    }
    return PreReadAuth::None;
}

} // namespace LibreSCRS::AgentClient
