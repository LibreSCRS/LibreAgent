// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

// Pure, card-free routing over a card's candidate plugin list (from
// CardPluginService::findAllCandidates, already priority-ordered). Filters by the
// plugin's MANIFEST-declared capabilities — the single source of truth, so no
// hardcoded plugin-identity assumptions. Order is preserved (priority); callers
// iterate with lazy fallback.
namespace LibreSCRS::Agent::Operations {

using CandidateList = std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>;

[[nodiscard]] inline CandidateList
filterByCapability(std::span<const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> cands,
                   LibreSCRS::Plugin::CardCapabilities required)
{
    CandidateList out;
    for (const auto& c : cands) {
        if (c && LibreSCRS::Plugin::hasCapability(c->capabilities(), required)) {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] inline CandidateList
identityCandidates(std::span<const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> c)
{
    return filterByCapability(c, LibreSCRS::Plugin::CardCapabilities::IdentityData);
}
[[nodiscard]] inline CandidateList
pkiCandidates(std::span<const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> c)
{
    return filterByCapability(c, LibreSCRS::Plugin::CardCapabilities::PKI);
}
// Signing needs BOTH PKI and PinManagement (matches LibreCelik's isSigningCapable).
[[nodiscard]] inline CandidateList
signingCandidates(std::span<const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> cands)
{
    CandidateList out;
    for (const auto& c : cands) {
        if (c && LibreSCRS::Plugin::hasCapability(c->capabilities(), LibreSCRS::Plugin::CardCapabilities::PKI) &&
            LibreSCRS::Plugin::hasCapability(c->capabilities(), LibreSCRS::Plugin::CardCapabilities::PinManagement)) {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] inline std::uint32_t
unionCapabilities(std::span<const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> cands)
{
    std::uint32_t u = 0;
    for (const auto& c : cands) {
        if (c) {
            u |= static_cast<std::uint32_t>(c->capabilities());
        }
    }
    return u;
}

} // namespace LibreSCRS::Agent::Operations
