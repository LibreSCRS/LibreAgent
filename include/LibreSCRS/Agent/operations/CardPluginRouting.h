// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <span>
#include <string>
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

// Stable prioritisation for mutation routing: move the candidate whose
// pluginId matches @p pluginId to the FRONT, preserving the relative
// (priority) order of the rest. A mutation is routed across the returned
// order with first-non-Unsupported-wins semantics, so the front slot decides
// which plugin answers first — the list flow binds each snapshot to its
// listing plugin (CredentialSnapshot::listPluginId) and the mutation flows
// pass that identity here. No-op for an empty or unmatched id: the list keeps
// its plain priority order.
[[nodiscard]] inline CandidateList prioritizeCandidate(CandidateList cands, const std::string& pluginId)
{
    if (pluginId.empty()) {
        return cands;
    }
    const auto it =
        std::find_if(cands.begin(), cands.end(), [&](const auto& c) { return c && c->pluginId() == pluginId; });
    if (it != cands.end()) {
        std::rotate(cands.begin(), it, std::next(it));
    }
    return cands;
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
