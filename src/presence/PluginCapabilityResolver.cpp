// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/PluginCapabilityResolver.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <utility>

namespace LibreSCRS::Agent {

PluginCapabilityResolver::PluginCapabilityResolver(std::shared_ptr<LibreSCRS::Plugin::CardPluginService> service)
    : m_service(std::move(service))
{}

std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
PluginCapabilityResolver::resolvePlugin(std::span<const std::uint8_t> atr) const noexcept
{
    if (!m_service) {
        return nullptr;
    }
    try {
        return m_service->findPluginForCard(atr);
    } catch (...) {
        return nullptr;
    }
}

std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
PluginCapabilityResolver::resolveCandidates(std::span<const std::uint8_t> atr,
                                            LibreSCRS::SmartCard::CardSession& session)
{
    if (!m_service) {
        return {};
    }
    std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>> candidates;
    try {
        candidates = m_service->findAllCandidates(atr, session);
    } catch (...) {
        // Treated as no match.
    }
    // Fall back to the ATR-only path if the session-based lookup produced nothing.
    if (candidates.empty()) {
        try {
            if (auto fast = m_service->findPluginForCard(atr); fast) {
                candidates.push_back(std::move(fast));
            }
        } catch (...) {
            // Treated as no match.
        }
    }
    return {candidates.begin(), candidates.end()};
}

} // namespace LibreSCRS::Agent
