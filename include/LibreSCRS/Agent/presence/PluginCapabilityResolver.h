// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <memory>
#include <string>
namespace LibreSCRS::Agent {
// Resolves a card to its plugin via the LM plugin registry. The ATR-only
// resolvePlugin() is a fast hint that misses AID-probed plugins (eMRTD declares
// an empty ATR table and identifies solely via SELECT AID). resolveCandidates()
// runs LM's findAllCandidates(atr, session) on an already-open session (the
// per-reader worker's held session) so the AID-probe path is reachable without
// opening a transient CardSession.
class PluginCapabilityResolver final : public CapabilityResolver
{
public:
    explicit PluginCapabilityResolver(std::shared_ptr<LibreSCRS::Plugin::CardPluginService> service);

    [[nodiscard]] std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> atr) const noexcept override;

    [[nodiscard]] std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t> atr, LibreSCRS::SmartCard::CardSession& session) override;

private:
    std::shared_ptr<LibreSCRS::Plugin::CardPluginService> m_service;
};
} // namespace LibreSCRS::Agent
