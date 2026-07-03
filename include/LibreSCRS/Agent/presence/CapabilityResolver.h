// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardInfo.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace LibreSCRS::Plugin {
class CardPlugin;
}
namespace LibreSCRS::SmartCard {
class CardSession;
}
namespace LibreSCRS::Agent {
// Seam: maps a card to non-secret facts. The ATR-only `resolvePlugin` is a fast
// hint covering plugins that declare a non-empty ATR table. Plugins that
// identify exclusively via AID probe (e.g. eMRTD) are resolved by
// `resolveCandidates` on the per-reader worker's already-open held session (the
// two-phase ATR fast path → AID probe fallback), so no transient CardSession is
// ever opened off the worker.
class CapabilityResolver
{
public:
    // Full resolution result: all matching plugins (priority-ordered) plus
    // the union of their declared capabilities and the strongest pre-read
    // auth requirement among them.
    struct CardResolution
    {
        std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> candidates;
        std::uint32_t capabilities{0};
        LibreSCRS::Auth::PreReadAuthMethod preReadAuth{LibreSCRS::Auth::PreReadAuthMethod::None};
    };

    virtual ~CapabilityResolver() = default;

    [[nodiscard]] virtual std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> /*atr*/) const noexcept
    {
        return nullptr;
    }

    // Resolve the priority-ordered candidate plugin list for a card on an
    // already-open @p session (the two-phase ATR + AID-probe lookup). Used by
    // the per-reader CardSessionHolder to resolve candidates once on the held
    // session. The default returns an empty list so existing fakes keep
    // compiling; the production resolver forwards to the plugin registry.
    [[nodiscard]] virtual std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t> /*atr*/, LibreSCRS::SmartCard::CardSession& /*session*/)
    {
        return {};
    }
};
} // namespace LibreSCRS::Agent
