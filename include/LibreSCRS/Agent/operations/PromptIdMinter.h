// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>

namespace LibreSCRS::Agent::Operations {

/// Mints the opaque identifier a prompt carries end to end.
///
/// The id is "<runNonce>:<counter>". The nonce is what makes it safe across a
/// restart: a bare per-process counter would restart at 1, and a prompter
/// still holding a window from the previous agent would answer to -- or be
/// closed by -- an id the NEW agent minted for something else. The same
/// mistake is already recorded against card ids as review finding LK-3.
///
/// Prompters treat the whole string as opaque and never parse it.
///
/// Injected by the agent core, never a static: the project bans singletons.
///
/// @since 4.3
class PromptIdMinter
{
public:
    /// Production: a random 64-bit nonce, rendered as lowercase hex.
    PromptIdMinter()
    {
        std::random_device rd;
        const auto hi = static_cast<std::uint64_t>(rd());
        const auto lo = static_cast<std::uint64_t>(rd());
        const std::uint64_t nonce = (hi << 32) ^ lo;
        static constexpr char kHex[] = "0123456789abcdef";
        m_runNonce.resize(16);
        for (int i = 15; i >= 0; --i) {
            m_runNonce[static_cast<std::size_t>(i)] = kHex[(nonce >> ((15 - i) * 4)) & 0xF];
        }
    }

    /// Tests inject a fixed nonce so ids are predictable.
    explicit PromptIdMinter(std::string runNonce) : m_runNonce(std::move(runNonce)) {}

    PromptIdMinter(const PromptIdMinter&) = delete;
    PromptIdMinter& operator=(const PromptIdMinter&) = delete;
    PromptIdMinter(PromptIdMinter&&) = delete;
    PromptIdMinter& operator=(PromptIdMinter&&) = delete;

    /// Next id. Thread-safe: reader workers mint concurrently.
    [[nodiscard]] std::string mint()
    {
        const auto n = m_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        return m_runNonce + ":" + std::to_string(n);
    }

    [[nodiscard]] const std::string& runNonce() const noexcept
    {
        return m_runNonce;
    }

private:
    std::string m_runNonce;
    std::atomic<std::uint64_t> m_counter{0};
};

} // namespace LibreSCRS::Agent::Operations
