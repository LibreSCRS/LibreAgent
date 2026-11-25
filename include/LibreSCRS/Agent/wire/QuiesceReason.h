// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

/// @file
/// @brief Why the agent quiesced card access, wire-frozen and append-only.

namespace LibreSCRS::Agent {

/// @brief Why the agent quiesced card access: the holder's session went away
///        (the machine sleeps, the user switched away, the screen locked).
///
/// One vocabulary for every platform. The host translates its own system
/// events into a reason (systemd-logind on Linux, the workspace and power
/// notifications on macOS) and hands it to the core, which decides what to
/// forget; the host then announces the same reason to its clients
/// (`AgentQuiesced` on the socket, `Quiesced` on D-Bus) and, when the quiesce
/// ends, says so (`AgentResumed`, `Resumed`).
///
/// WIRE-FROZEN, APPEND-ONLY: the integers travel. A client decodes a value
/// past the last one it knows through verbatim, as a quiesce for a reason it
/// cannot name.
///
/// @since 5.0
enum class QuiesceReason : std::uint8_t {
    SystemSleep = 0,     ///< The machine is about to sleep; the reader loses power.
    ScreenLocked = 1,    ///< The holder's screen locked; the session itself stays.
    SessionInactive = 2, ///< The holder's session stopped being the active one (user switch).
};

/// @brief Which quiesce reasons are active right now.
///
/// The one record both sides keep. A host announces the end of a reason
/// (`AgentResumed` on the socket, `Resumed` on D-Bus) only when that reason was
/// active; a client counts the agent reachable again only when no reason is
/// left. Holds any `uint8_t` value, including one past the last this build
/// names, which a client decodes through verbatim.
///
/// Thread-safety: none. The agent's host keeps its set behind the lock that
/// serialises its lifecycle callbacks; a client's transport touches it only
/// from its own (event-loop) thread.
///
/// @code
/// QuiesceSet set;
/// if (set.begin(QuiesceReason::ScreenLocked)) { /* announce Quiesced */ }
/// if (set.end(QuiesceReason::ScreenLocked)) { /* announce Resumed */ }
/// @endcode
///
/// @since 5.0
class QuiesceSet
{
public:
    /// @return true when @p reason was not active before.
    constexpr bool begin(QuiesceReason reason) noexcept
    {
        auto& word = words[index(reason)];
        const bool fresh = (word & bit(reason)) == 0;
        word |= bit(reason);
        return fresh;
    }

    /// @return true when @p reason was active before.
    constexpr bool end(QuiesceReason reason) noexcept
    {
        auto& word = words[index(reason)];
        const bool wasActive = (word & bit(reason)) != 0;
        word &= ~bit(reason);
        return wasActive;
    }

    /// @return true when no reason is active.
    [[nodiscard]] constexpr bool empty() const noexcept
    {
        for (const auto word : words) {
            if (word != 0) {
                return false;
            }
        }
        return true;
    }

    /// Forgets every reason.
    constexpr void clear() noexcept
    {
        words = {};
    }

private:
    static constexpr std::size_t index(QuiesceReason reason) noexcept
    {
        return static_cast<std::uint8_t>(reason) / 64u;
    }
    static constexpr std::uint64_t bit(QuiesceReason reason) noexcept
    {
        return std::uint64_t{1} << (static_cast<std::uint8_t>(reason) % 64u);
    }

    std::array<std::uint64_t, 4> words{};
};

} // namespace LibreSCRS::Agent
