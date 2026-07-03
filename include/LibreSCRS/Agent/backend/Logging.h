// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <format>
#include <functional>
#include <string>
#include <string_view>
// Qt-free logging facade. info/warn/error format a line and hand it to the
// injected LogSink together with its severity; the sink owns the platform
// transport (Linux: journald syslog-priority-prefixed std::clog). The category
// is injected once at startup, defaulting to the librescrs form. Mirrors
// LibreMiddleware's Qt-free std::clog approach.
namespace LibreSCRS::Agent::log {

enum class Level : std::uint8_t { Info, Warn, Error };

// Injected once into the log facade. Linux: journald syslog-priority-prefixed
// std::clog. An empty sink restores the built-in journald sink.
using LogSink = std::function<void(Level, std::string_view line)>;

// Replace the sink + category. Wired once during single-threaded startup; safe
// against concurrent emits (guarded by the same per-line mutex). An empty sink
// restores the built-in journald sink.
void init(LogSink sink, std::string category = "rs.librescrs.agent");

// Test-only: restore the built-in journald sink + default librescrs category so
// a following case in the same binary is unaffected by an injected sink.
void resetForTest() noexcept;

void info(std::string_view message);
void warn(std::string_view message);
void error(std::string_view message);

// Convenience: format then log.
template <class... Args>
void infof(std::format_string<Args...> fmt, Args&&... args)
{
    info(std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void warnf(std::format_string<Args...> fmt, Args&&... args)
{
    warn(std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void errorf(std::format_string<Args...> fmt, Args&&... args)
{
    error(std::format(fmt, std::forward<Args>(args)...));
}

} // namespace LibreSCRS::Agent::log
