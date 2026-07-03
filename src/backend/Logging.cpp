// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/backend/Logging.h>
#include <format>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
namespace LibreSCRS::Agent::log {
namespace {

// Serialize emits so a background poll thread and the main thread cannot
// interleave bytes within a log line. Not a singleton — TU-private mutex with
// no accessor and no domain state, serving the same role a per-object
// std::mutex would. Also guards g_sink/g_category so init() cannot race an emit.
std::mutex& logMutex()
{
    static std::mutex m;
    return m;
}

const char* priorityPrefix(Level level)
{
    switch (level) {
    case Level::Info:
        return "<6>";
    case Level::Warn:
        return "<4>";
    case Level::Error:
        return "<3>";
    }
    return "<6>";
}

const char* levelText(Level level)
{
    switch (level) {
    case Level::Info:
        return "info";
    case Level::Warn:
        return "warning";
    case Level::Error:
        return "error";
    }
    return "info";
}

// The built-in sink: write the already-formatted, journald-priority-prefixed
// line to std::clog (stderr). journald reads the leading `<N>` syslog priority.
void journaldSink(std::string_view line)
{
    std::clog << line << std::flush;
}

// Empty => journaldSink. Guarded by logMutex().
LogSink g_sink;
// Guarded by logMutex().
std::string g_category = "rs.librescrs.agent";

void emit(Level level, std::string_view message)
{
    // Hold the lock across the g_category/g_sink read, the format, and the sink
    // call: this both keeps every line atomic (no interleaved bytes) and guards
    // g_sink/g_category against a concurrent init().
    std::scoped_lock lock(logMutex());
    const auto line = std::format("{}{} {}: {}\n", priorityPrefix(level), g_category, levelText(level), message);
    if (g_sink) {
        g_sink(level, line);
    } else {
        journaldSink(line);
    }
}

} // namespace

void init(LogSink sink, std::string category)
{
    std::scoped_lock lock(logMutex());
    g_sink = std::move(sink);
    g_category = std::move(category);
}

void resetForTest() noexcept
{
    std::scoped_lock lock(logMutex());
    g_sink = nullptr;
    g_category = "rs.librescrs.agent";
}

void info(std::string_view message)
{
    emit(Level::Info, message);
}
void warn(std::string_view message)
{
    emit(Level::Warn, message);
}
void error(std::string_view message)
{
    emit(Level::Error, message);
}

} // namespace LibreSCRS::Agent::log
