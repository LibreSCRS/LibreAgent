// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Logging.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

// Recording double over the injected log sink (log::LogSink). install() wires it
// into the log facade; every info/warn/error line then lands in `lines` with its
// severity. The captured string is the fully-formatted line the facade produces
// (priority prefix + category + level + message + newline), not the bare
// message. Call log::resetForTest() (or this type's destructor) to restore the
// built-in journald sink so a following case is unaffected.
struct FakeLogSink
{
    std::vector<std::pair<log::Level, std::string>> lines;

    // The std::function the facade holds. Captures `this`, so this FakeLogSink
    // must outlive the injected sink (install()/resetForTest() bracket its life).
    [[nodiscard]] log::LogSink sink()
    {
        return [this](log::Level level, std::string_view line) { lines.emplace_back(level, std::string(line)); };
    }

    void install(std::string category = "rs.librescrs.agent")
    {
        log::init(sink(), std::move(category));
    }

    ~FakeLogSink()
    {
        log::resetForTest();
    }
};

} // namespace LibreSCRS::Agent
