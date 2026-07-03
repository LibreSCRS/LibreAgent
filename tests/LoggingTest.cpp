// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Stress the per-line atomicity claim: many threads emit interleaved log
// messages; with the TU-private mutex in Logging.cpp, every line in the
// captured stream must be intact (no two messages' bytes spliced together).

#include <LibreSCRS/Agent/backend/Logging.h>
#include <gtest/gtest.h>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;

TEST(Logging, ConcurrentEmitsArePerLineAtomic)
{
    // Redirect std::clog into a stringstream for the duration of the test.
    std::stringstream captured;
    std::streambuf* savedBuf = std::clog.rdbuf(captured.rdbuf());

    constexpr int kThreads = 8;
    constexpr int kPerThread = 200;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t] {
            for (int j = 0; j < kPerThread; ++j) {
                log::infof("thread-{}-msg-{}", t, j);
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }

    // Restore std::clog before any further use.
    std::clog.rdbuf(savedBuf);

    // Split into lines.
    std::vector<std::string> lines;
    {
        std::string line;
        while (std::getline(captured, line)) {
            lines.push_back(std::move(line));
        }
    }

    EXPECT_EQ(lines.size(), static_cast<std::size_t>(kThreads * kPerThread))
        << "expected exactly kThreads * kPerThread log lines";

    std::set<std::string> distinct;
    for (const auto& line : lines) {
        // Each well-formed line contains exactly one 'thread-' token. If the
        // mutex failed and two emits interleaved, we'd see two 'thread-'
        // substrings on the same line.
        const auto first = line.find("thread-");
        ASSERT_NE(first, std::string::npos) << "line missing payload: " << line;
        EXPECT_EQ(line.find("thread-", first + 1), std::string::npos)
            << "log line shows two messages spliced together: " << line;
        distinct.insert(line);
    }
    EXPECT_EQ(distinct.size(), static_cast<std::size_t>(kThreads * kPerThread))
        << "duplicated lines indicate broken atomicity / lost emits";
}

TEST(Logging, InjectedSinkReceivesLevelLineAndCategory)
{
    using LibreSCRS::Agent::log::Level;
    std::vector<std::pair<Level, std::string>> seen;
    log::init([&](Level lvl, std::string_view line) { seen.emplace_back(lvl, std::string{line}); },
              "rs.librescrs.agent");
    log::info("hello");
    log::warn("careful");
    log::error("boom");
    log::resetForTest(); // restore default journald std::clog sink

    ASSERT_EQ(seen.size(), 3u);
    EXPECT_EQ(seen[0].first, Level::Info);
    EXPECT_EQ(seen[1].first, Level::Warn);
    EXPECT_EQ(seen[2].first, Level::Error);
    EXPECT_NE(seen[0].second.find("rs.librescrs.agent"), std::string::npos);
    EXPECT_EQ(seen[0].second.find("librelinux"), std::string::npos) << "old repo name must be gone";
    EXPECT_NE(seen[2].second.find("boom"), std::string::npos);
}
