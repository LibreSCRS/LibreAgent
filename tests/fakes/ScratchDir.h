// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Agent/util/TempDir.h>

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace LibreSCRS::Agent::Testing {

/// A new, empty directory of the caller's own in the temporary directory.
/// ctest runs a binary's cases side by side, so a case that keeps its store
/// under a fixed name shares it with every other case of that binary, and one
/// case's teardown removes another's files mid-run.
[[nodiscard]] inline std::filesystem::path makeScratchDir(std::string_view prefix)
{
    std::vector<char> path = tempFileTemplate(prefix);
    if (::mkdtemp(path.data()) == nullptr) {
        throw std::runtime_error("mkdtemp failed");
    }
    return std::filesystem::path(path.data());
}

} // namespace LibreSCRS::Agent::Testing
