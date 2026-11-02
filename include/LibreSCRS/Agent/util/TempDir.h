// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

/// @file
/// @brief A mkstemp template in the process's temporary directory: the one
///        spelling of "TMPDIR, else /tmp" for code that makes an anonymous file
///        (create, then unlink at once) where memfd_create does not exist.

namespace LibreSCRS::Agent {

/// The temporary directory with a trailing '/': $TMPDIR when set and non-empty,
/// otherwise "/tmp/".
[[nodiscard]] inline std::string tempDirectory()
{
    const char* fromEnvironment = std::getenv("TMPDIR");
    std::string dir =
        (fromEnvironment != nullptr && *fromEnvironment != '\0') ? std::string(fromEnvironment) : std::string("/tmp/");
    if (dir.back() != '/') {
        dir.push_back('/');
    }
    return dir;
}

/// A NUL-terminated, writable mkstemp(3) template in tempDirectory(), named
/// @p prefix followed by the six X the call replaces.
[[nodiscard]] inline std::vector<char> tempFileTemplate(std::string_view prefix)
{
    std::string path = tempDirectory();
    path += prefix;
    path += "XXXXXX";
    std::vector<char> out(path.begin(), path.end());
    out.push_back('\0');
    return out;
}

} // namespace LibreSCRS::Agent
