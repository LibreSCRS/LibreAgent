// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL, TEST-only — never installed, never compiled into the library.
// An anonymous, in-memory-backed document source for the socket transport's
// fd-passing suites: the transport itself is agnostic about what kind of
// file descriptor a caller hands it (the production client passes plain
// file fds; these suites pass anonymous ones so no test artifact touches a
// named path). memfd_create on Linux; mkstemp + immediate unlink on Darwin
// (which has no memfd_create) — the same technique
// LibreDarwin/agent/src/backend/wire/AnonFd.cpp uses in production there.
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QByteArray>

namespace LibreSCRS::AgentClient {

/// @brief An anonymous fd holding @p bytes, file position rewound to 0
///        (invalid handle on failure). Linux + Darwin only.
[[nodiscard]] FdHandle makeMemfdDocument(const QByteArray& bytes);

/// @brief Read a descriptor's entire regular-file content via pread —
///        independent of (and without disturbing) any shared file-position
///        state, so it works on a JUST-received SCM_RIGHTS fd too.
[[nodiscard]] QByteArray readFdAll(int fd);

} // namespace LibreSCRS::AgentClient
