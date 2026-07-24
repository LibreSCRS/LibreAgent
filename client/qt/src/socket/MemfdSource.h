// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL, Linux-TEST-only — never installed, never compiled into the
// library. memfd_create is the TEST document source for the socket
// transport's fd-passing suites: the transport itself is agnostic about what
// kind of file descriptor a caller hands it (the macOS client passes plain
// file fds; these suites pass anonymous memfds so no test artifact touches
// the filesystem).
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QByteArray>

namespace LibreSCRS::AgentClient {

/// @brief An anonymous memfd holding @p bytes, file position rewound to 0
///        (invalid handle on failure). Linux-only.
[[nodiscard]] FdHandle makeMemfdDocument(const QByteArray& bytes);

/// @brief Read a descriptor's entire regular-file content via pread —
///        independent of (and without disturbing) any shared file-position
///        state, so it works on a JUST-received SCM_RIGHTS fd too.
[[nodiscard]] QByteArray readFdAll(int fd);

} // namespace LibreSCRS::AgentClient
