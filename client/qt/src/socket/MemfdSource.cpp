// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "MemfdSource.h"

#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/mman.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <cstdlib>
#include <string>
#include <vector>
#endif

#if defined(__linux__) || defined(__APPLE__)

namespace LibreSCRS::AgentClient {

#if defined(__linux__)

FdHandle makeMemfdDocument(const QByteArray& bytes)
{
    const int fd = ::memfd_create("laqt-test-document", 0);
    if (fd < 0) {
        return {};
    }
    FdHandle handle{fd};
    qint64 written = 0;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.constData() + written, static_cast<std::size_t>(bytes.size() - written));
        if (n <= 0) {
            return {};
        }
        written += n;
    }
    ::lseek(fd, 0, SEEK_SET);
    return handle;
}

#elif defined(__APPLE__)

FdHandle makeMemfdDocument(const QByteArray& bytes)
{
    // No memfd_create on Darwin: mkstemp into TMPDIR + immediate unlink is the
    // anonymous-file equivalent (same technique as LibreDarwin's
    // agent/src/backend/wire/AnonFd.cpp) — a regular-file fd that fully
    // supports pread/SCM_RIGHTS, unlike shm_open's mmap-only object.
    const char* tmpDir = std::getenv("TMPDIR");
    std::string tmpl = (tmpDir != nullptr && *tmpDir != '\0') ? std::string(tmpDir) : std::string("/tmp/");
    if (tmpl.back() != '/') {
        tmpl.push_back('/');
    }
    tmpl += "laqt-test-document-XXXXXX";
    std::vector<char> path(tmpl.begin(), tmpl.end());
    path.push_back('\0');

    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        return {};
    }
    FdHandle handle{fd};
    ::unlink(path.data()); // anonymous from here
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);

    qint64 written = 0;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.constData() + written, static_cast<std::size_t>(bytes.size() - written));
        if (n <= 0) {
            return {};
        }
        written += n;
    }
    ::lseek(fd, 0, SEEK_SET);
    return handle;
}

#endif

QByteArray readFdAll(int fd)
{
    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size < 0) {
        return {};
    }
    QByteArray out;
    out.resize(static_cast<qsizetype>(st.st_size));
    qint64 total = 0;
    while (total < out.size()) {
        const ssize_t n =
            ::pread(fd, out.data() + total, static_cast<std::size_t>(out.size() - total), static_cast<off_t>(total));
        if (n <= 0) {
            break;
        }
        total += n;
    }
    out.resize(static_cast<qsizetype>(total));
    return out;
}

} // namespace LibreSCRS::AgentClient

#endif // __linux__ || __APPLE__
