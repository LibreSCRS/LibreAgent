// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "MemfdSource.h"

#if defined(__linux__)

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace LibreSCRS::AgentClient {

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

#endif // __linux__
