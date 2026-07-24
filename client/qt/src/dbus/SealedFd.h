// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QByteArray>

#include <sys/mman.h>
#include <sys/stat.h>

/// @file
/// @brief INTERNAL — never installed. The audited reader for BOUNDED
///        sealed-memfd payloads the agent hands over as file descriptors —
///        small, fully-buffered data such as a photo result. It mmaps the
///        whole fd into a `QByteArray`, so every place reading a bounded
///        payload shares this single implementation rather than re-spelling
///        sealed-fd + mmap + PII handling per call site.
///
/// It is deliberately NOT used for arbitrary-size streamed artifacts (e.g. a
/// signed document, which may be a large PDF): those are copied through a
/// bounded read-loop straight into the consumer's output file, never mmapped
/// whole into memory. NEVER logs the bytes — the payload is PII.

namespace LibreSCRS::AgentClient {

/// @brief mmap-read the whole sealed memfd behind @p sealed into a QByteArray.
///        Returns an empty array on an invalid fd, a non-positive size, or an
///        mmap failure. The mapping is released before returning; the handle
///        keeps ownership of the descriptor.
[[nodiscard]] inline QByteArray readSealedFd(const FdHandle& sealed)
{
    if (!sealed.valid()) {
        return {};
    }
    const int fd = sealed.get();
    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
        return {};
    }
    const auto size = static_cast<size_t>(st.st_size);
    void* map = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        return {};
    }
    QByteArray out(static_cast<const char*>(map), static_cast<qsizetype>(size));
    ::munmap(map, size);
    return out;
}

} // namespace LibreSCRS::AgentClient
