// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// A PURE INTERNAL translation unit: it defines no exported symbol, so a test
// can compile it directly without also acquiring a second definition of
// anything the shared library exports. That is the whole reason these two
// helpers live here rather than beside readBoundedPayload() in
// SealedPayload.cpp -- which is a mixed TU carrying the exported entry point.

#include "SealedPayloadInternal.h"

#include <LibreSCRS/AgentClient/SealedPayload.h> // kMaxBoundedPayloadBytes

#include <cerrno>
#include <cstddef>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace LibreSCRS::AgentClient::Internal {

std::optional<qsizetype> acceptablePayloadSize(mode_t mode, off_t reportedSize) noexcept
{
    // Only a REGULAR file has a size worth trusting. A pipe, socket or
    // character device answers the size query with st_size == 0 no matter how
    // many bytes are readable from it, so accepting one would hand the caller
    // an engaged-but-empty payload and destroy the very empty-versus-failure
    // distinction this reader exists to keep sharp: a caller could not tell
    // "the card carried no photo" from "you were handed a pipe". Positional
    // reads are not meaningful on those descriptors either. This check is
    // deliberately outside every platform gate.
    if (!S_ISREG(mode)) {
        return std::nullopt;
    }

    // st_size is a signed off_t. Reject a negative size before any conversion,
    // and compare against the cap in the WIDER of the two signed types so an
    // off_t larger than qsizetype can never wrap into a small positive value
    // and slip under the cap.
    if (reportedSize < 0) {
        return std::nullopt;
    }
    if (static_cast<qint64>(reportedSize) > static_cast<qint64>(kMaxBoundedPayloadBytes)) {
        return std::nullopt;
    }
    return static_cast<qsizetype>(reportedSize);
}

bool readExactly(int fd, char* dest, qsizetype size) noexcept
{
    qsizetype total = 0;
    while (total < size) {
        const ssize_t n = ::pread(fd, dest + total, static_cast<std::size_t>(size - total), static_cast<off_t>(total));
        if (n > 0) {
            total += static_cast<qsizetype>(n);
            continue;
        }
        if (n == 0) {
            // Premature end of file: fewer bytes than the size query promised.
            // This is the truncating-writer race the whole reader exists to
            // survive. Fail rather than hand up a silently truncated payload.
            //
            // This branch must come BEFORE the errno test below. It does not
            // change what is returned -- falling through would return false
            // too -- but errno is not set by a successful zero-byte read, so a
            // stale EINTR left in it would send the loop round again forever
            // on a descriptor that has nothing more to give.
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

} // namespace LibreSCRS::AgentClient::Internal
