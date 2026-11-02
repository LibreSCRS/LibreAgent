// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Wire {

/// The largest document a client may hand the agent behind a file descriptor:
/// the input of a Sign or SignBatch entry. Both hosts refuse anything larger
/// with `InputTooLarge`.
inline constexpr std::size_t kMaxInputBytes = 256ull * 1024 * 1024;

enum class ReadStatus : std::uint8_t {
    Ok,
    /// More than the cap was there; nothing is returned.
    TooLarge,
    /// Not a descriptor, or fstat/read failed.
    Error,
    /// A pipe, socket, character device or directory: not something a
    /// blocking read is guaranteed to finish on.
    NotRegular,
};

struct BoundedRead
{
    ReadStatus status{ReadStatus::Error};
    std::vector<std::uint8_t> bytes{};
};

/// Read the whole of a client-supplied @p fd, refusing more than @p cap bytes.
///
/// The fd MUST be a regular file or memfd. A pipe or socket would let a client
/// hold the read open forever on the thread that serves every other client --
/// one request stalling the whole agent -- so a non-regular fd is refused before
/// the first read. A regular file is finite, and the cap bounds it.
///
/// One function for every host and every fd-carried input (documents, master
/// lists): two copies of this check are two places to forget the fstat.
[[nodiscard]] inline BoundedRead readBoundedRegularFd(int fd, std::size_t cap)
{
    if (fd < 0) {
        return {ReadStatus::Error, {}};
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return {ReadStatus::Error, {}};
    }
    if (!S_ISREG(st.st_mode)) {
        return {ReadStatus::NotRegular, {}};
    }
    std::vector<std::uint8_t> out;
    std::array<std::uint8_t, 64 * 1024> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {ReadStatus::Error, {}};
        }
        if (n == 0) {
            return {ReadStatus::Ok, std::move(out)};
        }
        const auto got = static_cast<std::size_t>(n);
        // Subtraction, not out.size() + got: the sum is what a cap near
        // SIZE_MAX would wrap.
        if (got > cap - out.size()) {
            return {ReadStatus::TooLarge, {}};
        }
        out.insert(out.end(), buf.data(), buf.data() + got);
    }
}

} // namespace LibreSCRS::Agent::Wire
