// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The two decision pieces of readBoundedPayload() driven directly, because
// both carry a branch the public entry point cannot reach on a sane kernel:
//
//   * a NEGATIVE reported size. A regular file never reports one, so this is
//     pure defence against a hostile or broken filesystem and no fixture can
//     produce it through the public call.
//   * a PREMATURE end of file. This one is not hypothetical at all — it is the
//     truncating-writer race the whole reader exists to survive — but staging
//     it through the public call would mean truncating the file in the window
//     between the size query and the read, which no single-threaded test can
//     do deterministically. Asking readExactly() for more bytes than the file
//     holds reproduces exactly the same code path with no race.
//
// Compiles SealedPayloadInternal.cpp directly, the same way this component's
// other internal-TU suites do, since neither helper is exported from the shared
// library. That file is a PURE internal TU -- it defines no exported symbol --
// so this executable does not end up with a second definition of anything the
// linked library exports.

#include "SealedPayloadInternal.h"

#include <LibreSCRS/AgentClient/SealedPayload.h>

#include <gtest/gtest.h>

#include <QByteArray>

#include <cerrno>
#include <cstddef>
#include <limits>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using LibreSCRS::AgentClient::kMaxBoundedPayloadBytes;
using LibreSCRS::AgentClient::Internal::acceptablePayloadSize;
using LibreSCRS::AgentClient::Internal::readExactly;

namespace {

// A regular file holding @p bytes, unlinked immediately. Returns -1 on
// failure; the caller closes it.
[[nodiscard]] int makeRegularFileFd(const QByteArray& bytes)
{
    std::string path = "/tmp/librescrs-bounded-payload-internal-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        return -1;
    }
    ::unlink(path.c_str());
    qsizetype written = 0;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.constData() + written, static_cast<std::size_t>(bytes.size() - written));
        if (n > 0) {
            written += static_cast<qsizetype>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

// --- acceptablePayloadSize -------------------------------------------------

TEST(SealedPayloadInternalTest, RegularFileSizesAreAccepted)
{
    EXPECT_EQ(acceptablePayloadSize(S_IFREG | 0600, 0), std::optional<qsizetype>{0});
    EXPECT_EQ(acceptablePayloadSize(S_IFREG | 0600, 1), std::optional<qsizetype>{1});
    EXPECT_EQ(acceptablePayloadSize(S_IFREG | 0600, 4096), std::optional<qsizetype>{4096});
}

TEST(SealedPayloadInternalTest, NegativeReportedSizeIsRejected)
{
    EXPECT_FALSE(acceptablePayloadSize(S_IFREG | 0600, -1).has_value())
        << "a negative size must be refused before any conversion to an unsigned length";
    EXPECT_FALSE(acceptablePayloadSize(S_IFREG | 0600, -4096).has_value());
    EXPECT_FALSE(acceptablePayloadSize(S_IFREG | 0600, std::numeric_limits<off_t>::min()).has_value())
        << "the most negative value must not wrap into a huge positive length";
}

TEST(SealedPayloadInternalTest, CapBoundaryIsInclusive)
{
    EXPECT_EQ(acceptablePayloadSize(S_IFREG | 0600, static_cast<off_t>(kMaxBoundedPayloadBytes)),
              std::optional<qsizetype>{kMaxBoundedPayloadBytes});
    EXPECT_FALSE(acceptablePayloadSize(S_IFREG | 0600, static_cast<off_t>(kMaxBoundedPayloadBytes) + 1).has_value());
    EXPECT_FALSE(acceptablePayloadSize(S_IFREG | 0600, std::numeric_limits<off_t>::max()).has_value());
}

TEST(SealedPayloadInternalTest, NonRegularModesAreRejectedWhateverTheSize)
{
    // Each of these is refused for its MODE alone — the sizes passed here are
    // deliberately plausible, so nothing can pass by way of the size rules.
    EXPECT_FALSE(acceptablePayloadSize(S_IFIFO | 0600, 0).has_value()) << "pipe";
    EXPECT_FALSE(acceptablePayloadSize(S_IFIFO | 0600, 38).has_value()) << "pipe with a plausible size";
    EXPECT_FALSE(acceptablePayloadSize(S_IFSOCK | 0600, 24).has_value()) << "socket";
    EXPECT_FALSE(acceptablePayloadSize(S_IFCHR | 0600, 0).has_value()) << "character device";
    EXPECT_FALSE(acceptablePayloadSize(S_IFBLK | 0600, 4096).has_value()) << "block device";
    EXPECT_FALSE(acceptablePayloadSize(S_IFDIR | 0700, 4096).has_value()) << "directory";
    EXPECT_FALSE(acceptablePayloadSize(S_IFLNK | 0777, 12).has_value()) << "symbolic link";
}

// --- readExactly -----------------------------------------------------------

TEST(SealedPayloadInternalTest, ExactFillSucceeds)
{
    const QByteArray payload("twenty-nine bytes of payload!", 29);
    const int fd = makeRegularFileFd(payload);
    ASSERT_GE(fd, 0) << "fixture failed to build a regular file";

    QByteArray out;
    out.resize(payload.size());
    EXPECT_TRUE(readExactly(fd, out.data(), out.size()));
    EXPECT_EQ(out, payload);
    ::close(fd);
}

TEST(SealedPayloadInternalTest, PrematureEndOfFileIsAFailure)
{
    // The file holds 10 bytes; ask for 20. The positional read returns 0 once
    // it reaches the end — exactly what a writer truncating the file between
    // the size query and the read would produce.
    const QByteArray payload("0123456789", 10);
    const int fd = makeRegularFileFd(payload);
    ASSERT_GE(fd, 0) << "fixture failed to build a regular file";

    // Premise: the file really is shorter than the length being demanded.
    struct ::stat st{};
    ASSERT_EQ(::fstat(fd, &st), 0);
    ASSERT_EQ(st.st_size, 10);

    QByteArray out;
    out.resize(20);
    EXPECT_FALSE(readExactly(fd, out.data(), out.size()))
        << "fewer bytes than promised must fail, never be handed up as a truncated success";
    ::close(fd);
}

TEST(SealedPayloadInternalTest, ZeroLengthReadTriviallySucceeds)
{
    const int fd = makeRegularFileFd(QByteArray{});
    ASSERT_GE(fd, 0) << "fixture failed to build a regular file";
    EXPECT_TRUE(readExactly(fd, nullptr, 0)) << "nothing to read is not a failure";
    ::close(fd);
}

TEST(SealedPayloadInternalTest, ReadOnABadDescriptorFails)
{
    QByteArray out;
    out.resize(8);
    EXPECT_FALSE(readExactly(-1, out.data(), out.size())) << "a read error must be reported as failure";
}
