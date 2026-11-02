// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The fd guard every host reads a client's document or master list through.
#include <LibreSCRS/Agent/util/TempDir.h>
#include <LibreSCRS/Agent/wire/BoundedFdRead.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

using LibreSCRS::Agent::Wire::kMaxInputBytes;
using LibreSCRS::Agent::Wire::readBoundedRegularFd;
using LibreSCRS::Agent::Wire::ReadStatus;

// An unlinked regular file holding @p size bytes (0, 1, 2, ...), rewound.
class RegularFile
{
public:
    explicit RegularFile(std::size_t size)
    {
        auto path = LibreSCRS::Agent::tempFileTemplate("bounded-read-");
        m_fd = ::mkstemp(path.data());
        if (m_fd < 0) {
            return;
        }
        ::unlink(path.data());
        std::vector<std::uint8_t> bytes(size);
        for (std::size_t i = 0; i < size; ++i) {
            bytes[i] = static_cast<std::uint8_t>(i);
        }
        if (size != 0 && ::write(m_fd, bytes.data(), size) != static_cast<ssize_t>(size)) {
            ::close(m_fd);
            m_fd = -1;
            return;
        }
        ::lseek(m_fd, 0, SEEK_SET);
    }
    ~RegularFile()
    {
        if (m_fd >= 0) {
            ::close(m_fd);
        }
    }
    RegularFile(const RegularFile&) = delete;
    RegularFile& operator=(const RegularFile&) = delete;
    [[nodiscard]] int fd() const
    {
        return m_fd;
    }

private:
    int m_fd{-1};
};

TEST(BoundedFdRead, TheCapIsTheDocumentLimitTheHostsAdvertise)
{
    EXPECT_EQ(kMaxInputBytes, 256ull * 1024 * 1024);
}

TEST(BoundedFdRead, ARegularFileUpToTheCapIsReadWhole)
{
    // Larger than the read chunk, so the loop runs more than once.
    constexpr std::size_t kSize = 64 * 1024 + 17;
    RegularFile file(kSize);
    ASSERT_GE(file.fd(), 0);
    const auto r = readBoundedRegularFd(file.fd(), kSize);
    ASSERT_EQ(r.status, ReadStatus::Ok);
    ASSERT_EQ(r.bytes.size(), kSize);
    EXPECT_EQ(r.bytes[1], 1);
    EXPECT_EQ(r.bytes[kSize - 1], static_cast<std::uint8_t>(kSize - 1));
}

TEST(BoundedFdRead, AnEmptyFileIsAnEmptyDocumentNotAnError)
{
    RegularFile file(0);
    ASSERT_GE(file.fd(), 0);
    const auto r = readBoundedRegularFd(file.fd(), 16);
    EXPECT_EQ(r.status, ReadStatus::Ok);
    EXPECT_TRUE(r.bytes.empty());
}

TEST(BoundedFdRead, OneByteOverTheCapIsRefusedAndReturnsNothing)
{
    RegularFile file(101);
    ASSERT_GE(file.fd(), 0);
    const auto r = readBoundedRegularFd(file.fd(), 100);
    EXPECT_EQ(r.status, ReadStatus::TooLarge);
    EXPECT_TRUE(r.bytes.empty());
}

TEST(BoundedFdRead, APipeIsRefusedBeforeAnyRead)
{
    int fds[2] = {-1, -1};
    ASSERT_EQ(::pipe(fds), 0);
    // A finished writer: were the pipe read, it would end cleanly at EOF and
    // come back Ok, so only the up-front refusal can produce NotRegular.
    ASSERT_EQ(::write(fds[1], "abc", 3), 3);
    ::close(fds[1]);
    const auto r = readBoundedRegularFd(fds[0], 100);
    EXPECT_EQ(r.status, ReadStatus::NotRegular);
    EXPECT_TRUE(r.bytes.empty());
    char left[4] = {};
    EXPECT_EQ(::read(fds[0], left, sizeof left), 3) << "the guard consumed bytes from a pipe";
    ::close(fds[0]);
}

TEST(BoundedFdRead, ASocketIsRefused)
{
    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    // Non-blocking, so a guard that let the socket through fails here with
    // EAGAIN instead of hanging this test the way it would hang the agent.
    ASSERT_EQ(::fcntl(fds[0], F_SETFL, ::fcntl(fds[0], F_GETFL) | O_NONBLOCK), 0);
    const auto r = readBoundedRegularFd(fds[0], 100);
    EXPECT_EQ(r.status, ReadStatus::NotRegular);
    ::close(fds[0]);
    ::close(fds[1]);
}

TEST(BoundedFdRead, NoDescriptorAndAClosedOneAreErrors)
{
    EXPECT_EQ(readBoundedRegularFd(-1, 100).status, ReadStatus::Error);
    int fds[2] = {-1, -1};
    ASSERT_EQ(::pipe(fds), 0);
    ::close(fds[0]);
    ::close(fds[1]);
    EXPECT_EQ(readBoundedRegularFd(fds[0], 100).status, ReadStatus::Error);
}

TEST(BoundedFdRead, AWriteOnlyFileIsAnErrorNotAnEmptyDocument)
{
    auto path = LibreSCRS::Agent::tempFileTemplate("bounded-read-");
    const int created = ::mkstemp(path.data());
    ASSERT_GE(created, 0);
    ASSERT_EQ(::write(created, "xyz", 3), 3);
    ::close(created);
    const int wo = ::open(path.data(), O_WRONLY);
    ::unlink(path.data());
    ASSERT_GE(wo, 0);
    const auto r = readBoundedRegularFd(wo, 100);
    EXPECT_EQ(r.status, ReadStatus::Error);
    ::close(wo);
}

} // namespace
