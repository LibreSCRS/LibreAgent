// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The non-blocking streaming reassembler: partial frames across pumps, multiple
// frames in one read, fd-bearing frames (FD_CLOEXEC + correct attribution),
// clean EOF, and fail-closed on oversize / fd-count violations. Driven over a
// non-blocking socketpair.
#include <LibreSCRS/Agent/wire/FrameReassembler.h>
#include <LibreSCRS/Agent/wire/Framing.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace LibreSCRS::Agent::Wire;

namespace {

struct NbSocketPair
{
    int fds[2]{-1, -1};
    NbSocketPair()
    {
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        // Reader end non-blocking (the reassembler expects EAGAIN when drained).
        ::fcntl(fds[1], F_SETFL, ::fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    }
    ~NbSocketPair()
    {
        if (fds[0] >= 0) {
            ::close(fds[0]);
        }
        if (fds[1] >= 0) {
            ::close(fds[1]);
        }
    }
    int writer() const
    {
        return fds[0];
    }
    int reader() const
    {
        return fds[1];
    }
};

std::vector<std::uint8_t> body(std::initializer_list<std::uint8_t> b)
{
    return std::vector<std::uint8_t>(b);
}

TEST(FrameReassembler, SingleFrameInOneRead)
{
    NbSocketPair sp;
    const auto framed = encodeFrame(body({1, 2, 3}), 0);
    ASSERT_EQ(::write(sp.writer(), framed.data(), framed.size()), static_cast<ssize_t>(framed.size()));

    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Ok);
    ASSERT_EQ(r.frames.size(), 1u);
    EXPECT_EQ(r.frames[0].body, body({1, 2, 3}));
    EXPECT_TRUE(r.frames[0].fds.empty());
}

TEST(FrameReassembler, TwoFramesInOneRead)
{
    NbSocketPair sp;
    auto a = encodeFrame(body({0xAA}), 0);
    const auto b = encodeFrame(body({0xBB, 0xCC}), 0);
    a.insert(a.end(), b.begin(), b.end());
    ASSERT_EQ(::write(sp.writer(), a.data(), a.size()), static_cast<ssize_t>(a.size()));

    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    ASSERT_EQ(r.frames.size(), 2u);
    EXPECT_EQ(r.frames[0].body, body({0xAA}));
    EXPECT_EQ(r.frames[1].body, body({0xBB, 0xCC}));
}

TEST(FrameReassembler, PartialFrameAcrossPumps)
{
    NbSocketPair sp;
    const auto framed = encodeFrame(body({9, 8, 7, 6}), 0);
    // Write the header + first body byte, pump (incomplete), then the rest.
    ASSERT_EQ(::write(sp.writer(), framed.data(), kFrameHeaderBytes + 1), static_cast<ssize_t>(kFrameHeaderBytes + 1));

    FrameReassembler ra;
    auto r1 = ra.pump(sp.reader());
    EXPECT_EQ(r1.status, PumpStatus::Ok);
    EXPECT_TRUE(r1.frames.empty()); // not complete yet

    ASSERT_EQ(::write(sp.writer(), framed.data() + kFrameHeaderBytes + 1, framed.size() - kFrameHeaderBytes - 1),
              static_cast<ssize_t>(framed.size() - kFrameHeaderBytes - 1));
    auto r2 = ra.pump(sp.reader());
    ASSERT_EQ(r2.frames.size(), 1u);
    EXPECT_EQ(r2.frames[0].body, body({9, 8, 7, 6}));
}

TEST(FrameReassembler, FdBearingFrameAttributesFdWithCloexec)
{
    NbSocketPair sp;
    int pipefd[2]{-1, -1};
    ASSERT_EQ(::pipe(pipefd), 0);
    // Send one frame declaring 1 fd, with the pipe read end over SCM_RIGHTS.
    const std::array<int, 1> pass{pipefd[0]};
    ASSERT_TRUE(sendFrame(sp.writer(), body({0x42}), pass).has_value());

    FrameReassembler ra;
    auto r = ra.pump(sp.reader());
    ASSERT_EQ(r.frames.size(), 1u);
    ASSERT_EQ(r.frames[0].fds.size(), 1u);
    const int got = r.frames[0].fds[0].get();
    EXPECT_TRUE(::fcntl(got, F_GETFD) & FD_CLOEXEC);

    // The received fd is a working dup of the pipe read end.
    const char payload = 'Q';
    ASSERT_EQ(::write(pipefd[1], &payload, 1), 1);
    char c = 0;
    ASSERT_EQ(::read(got, &c, 1), 1);
    EXPECT_EQ(c, 'Q');
    ::close(pipefd[0]);
    ::close(pipefd[1]);
}

TEST(FrameReassembler, PeerClosedReported)
{
    NbSocketPair sp;
    ::close(sp.fds[0]); // writer gone
    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::PeerClosed);
    EXPECT_TRUE(r.frames.empty());
}

TEST(FrameReassembler, OversizeBodyFailsClosed)
{
    NbSocketPair sp;
    // A header declaring a body larger than the cap, no body bytes.
    const std::uint32_t huge = static_cast<std::uint32_t>(kMaxFrameBytes) + 1;
    std::array<std::uint8_t, kFrameHeaderBytes> hdr{static_cast<std::uint8_t>(huge & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 8) & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 16) & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 24) & 0xFF),
                                                    0,
                                                    0,
                                                    0,
                                                    0};
    ASSERT_EQ(::write(sp.writer(), hdr.data(), hdr.size()), static_cast<ssize_t>(hdr.size()));
    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Error);
    EXPECT_EQ(r.error, FrameError::Oversize);
}

TEST(FrameReassembler, DeclaredFdCountWithoutFdsFailsClosed)
{
    NbSocketPair sp;
    // Header declares 1 fd but the frame is written with no SCM_RIGHTS ancillary.
    const auto framed = encodeFrame(body({0x00}), 1);
    ASSERT_EQ(::write(sp.writer(), framed.data(), framed.size()), static_cast<ssize_t>(framed.size()));
    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Error);
    EXPECT_EQ(r.error, FrameError::FdMismatch);
}

// The twin has this test (FramingTest.cpp) and the twin is the reason the clamp
// exists: ASan reported a stack-buffer-overflow from that very test while the
// frame still failed closed -- the overrun happens on the way there. pump() had
// no such test, so the same overrun rode into the Qt client library unseen.
//
// On Linux this passes with or without the clamp (scm_detach_fds rewrites
// cmsg_len to what it delivered), so it is NOT the Linux gate --
// ci/scripts/check-fd-harvest.sh is. Its job is the wire ASan leg on macOS,
// which already builds and runs this binary under -fsanitize=address: there the
// kernel leaves cmsg_len saying 32 descriptors while delivering 16, and the
// unclamped loop walks 64 bytes past `control`.
TEST(FrameReassembler, ControlMessageTruncatedFailsClosed)
{
    NbSocketPair sp;
    int pipefd[2]{-1, -1};
    ASSERT_EQ(::pipe(pipefd), 0);

    constexpr std::size_t kOverflowCount = kMaxFrameFds * 2;
    const std::vector<int> manyFds(kOverflowCount, pipefd[0]);
    const auto framed = encodeFrame(body({0x01}), static_cast<std::uint32_t>(kMaxFrameFds));

    iovec iov{};
    iov.iov_base = const_cast<std::uint8_t*>(framed.data());
    iov.iov_len = framed.size();

    const std::size_t ctrlBytes = sizeof(int) * kOverflowCount;
    std::vector<std::uint8_t> control(CMSG_SPACE(ctrlBytes));
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = static_cast<socklen_t>(control.size());
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(c, nullptr);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(ctrlBytes);
    std::memcpy(CMSG_DATA(c), manyFds.data(), ctrlBytes);

    ASSERT_GE(::sendmsg(sp.writer(), &msg, 0), 0);

    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Error);
    EXPECT_EQ(r.error, FrameError::Io);

    ::close(pipefd[0]);
    ::close(pipefd[1]);
}

} // namespace
