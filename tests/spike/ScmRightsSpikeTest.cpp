// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Spike: prove the raw POSIX SCM_RIGHTS + memfd_create fd-passing mechanics
// on Linux before any transport code exists. The macOS client's AF_UNIX
// transport will pass documents-to-sign and results as file descriptors;
// this is the de-risking exercise ahead of that work.
//
// Deliberately Qt-free: the receive side drives a plain poll() loop.
// QSocketNotifier/QEventLoop integration is a later task, once the client
// transport itself exists — this spike only needs to prove the kernel-level
// mechanics, not the eventual Qt plumbing around them.
//
// Temporary location under tests/spike/: intended to be adopted by the
// client transport tests once that work lands.

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace {

// RAII fd wrapper. Ensures every fd this spike touches — sockets, memfds,
// and fds received over SCM_RIGHTS — is closed exactly once, including on
// early ASSERT_* returns, without relying on manual bookkeeping.
class UniqueFd
{
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : m_fd(fd) {}
    ~UniqueFd()
    {
        reset();
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : m_fd(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    int get() const
    {
        return m_fd;
    }
    bool valid() const
    {
        return m_fd >= 0;
    }

    // Hands ownership to the caller; this wrapper forgets the fd.
    int release()
    {
        const int fd = m_fd;
        m_fd = -1;
        return fd;
    }

    void reset(int fd = -1)
    {
        if (m_fd >= 0) {
            ::close(m_fd);
        }
        m_fd = fd;
    }

private:
    int m_fd = -1;
};

// Creates an anonymous memfd and writes `payload` into it. The receiver
// reads via pread(), so the memfd's file-position offset after this write
// (left at end-of-file) does not matter.
UniqueFd makeMemfdWithPayload(const char* name, const std::string& payload)
{
    UniqueFd fd(::memfd_create(name, 0));
    if (!fd.valid()) {
        return fd;
    }
    const ssize_t written = ::write(fd.get(), payload.data(), payload.size());
    if (written < 0 || static_cast<std::size_t>(written) != payload.size()) {
        return UniqueFd{};
    }
    return fd;
}

// Reads exactly `length` bytes from `fd` at offset 0 via pread — proves the
// fd is a live, independent handle onto the same underlying memfd object
// (not merely a copied integer), because it is read without disturbing (or
// depending on) any shared file-position state.
std::string preadAll(int fd, std::size_t length)
{
    std::string buffer(length, '\0');
    std::size_t total = 0;
    while (total < length) {
        const ssize_t n = ::pread(fd, buffer.data() + total, length - total, static_cast<off_t>(total));
        if (n <= 0) {
            break;
        }
        total += static_cast<std::size_t>(n);
    }
    buffer.resize(total);
    return buffer;
}

// Sends one regular data byte (required alongside SCM_RIGHTS: a cmsg with
// zero-length regular payload is not guaranteed to carry ancillary data on
// every implementation) plus every fd in `fdsToSend`, in a single sendmsg().
bool sendFds(int sock, const std::vector<int>& fdsToSend, char payloadByte)
{
    char data = payloadByte;
    struct iovec iov{};
    iov.iov_base = &data;
    iov.iov_len = 1;

    const std::size_t rightsSize = sizeof(int) * fdsToSend.size();
    std::vector<char> control(CMSG_SPACE(rightsSize));

    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(rightsSize);
    std::memcpy(CMSG_DATA(cmsg), fdsToSend.data(), rightsSize);

    const ssize_t sent = ::sendmsg(sock, &msg, 0);
    return sent == 1;
}

// Drives recvmsg() from a plain poll() loop (no Qt at this spike stage —
// QSocketNotifier/QEventLoop integration is a later task, once the client
// transport exists). Retries across EINTR and spurious wakeups until either
// data arrives or `overallTimeoutMs` elapses, then receives up to `maxFds`
// SCM_RIGHTS file descriptors alongside the >=1 regular byte.
std::vector<UniqueFd> recvFdsViaPoll(int sock, std::size_t maxFds, int overallTimeoutMs = 2000)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(overallTimeoutMs);
    for (;;) {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto remainingMs = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        if (remainingMs <= 0) {
            return {};
        }

        struct pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, static_cast<int>(remainingMs));
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {};
        }
        if (rc == 0) {
            continue; // timed out this iteration; loop re-checks the deadline above
        }
        if (pfd.revents & POLLIN) {
            break;
        }
    }

    char data = 0;
    struct iovec iov{};
    iov.iov_base = &data;
    iov.iov_len = 1;

    const std::size_t rightsSize = sizeof(int) * maxFds;
    std::vector<char> control(CMSG_SPACE(rightsSize));

    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    const ssize_t received = ::recvmsg(sock, &msg, 0);
    if (received != 1) {
        return {};
    }

    std::vector<UniqueFd> result;
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        const std::size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        const int* fds = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        for (std::size_t i = 0; i < count; ++i) {
            result.emplace_back(fds[i]);
        }
    }
    return result;
}

} // namespace

// Step 1+2 of the spike: socketpair, sender writes a known payload into a
// memfd and passes it via sendmsg+SCM_RIGHTS alongside 1 regular byte; the
// receiver drives recvmsg from a poll() loop, extracts the fd, and reads the
// payload back through the RECEIVED fd (not the sender's original fd).
TEST(ScmRightsSpike, SingleFdPassedThroughSocketpairIsReadableAtReceiver)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0) << std::strerror(errno);
    UniqueFd senderSock(fds[0]);
    UniqueFd receiverSock(fds[1]);

    const std::string payload = "SCM_RIGHTS spike payload -- single fd";
    UniqueFd memfd = makeMemfdWithPayload("scm-rights-spike-single", payload);
    ASSERT_TRUE(memfd.valid());

    ASSERT_TRUE(sendFds(senderSock.get(), {memfd.get()}, 'X'));
    // The sender may close its own copy right after sendmsg() returns: the
    // kernel has already duplicated the fd into the receiver's fd table, so
    // the receiver's copy must stay live independent of the sender's.
    memfd.reset();

    std::vector<UniqueFd> received = recvFdsViaPoll(receiverSock.get(), 1);
    ASSERT_EQ(received.size(), 1u);
    ASSERT_TRUE(received[0].valid());

    const std::string readBack = preadAll(received[0].get(), payload.size());
    EXPECT_EQ(readBack, payload);

    // Explicit close with an error check, proving cleanup actually happens
    // (RAII would otherwise close silently at scope exit).
    const int fdToClose = received[0].release();
    EXPECT_EQ(::close(fdToClose), 0) << std::strerror(errno);
    // A closed fd must be rejected by the kernel from here on -- confirms
    // the close() above genuinely released the descriptor rather than the
    // check being a no-op against a fd number that was never valid.
    EXPECT_EQ(::fcntl(fdToClose, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

// Step 3 (part 1): two fds carried in a single cmsg (multiple SCM_RIGHTS
// payload), each backed by a distinct memfd with distinct content, both
// recovered intact and as distinct descriptor numbers.
TEST(ScmRightsSpike, TwoFdsInOneCmsgAreBothReceivedIntact)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0) << std::strerror(errno);
    UniqueFd senderSock(fds[0]);
    UniqueFd receiverSock(fds[1]);

    const std::string payloadA = "first memfd payload";
    const std::string payloadB = "second memfd payload, different length!";
    UniqueFd memfdA = makeMemfdWithPayload("scm-rights-spike-a", payloadA);
    UniqueFd memfdB = makeMemfdWithPayload("scm-rights-spike-b", payloadB);
    ASSERT_TRUE(memfdA.valid());
    ASSERT_TRUE(memfdB.valid());

    ASSERT_TRUE(sendFds(senderSock.get(), {memfdA.get(), memfdB.get()}, 'Y'));
    memfdA.reset();
    memfdB.reset();

    std::vector<UniqueFd> received = recvFdsViaPoll(receiverSock.get(), 2);
    ASSERT_EQ(received.size(), 2u);
    ASSERT_TRUE(received[0].valid());
    ASSERT_TRUE(received[1].valid());
    EXPECT_NE(received[0].get(), received[1].get());

    EXPECT_EQ(preadAll(received[0].get(), payloadA.size()), payloadA);
    EXPECT_EQ(preadAll(received[1].get(), payloadB.size()), payloadB);

    // Explicit cleanup with error checks for both received fds.
    const int fdA = received[0].release();
    const int fdB = received[1].release();
    EXPECT_EQ(::close(fdA), 0) << std::strerror(errno);
    EXPECT_EQ(::close(fdB), 0) << std::strerror(errno);
}

// Step 3 (part 2): the poll() loop must not spuriously report readability
// when nothing was sent -- it should genuinely wait, then time out empty.
// This guards against a loop that (mis-)reports success unconditionally.
TEST(ScmRightsSpike, PollLoopTimesOutWhenNoMessageIsSent)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0) << std::strerror(errno);
    UniqueFd senderSock(fds[0]);
    UniqueFd receiverSock(fds[1]);
    (void)senderSock; // kept open: an EOF-closed peer would also make poll() return readable

    std::vector<UniqueFd> received = recvFdsViaPoll(receiverSock.get(), 1, /*overallTimeoutMs=*/150);
    EXPECT_TRUE(received.empty());
}
