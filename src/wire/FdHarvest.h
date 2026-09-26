// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The whole SCM_RIGHTS surface of the wire component: the recvmsg that harvests
// descriptors, the clamp that decides how many of them really arrived, and the
// sendmsg that attaches them. Nothing else in the production sources builds a
// msghdr, walks a cmsghdr or names an ancillary macro -- ci/scripts/
// check-fd-harvest.sh measures exactly that, so a second harvest cannot be
// written anywhere but here.
//
// Internal to the wire target: not under include/, so not installed, and inline,
// so it emits no T-binding symbol into libLibreAgentWire.a.
#pragma once

#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace LibreSCRS::Agent::Wire {

// EPIPE, not SIGPIPE: a peer that vanished between the caller's liveness check
// and a send must surface as FrameError::Io (the transports map it to a failed
// call -- CallError::AgentUnavailable), never as a process-killing signal. Linux
// spells that MSG_NOSIGNAL per send; on platforms without it (Darwin) the
// connecting side sets SO_NOSIGPIPE on the socket instead
// (SocketTransport::connectAndHandshake). The plain send() that carries the
// remainder of a frame uses the same flag, which is why it lives here.
#ifdef MSG_NOSIGNAL
inline constexpr int kSendNoSigPipe = MSG_NOSIGNAL;
#else
inline constexpr int kSendNoSigPipe = 0;
#endif

// How many SCM_RIGHTS payload BYTES of `c` actually arrived, given what recvmsg
// reported in `msg`.
//
// cmsg_len describes what the SENDER attached. On a truncated control message
// XNU keeps reporting that number while msg_controllen shrinks to what was
// really delivered: copyout_control() (bsd/kern/uipc_syscalls.c) copies the
// cmsg header out verbatim and corrects only *controllen. Linux does the
// opposite -- scm_detach_fds rewrites cmsg_len to what it delivered -- which is
// why no Linux run can see the difference and why the clamp cannot be dropped
// on the grounds that "it never fires here".
//
// The peer-supplied length is read once, into `claimed`, and everything after
// that is arithmetic on a local. Two guards, both load-bearing:
//   * a length below CMSG_LEN(0) would make the subtraction wrap to an enormous
//     size_t;
//   * a header sitting outside what was delivered has zero payload, not a
//     negative one.
// The result is min(claimed, delivered), so a caller may divide it by
// sizeof(int) and index that many descriptors without leaving the buffer.
[[nodiscard]] inline std::size_t deliveredFdBytes(const msghdr& msg, const cmsghdr* c) noexcept
{
    if (c == nullptr || msg.msg_control == nullptr) {
        return 0;
    }
    const std::size_t claimed = c->cmsg_len;
    if (claimed < CMSG_LEN(0)) {
        return 0; // malformed header: the subtraction below would wrap
    }
    const auto* const controlEnd = static_cast<const std::uint8_t*>(msg.msg_control) + msg.msg_controllen;
    const auto* const data = static_cast<const std::uint8_t*>(CMSG_DATA(const_cast<cmsghdr*>(c)));
    if (data > controlEnd) {
        return 0; // the header sits outside what was delivered
    }
    const auto delivered = static_cast<std::size_t>(controlEnd - data);
    return std::min(claimed - CMSG_LEN(0), delivered);
}

// What one recvmsg produced.
struct FdRecvResult
{
    // recvmsg's own return value: >0 bytes read, 0 a clean EOF, <0 an error with
    // errno still set (nothing between the syscall and the return touches it).
    ssize_t bytes{-1};
    // The kernel could not deliver all of the ancillary data. Checked by the
    // callers AFTER they take `fds`: the descriptors that did arrive are already
    // open in this process, and owning them is what closes them.
    bool ancillaryTruncated{false};
    // The harvested descriptors, FD_CLOEXEC already set on each (macOS has no
    // MSG_CMSG_CLOEXEC), and the count clamped to what was delivered.
    std::vector<UniqueFd> fds;
};

// Read up to `n` bytes into `dst`, harvesting any SCM_RIGHTS descriptors that
// arrive with them.
//
// The ancillary buffer is sized for kMaxFrameFds descriptors and lives for the
// duration of this call, so no caller can hold a pointer into it. The count of
// descriptors read out of it is deliveredFdBytes()'s answer, never the peer's:
// the MSG_CTRUNC check a caller performs afterwards is too late on its own, as
// by then every descriptor read out of an overrun would already have an fcntl()
// and an owner.
[[nodiscard]] inline FdRecvResult receiveWithFds(int fd, void* dst, std::size_t n)
{
    FdRecvResult out;

    iovec iov{};
    iov.iov_base = dst;
    iov.iov_len = n;

    alignas(struct cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int) * kMaxFrameFds)> control{};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = static_cast<socklen_t>(control.size());

    out.bytes = ::recvmsg(fd, &msg, 0);
    if (out.bytes <= 0) {
        return out; // an error (errno) or a clean EOF: nothing was attached
    }

    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        const std::size_t count = deliveredFdBytes(msg, c) / sizeof(int);
        const auto* const fds = reinterpret_cast<const int*>(CMSG_DATA(c));
        for (std::size_t i = 0; i < count; ++i) {
            ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
            out.fds.emplace_back(fds[i]);
        }
    }
    out.ancillaryTruncated = (msg.msg_flags & MSG_CTRUNC) != 0;
    return out;
}

// Send `len` bytes from `data` with `passFds` attached as one SCM_RIGHTS
// message. Returns sendmsg's own value; on a negative return errno is still the
// syscall's. The caller keeps ownership of the descriptors -- SCM_RIGHTS
// duplicates them into the peer.
//
// More descriptors than the ancillary buffer holds is a programming error, not a
// wire condition, and it fails closed here rather than writing past the buffer:
// the one caller caps at kMaxFrameFds before this is reached.
[[nodiscard]] inline ssize_t sendWithFds(int fd, const void* data, std::size_t len, std::span<const int> passFds)
{
    if (passFds.size() > kMaxFrameFds) {
        errno = EINVAL;
        return -1;
    }

    iovec iov{};
    iov.iov_base = const_cast<void*>(data);
    iov.iov_len = len;

    alignas(struct cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int) * kMaxFrameFds)> control{};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (!passFds.empty()) {
        const std::size_t bytes = sizeof(int) * passFds.size();
        msg.msg_control = control.data();
        msg.msg_controllen = CMSG_SPACE(bytes);
        cmsghdr* c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(bytes);
        std::memcpy(CMSG_DATA(c), passFds.data(), bytes);
    }
    return ::sendmsg(fd, &msg, kSendNoSigPipe);
}

} // namespace LibreSCRS::Agent::Wire
