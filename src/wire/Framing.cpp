// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Socket framing: uint32-LE-length-prefixed CBOR bodies + SCM_RIGHTS fd-passing.
// FD_CLOEXEC is set on each received fd via fcntl (no MSG_CMSG_CLOEXEC on
// macOS). The body length is capped before allocation; the ancillary fd count
// is capped. Fail-closed on any short/oversize/malformed input.
#include <algorithm>
#include <LibreSCRS/Agent/wire/Framing.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>

namespace LibreSCRS::Agent::Wire {
namespace {

// Read exactly n bytes into dst, harvesting any SCM_RIGHTS fds delivered along
// the way (into outFds, with FD_CLOEXEC set). Returns false on EOF/error; sets
// `err` to the specific FrameError on error (PeerClosed on clean EOF).
bool recvExact(int fd, std::uint8_t* dst, std::size_t n, std::vector<UniqueFd>& outFds, FrameError& err)
{
    std::size_t got = 0;
    while (got < n) {
        iovec iov{};
        iov.iov_base = dst + got;
        iov.iov_len = n - got;

        // Ancillary buffer sized for kMaxFrameFds descriptors. alignas(cmsghdr)
        // so CMSG_FIRSTHDR/CMSG_NXTHDR's aligned struct-cmsghdr reads are defined.
        alignas(struct cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int) * kMaxFrameFds)> control{};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = static_cast<socklen_t>(control.size());

        const ssize_t r = ::recvmsg(fd, &msg, 0);
        if (r == 0) {
            err = FrameError::PeerClosed; // clean EOF
            return false;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            // A non-blocking socket with no data ready: not an I/O failure. This
            // API is for BLOCKING sockets (see Framing.h); the signal lets a
            // misused non-blocking caller distinguish rather than tear down.
            err = (errno == EAGAIN || errno == EWOULDBLOCK) ? FrameError::WouldBlock : FrameError::Io;
            return false;
        }

        // Harvest any passed fds; set FD_CLOEXEC on each (macOS has no
        // MSG_CMSG_CLOEXEC). Close anything beyond the cap.
        //
        // cmsg_len describes what the SENDER attached, and on a truncated
        // control message it keeps saying so after the kernel has delivered
        // less. Trusting it walks off the end of `control`, which is on the
        // stack -- and the descriptors read out of that overrun get an fcntl
        // each. The MSG_CTRUNC check below is too late to prevent any of it.
        //
        // So every count here comes from what was actually delivered: the
        // recvmsg-updated msg_controllen, clamped, with the subtraction guarded
        // because cmsg_len is peer-influenced and a value below CMSG_LEN(0)
        // would wrap to an enormous size_t. Harvesting still happens on a
        // truncated message rather than being skipped: the descriptors that DID
        // arrive are open in this process, and putting them in outFds is what
        // closes them -- UniqueFd owns them, and the caller drops the vector
        // when this returns false.
        const auto* const controlEnd = static_cast<const std::uint8_t*>(msg.msg_control) + msg.msg_controllen;
        for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) {
                continue;
            }
            if (c->cmsg_len < CMSG_LEN(0)) {
                continue; // malformed header: the subtraction below would wrap
            }
            const auto* const data = static_cast<const std::uint8_t*>(CMSG_DATA(c));
            if (data > controlEnd) {
                continue; // header sits outside what was delivered
            }
            const std::size_t claimed = c->cmsg_len - CMSG_LEN(0);
            const auto delivered = static_cast<std::size_t>(controlEnd - data);
            const std::size_t payload = std::min(claimed, delivered);
            const std::size_t count = payload / sizeof(int);
            const auto* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
            for (std::size_t i = 0; i < count; ++i) {
                ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
                if (outFds.size() < kMaxFrameFds) {
                    outFds.emplace_back(fds[i]);
                } else {
                    ::close(fds[i]); // over the cap: drop it closed
                }
            }
        }
        if (msg.msg_flags & MSG_CTRUNC) {
            err = FrameError::Io; // ancillary was truncated — treat as a protocol error
            return false;
        }
        got += static_cast<std::size_t>(r);
    }
    return true;
}

} // namespace

namespace {
// EPIPE, not SIGPIPE: a peer that vanished between the caller's liveness
// check and this send must surface as FrameError::Io (the transports map it
// to a failed call — CallError::AgentUnavailable), never as a
// process-killing signal. Linux spells that MSG_NOSIGNAL per send; on
// platforms without MSG_NOSIGNAL (Darwin) the connecting side sets
// SO_NOSIGPIPE on the socket instead (SocketTransport::connectAndHandshake).
#ifdef MSG_NOSIGNAL
inline constexpr int kSendNoSigPipe = MSG_NOSIGNAL;
#else
inline constexpr int kSendNoSigPipe = 0;
#endif

void putU32Le(std::vector<std::uint8_t>& out, std::uint32_t v)
{
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}
std::uint32_t getU32Le(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
} // namespace

std::vector<std::uint8_t> encodeFrame(std::span<const std::uint8_t> body, std::uint32_t fdCount)
{
    std::vector<std::uint8_t> out;
    out.reserve(kFrameHeaderBytes + body.size());
    putU32Le(out, static_cast<std::uint32_t>(body.size()));
    putU32Le(out, fdCount);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

std::expected<void, FrameError> sendFrame(int fd, std::span<const std::uint8_t> body, std::span<const int> passFds)
{
    if (body.size() > kMaxFrameBytes) {
        return std::unexpected(FrameError::Oversize); // symmetric with recvFrame
    }
    if (passFds.size() > kMaxFrameFds) {
        return std::unexpected(FrameError::TooManyFds);
    }
    const std::vector<std::uint8_t> framed = encodeFrame(body, static_cast<std::uint32_t>(passFds.size()));

    iovec iov{};
    iov.iov_base = const_cast<std::uint8_t*>(framed.data());
    iov.iov_len = framed.size();

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

    std::size_t sent = 0;
    bool ancillarySent = false;
    // The ancillary rides the FIRST sendmsg (SCM_RIGHTS is delivered with the
    // first byte on a stream socket); the remainder goes as plain writes so the
    // fds are never re-transmitted, even on a partial first send.
    while (sent < framed.size()) {
        if (!ancillarySent) {
            const ssize_t w = ::sendmsg(fd, &msg, kSendNoSigPipe);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(FrameError::Io);
            }
            ancillarySent = true;
            sent += static_cast<std::size_t>(w);
        } else {
            // ::send, not ::write: the remainder must carry the same
            // no-SIGPIPE flag as the first sendmsg (see kSendNoSigPipe).
            const ssize_t w = ::send(fd, framed.data() + sent, framed.size() - sent, kSendNoSigPipe);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(FrameError::Io);
            }
            sent += static_cast<std::size_t>(w);
        }
    }
    return {};
}

std::expected<Frame, FrameError> recvFrame(int fd)
{
    Frame frame;
    FrameError err = FrameError::Io;

    std::array<std::uint8_t, kFrameHeaderBytes> header{};
    if (!recvExact(fd, header.data(), header.size(), frame.fds, err)) {
        return std::unexpected(err);
    }
    const std::uint32_t len = getU32Le(header.data());
    const std::uint32_t fdCount = getU32Le(header.data() + sizeof(std::uint32_t));
    if (len > kMaxFrameBytes) {
        return std::unexpected(FrameError::Oversize);
    }
    if (fdCount > kMaxFrameFds) {
        return std::unexpected(FrameError::TooManyFds);
    }

    frame.body.resize(len);
    if (len > 0 && !recvExact(fd, frame.body.data(), len, frame.fds, err)) {
        return std::unexpected(err);
    }
    // Every declared fd must have arrived over SCM_RIGHTS with the frame's bytes.
    if (frame.fds.size() != fdCount) {
        return std::unexpected(FrameError::FdMismatch);
    }
    return frame;
}

} // namespace LibreSCRS::Agent::Wire
