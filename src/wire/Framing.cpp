// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Socket framing: uint32-LE-length-prefixed CBOR bodies + SCM_RIGHTS fd-passing.
// The ancillary side of both directions -- the recvmsg that harvests the
// descriptors with FD_CLOEXEC on each, and the sendmsg that attaches them --
// lives in FdHarvest.h. The body length is capped before allocation; the
// ancillary fd count is capped. Fail-closed on any short/oversize/malformed
// input.
#include <LibreSCRS/Agent/wire/Framing.h>

#include "FdHarvest.h"

#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <utility>

namespace LibreSCRS::Agent::Wire {
namespace {

// Read exactly n bytes into dst, harvesting any SCM_RIGHTS fds delivered along
// the way (into outFds, with FD_CLOEXEC set). Returns false on EOF/error; sets
// `err` to the specific FrameError on error (PeerClosed on clean EOF).
bool recvExact(int fd, std::uint8_t* dst, std::size_t n, std::vector<UniqueFd>& outFds, FrameError& err)
{
    std::size_t got = 0;
    while (got < n) {
        // The read and the harvest are one operation and live in FdHarvest.h,
        // which is also where the count of descriptors is clamped to what the
        // kernel actually delivered rather than to what the sender claimed.
        FdRecvResult r = receiveWithFds(fd, dst + got, n - got);
        if (r.bytes == 0) {
            err = FrameError::PeerClosed; // clean EOF
            return false;
        }
        if (r.bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            // A non-blocking socket with no data ready: not an I/O failure. This
            // API is for BLOCKING sockets (see Framing.h); the signal lets a
            // misused non-blocking caller distinguish rather than tear down.
            err = (errno == EAGAIN || errno == EWOULDBLOCK) ? FrameError::WouldBlock : FrameError::Io;
            return false;
        }

        // Anything beyond the cap is dropped CLOSED: the harvest owns every
        // descriptor it produced, so one left behind here is closed when this
        // result goes out of scope. Harvesting still happens on a truncated
        // message rather than being skipped -- the descriptors that DID arrive
        // are open in this process, and putting them in outFds is what closes
        // them, since the caller drops the vector when this returns false.
        for (UniqueFd& harvested : r.fds) {
            if (outFds.size() < kMaxFrameFds) {
                outFds.push_back(std::move(harvested));
            }
        }
        if (r.ancillaryTruncated) {
            err = FrameError::Io; // ancillary was truncated — treat as a protocol error
            return false;
        }
        got += static_cast<std::size_t>(r.bytes);
    }
    return true;
}

} // namespace

namespace {
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

    std::size_t sent = 0;
    bool ancillarySent = false;
    // The ancillary rides the FIRST send (SCM_RIGHTS is delivered with the first
    // byte on a stream socket); the remainder goes as plain writes so the fds are
    // never re-transmitted, even on a partial first send. Attaching them is
    // FdHarvest.h's job, for the same reason harvesting them is.
    while (sent < framed.size()) {
        if (!ancillarySent) {
            const ssize_t w = sendWithFds(fd, framed.data(), framed.size(), passFds);
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
            // no-SIGPIPE flag as the ancillary-bearing first send (see
            // kSendNoSigPipe in FdHarvest.h).
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
