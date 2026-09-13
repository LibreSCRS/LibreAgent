// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Non-blocking streaming frame reassembly. pump() drains a readable socket into
// an accumulation buffer + an fd FIFO, then extracts complete frames, giving each
// exactly its header-declared fd count (D-Bus UNIX_FDS model). Fail-closed on any
// limit violation; every received fd gets FD_CLOEXEC before it is owned.
#include <LibreSCRS/Agent/wire/FrameReassembler.h>

#include "FdHarvest.h"

#include <array>
#include <cerrno>
#include <utility>

namespace LibreSCRS::Agent::Wire {
namespace {
std::uint32_t getU32Le(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

// The fd FIFO holds at most one pending frame plus one incoming frame's worth of
// descriptors; beyond that a peer is flooding fds without completing frames.
constexpr std::size_t kMaxPendingFds = 2 * kMaxFrameFds;

// The buffer holds at most one in-flight frame (header + body); anything larger
// is a malformed / oversize stream.
constexpr std::size_t kMaxBufferBytes = kFrameHeaderBytes + kMaxFrameBytes;
} // namespace

PumpResult FrameReassembler::pump(int fd)
{
    PumpResult out;

    for (;;) {
        std::array<std::uint8_t, 4096> chunk{};

        // The read and the harvest are one operation, and it lives in
        // FdHarvest.h: the descriptor count comes from what the kernel
        // delivered, never from what the peer claimed.
        FdRecvResult got = receiveWithFds(fd, chunk.data(), chunk.size());
        if (got.bytes == 0) {
            out.status = PumpStatus::PeerClosed;
            break;
        }
        if (got.bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; // drained for now
            }
            out.status = PumpStatus::Error;
            out.error = FrameError::Io;
            break;
        }

        // Take ownership before the truncation verdict below: the descriptors
        // that DID arrive are open in this process either way, and the FIFO is
        // what closes them.
        for (UniqueFd& harvested : got.fds) {
            m_fds.push_back(std::move(harvested));
        }
        if (got.ancillaryTruncated) {
            out.status = PumpStatus::Error;
            out.error = FrameError::Io;
            break;
        }
        if (m_fds.size() > kMaxPendingFds) {
            out.status = PumpStatus::Error;
            out.error = FrameError::TooManyFds;
            break;
        }

        m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.begin() + got.bytes);
        if (m_buffer.size() > kMaxBufferBytes) {
            out.status = PumpStatus::Error;
            out.error = FrameError::Oversize;
            break;
        }
    }

    // Extract complete frames regardless of why the read loop ended (a clean EOF
    // may still leave fully-buffered frames to deliver before the close).
    if (out.status != PumpStatus::Error) {
        extract(out);
    }
    return out;
}

void FrameReassembler::extract(PumpResult& out)
{
    std::size_t pos = 0;
    while (m_buffer.size() - pos >= kFrameHeaderBytes) {
        const std::uint8_t* h = m_buffer.data() + pos;
        const std::uint32_t bodyLen = getU32Le(h);
        const std::uint32_t fdCount = getU32Le(h + sizeof(std::uint32_t));

        if (bodyLen > kMaxFrameBytes) {
            out.status = PumpStatus::Error;
            out.error = FrameError::Oversize;
            break;
        }
        if (fdCount > kMaxFrameFds) {
            out.status = PumpStatus::Error;
            out.error = FrameError::TooManyFds;
            break;
        }
        if (m_buffer.size() - pos < kFrameHeaderBytes + bodyLen) {
            break; // body not fully arrived yet
        }
        // The frame's bytes are all here; its fds (attached to the first byte)
        // must therefore already be in the FIFO.
        if (m_fds.size() < fdCount) {
            out.status = PumpStatus::Error;
            out.error = FrameError::FdMismatch;
            break;
        }

        Frame f;
        const std::uint8_t* bodyStart = h + kFrameHeaderBytes;
        f.body.assign(bodyStart, bodyStart + bodyLen);
        for (std::uint32_t i = 0; i < fdCount; ++i) {
            f.fds.push_back(std::move(m_fds.front()));
            m_fds.pop_front();
        }
        out.frames.push_back(std::move(f));
        pos += kFrameHeaderBytes + bodyLen;
    }
    if (pos > 0) {
        m_buffer.erase(m_buffer.begin(), m_buffer.begin() + static_cast<std::ptrdiff_t>(pos));
    }
}

} // namespace LibreSCRS::Agent::Wire
