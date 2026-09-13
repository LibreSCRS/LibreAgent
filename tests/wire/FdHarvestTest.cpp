// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The SCM_RIGHTS length clamp itself, measured directly.
//
// The two harvest loops that call deliveredFdBytes() are exercised over a real
// socketpair, and on Linux that can never see the defect this helper exists to
// stop: scm_detach_fds rewrites cmsg_len down to what it actually delivered, so
// the clamped and the unclamped computation return the same number and both
// suites stay green with the clamp deleted. The kernel that does NOT do this is
// XNU -- copyout_control() copies the cmsg header out verbatim and corrects
// only *controllen -- and no test can produce that state through a syscall
// here.
//
// It can be produced by hand: a msghdr whose control buffer says one thing and
// whose cmsg header claims another is an ordinary struct. That is what these
// cases do, which is why the clamp is falsifiable on this host and not only on
// an Apple one. Each of the helper's three guards has one case that fails
// without it.
#include "wire/FdHarvest.h"

#include <gtest/gtest.h>

#include <sys/socket.h>

#include <array>
#include <cstddef>
#include <cstdint>

using LibreSCRS::Agent::Wire::deliveredFdBytes;

namespace {

constexpr std::size_t kFds = 4;

// A control buffer holding one well-formed SCM_RIGHTS header for kFds
// descriptors, with the msghdr reporting the whole buffer as delivered.
struct ControlBuffer
{
    alignas(struct cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int) * kFds)> bytes{};
    msghdr msg{};
    cmsghdr* header = nullptr;

    ControlBuffer()
    {
        msg.msg_control = bytes.data();
        msg.msg_controllen = bytes.size();
        header = CMSG_FIRSTHDR(&msg);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * kFds);
    }
};

} // namespace

// The undamaged case: everything the sender attached also arrived, so the
// clamp is a no-op and the caller gets all four descriptors' worth.
TEST(FdHarvest, WholeControlMessageYieldsEveryAttachedByte)
{
    ControlBuffer cb;
    EXPECT_EQ(deliveredFdBytes(cb.msg, cb.header), sizeof(int) * kFds);
}

// The XNU shape, and the whole reason the helper exists: the header still
// claims four descriptors while only one was copied out. Unclamped, the caller
// divides the CLAIMED length by sizeof(int) and indexes three ints past the end
// of its own buffer -- each of which gets an fcntl() and an owner. The answer
// must be what was delivered, not what was claimed.
TEST(FdHarvest, TruncatedControlMessageYieldsOnlyWhatArrived)
{
    ControlBuffer cb;
    cb.msg.msg_controllen = CMSG_LEN(sizeof(int)); // one descriptor really arrived
    EXPECT_EQ(deliveredFdBytes(cb.msg, cb.header), sizeof(int));
}

// A header claiming less than an empty header is malformed. Subtracting
// CMSG_LEN(0) from it wraps a size_t to something near SIZE_MAX, so the guard
// has to come before the arithmetic, not after it.
TEST(FdHarvest, HeaderShorterThanAnEmptyOneYieldsNothing)
{
    ControlBuffer cb;
    cb.header->cmsg_len = CMSG_LEN(0) - 1;
    EXPECT_EQ(deliveredFdBytes(cb.msg, cb.header), 0U);
}

// A header sitting outside what was delivered has no payload at all. The
// difference controlEnd - data is negative here, and it is computed in
// std::size_t, so without the guard it reads as an enormous positive length.
TEST(FdHarvest, HeaderPastTheDeliveredEndYieldsNothing)
{
    ControlBuffer cb;
    cb.msg.msg_controllen = 0;
    EXPECT_EQ(deliveredFdBytes(cb.msg, cb.header), 0U);
}

// No ancillary data at all is the common case on this socket, and it must not
// be a special case at the call site.
TEST(FdHarvest, AbsentHeaderOrControlBufferYieldsNothing)
{
    ControlBuffer cb;
    EXPECT_EQ(deliveredFdBytes(cb.msg, nullptr), 0U);

    msghdr bare{};
    EXPECT_EQ(deliveredFdBytes(bare, cb.header), 0U);
}
