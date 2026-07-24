// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <unistd.h>

namespace LibreSCRS::AgentClient {

FdHandle::FdHandle() noexcept : m_fd(-1) {}

FdHandle::FdHandle(int fd) noexcept : m_fd(fd) {}

FdHandle::FdHandle(FdHandle&& other) noexcept : m_fd(other.m_fd)
{
    other.m_fd = -1;
}

FdHandle& FdHandle::operator=(FdHandle&& other) noexcept
{
    if (this != &other) {
        if (m_fd >= 0) {
            ::close(m_fd);
        }
        m_fd = other.m_fd;
        other.m_fd = -1;
    }
    return *this;
}

FdHandle::~FdHandle()
{
    if (m_fd >= 0) {
        ::close(m_fd);
    }
}

int FdHandle::get() const noexcept
{
    return m_fd;
}

bool FdHandle::valid() const noexcept
{
    return m_fd >= 0;
}

int FdHandle::release() noexcept
{
    const int fd = m_fd;
    m_fd = -1;
    return fd;
}

} // namespace LibreSCRS::AgentClient
