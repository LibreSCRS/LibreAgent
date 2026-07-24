// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>

// Move-only RAII owner of one file descriptor, for the client side of the
// socket wire's SCM_RIGHTS fd-passing (see wire/librescrs-agent.cddl's
// `fd-index` and LibreSCRS::Agent::Wire::UniqueFd, the server-side
// counterpart this mirrors). -1 is the empty/invalid state. Deliberately
// NOT header-only (unlike every other value type in this directory) --
// exported across the shared-library boundary via LIBRESCRS_AGENTCLIENT_EXPORT
// so the lifted API (a later task) can return/accept it by value through the
// library's public ABI.
namespace LibreSCRS::AgentClient {

class LIBRESCRS_AGENTCLIENT_EXPORT FdHandle
{
public:
    FdHandle() noexcept;
    explicit FdHandle(int fd) noexcept;

    FdHandle(const FdHandle&) = delete;
    FdHandle& operator=(const FdHandle&) = delete;

    FdHandle(FdHandle&& other) noexcept;
    FdHandle& operator=(FdHandle&& other) noexcept;

    ~FdHandle();

    [[nodiscard]] int get() const noexcept;
    [[nodiscard]] bool valid() const noexcept;

    // Relinquishes ownership WITHOUT closing the fd -- the caller now owns
    // it (e.g. handing it to a lower-level transport call, or returning the
    // raw descriptor to non-RAII code). This handle is invalid() afterwards.
    [[nodiscard]] int release() noexcept;

private:
    int m_fd;
};

} // namespace LibreSCRS::AgentClient
