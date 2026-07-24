// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>

/// @file
/// @brief Move-only RAII owner of one file descriptor.

namespace LibreSCRS::AgentClient {

/// @brief Move-only RAII owner of one file descriptor, for the client side
///        of the socket wire's SCM_RIGHTS fd-passing (see
///        wire/librescrs-agent.cddl's `fd-index` and
///        `LibreSCRS::Agent::Wire::UniqueFd`, the server-side counterpart
///        this mirrors). -1 is the empty/invalid state.
///
/// @note Deliberately NOT header-only (unlike every other value type in this
///       directory) — exported across the shared-library boundary via
///       `LIBRESCRS_AGENTCLIENT_EXPORT` so this library's public ABI can
///       return/accept it by value (e.g. `AgentCard::sign()`'s document
///       parameter, `AgentOperation::takeSignedArtifact()`,
///       `PhotoItem::fd`).
class LIBRESCRS_AGENTCLIENT_EXPORT FdHandle
{
public:
    /// @brief Constructs an empty/invalid handle (`get() == -1`).
    FdHandle() noexcept;
    /// @brief Takes ownership of @p fd. Pass -1 for an empty handle.
    explicit FdHandle(int fd) noexcept;

    FdHandle(const FdHandle&) = delete;
    FdHandle& operator=(const FdHandle&) = delete;

    /// @brief Transfers ownership from @p other, which becomes invalid.
    FdHandle(FdHandle&& other) noexcept;
    /// @brief Closes any fd currently held, then transfers ownership from
    ///        @p other, which becomes invalid.
    FdHandle& operator=(FdHandle&& other) noexcept;

    /// @brief Closes the owned fd, if any.
    ~FdHandle();

    /// @brief The owned descriptor, or -1 if empty.
    [[nodiscard]] int get() const noexcept;
    /// @brief True when `get()` returns a real descriptor (not -1).
    [[nodiscard]] bool valid() const noexcept;

    /// @brief Relinquishes ownership WITHOUT closing the fd — the caller now
    ///        owns it (e.g. handing it to a lower-level transport call, or
    ///        returning the raw descriptor to non-RAII code). This handle is
    ///        `valid() == false` afterwards.
    /// @return The previously-owned descriptor, or -1 if this handle was
    ///         already empty.
    [[nodiscard]] int release() noexcept;

private:
    int m_fd;
};

} // namespace LibreSCRS::AgentClient
