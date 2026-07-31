// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <QByteArray>

#include <optional>

#include <sys/types.h>

/// @file
/// @brief INTERNAL — never installed. The two decision pieces of
///        `readBoundedPayload()`, split out so each can be driven directly.
///
/// Both are defined in `SealedPayloadInternal.cpp`, deliberately NOT alongside
/// `readBoundedPayload()`: that keeps their translation unit free of exported
/// symbols, so the suite driving them can compile it directly without also
/// acquiring a second definition of the library's exported entry point.
///
/// Both branches these expose are otherwise unreachable from the public entry
/// point on a sane kernel: a regular file never reports a negative size, and a
/// premature end of file only happens when a writer truncates the file between
/// the size query and the read — a race no single-threaded test can stage.
/// Both are load-bearing failure modes on a path whose whole purpose is to not
/// take the hosting process down, so they are made testable rather than left
/// asserted-but-unexercised.

namespace LibreSCRS::AgentClient::Internal {

/// @brief Validate what the size query reported about a descriptor.
///
/// Platform-independent by construction — it sees only the mode and size, and
/// is called on EVERY platform, so no shape rule here can be bypassed by a
/// build configuration.
///
/// @param mode         The descriptor's mode bits.
/// @param reportedSize The size the kernel reported.
/// @return The accepted payload size, or `std::nullopt` when the descriptor is
///         not a regular file, reports a negative size, or exceeds
///         `kMaxBoundedPayloadBytes`.
[[nodiscard]] std::optional<qsizetype> acceptablePayloadSize(mode_t mode, off_t reportedSize) noexcept;

/// @brief Fill exactly @p size bytes at @p dest from @p fd using positional
///        reads, retrying on interruption.
///
/// @return True only when all @p size bytes were read. False on a read error
///         or on a premature end of file — a payload shorter than the size
///         query promised is a failure, never a silently truncated success.
[[nodiscard]] bool readExactly(int fd, char* dest, qsizetype size) noexcept;

} // namespace LibreSCRS::AgentClient::Internal
