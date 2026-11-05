// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <QByteArray>
#include <QtGlobal>

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

/// @brief Hard ceiling, in bytes, on a payload `readBoundedPayload()` will
///        accept. 8 MiB.
///
/// @warning This is a NEW invariant introduced by this reader. It does not
///          mirror, restate or track any bound that already exists elsewhere
///          in the stack, and nothing upstream enforces it:
///          - the agent pushes a photo field's raw bytes into the descriptor
///            with no length check of its own;
///          - the 1 MiB frame ceiling the socket wire applies bounds the CBOR
///            message body, not the descriptor passed alongside it — the bytes
///            never travel inline;
///          - neither producer (the sealed anonymous file on Linux, the
///            unlinked temporary file on macOS) checks a size before writing.
///
///          So this constant is the ONLY bound standing between a hostile or
///          simply buggy producer and this process's address space.
///
/// Sizing, and where the number comes from. The largest payload the supported
/// card stack can actually produce is bounded by the card-read paths that
/// yield a portrait:
///   - the machine-readable travel-document reader has a hard safety stop in
///     its READ BINARY loop, but the stop is tested AFTER the chunk has been
///     appended, so its true ceiling is one 256-byte chunk above the nominal
///     1 MiB — 1 048 832 bytes exactly;
///   - the national eID readers cap one file at 64 KiB / 65535 bytes;
///   - the portrait file on those eID cards is documented at roughly 15 KiB.
/// 1 048 832 bytes is therefore the largest figure any of those paths can hand
/// up. 8 MiB clears it by a factor of eight, so no payload the supported cards can
/// carry is ever refused, while still being small enough that a single
/// accepted allocation cannot wedge a long-lived desktop shell process. The
/// factor of eight is a deliberate durability margin for card families not yet
/// supported — a policy choice, not a measurement.
inline constexpr qsizetype kMaxBoundedPayloadBytes = 8 * 1024 * 1024;

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
