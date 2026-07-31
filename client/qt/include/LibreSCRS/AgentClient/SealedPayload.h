// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QByteArray>

#include <optional>

/// @file
/// @brief The single audited reader for the SMALL, fully-buffered payloads the
///        agent hands over as file descriptors.
///
/// Every place that turns such a descriptor into bytes goes through
/// `readBoundedPayload()` rather than re-spelling stat + read per call site,
/// so the byte cap and the descriptor-shape checks below cannot be forgotten
/// at one call site and applied at another.

namespace LibreSCRS::AgentClient {

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

/// @brief Read the whole payload behind @p fd into a `QByteArray`, refusing
///        anything larger than `kMaxBoundedPayloadBytes`.
///
/// The descriptor is read with positional reads against a size the kernel has
/// already committed to — never memory-mapped. A writer that truncates a
/// mapped file out from under the reader raises SIGBUS, which cannot be caught
/// and would take down the whole hosting process (a desktop shell, in the case
/// this reader exists to serve). A short read is a failure, not a truncation.
///
/// @par Regular files only
/// Only a REGULAR file is accepted, on every platform — this rule sits outside
/// every platform gate. A pipe, socket or character device reports a size of
/// zero however many bytes are actually readable from it, so accepting one
/// would return an engaged-but-empty payload and collapse the
/// empty-versus-failure distinction below: the caller could not tell "the card
/// carried no photo" from "you were handed a pipe". Such a descriptor yields
/// `std::nullopt`.
///
/// @par Seal state
/// Three states, and all three are legitimate:
/// - The descriptor's backing store implements seals and the full
///   write/shrink/grow set is present: accepted. This is the live branch on the
///   Linux D-Bus transport, whose producer seals every payload it hands over.
/// - The backing store implements seals but the full set is NOT present:
///   refused. An anonymous file created WITHOUT the sealing-permitted flag
///   still answers the seal query successfully and reports only the
///   seal-the-seals flag, so "the query succeeded" is not on its own evidence
///   of immutability. Such a descriptor cannot be repaired after the fact
///   either — see the sealing-is-not-retrofittable warning below — so refusing
///   is the only available answer.
/// - The backing store has no seal support at all: accepted, under the cap.
///   Seal verification is hardening where the platform and the backing store
///   support it; it is NOT a precondition, because the socket transport is a
///   production transport whose only real producer — macOS, which has no
///   anonymous-memory file primitive and passes an unlinked ordinary file —
///   cannot seal anything.
///
/// On platforms with no seal facility at all, no shape check applies; the cap
/// and the positional-read loop apply exactly as everywhere else. That is what
/// makes the macOS producer's unsealed ordinary file work: the check is
/// compiled out there entirely, not satisfied.
///
/// @warning "An ordinary file" is NOT a synonym for the third state on Linux.
///          Whether a regular file answers the seal query is a property of its
///          FILESYSTEM: on a memory-backed filesystem the query succeeds and
///          reports no seals, so such a file falls into the SECOND state and
///          is refused; only on a disk-backed filesystem does it fail with
///          EINVAL and reach the third. Measured on a 6.12 kernel: a regular
///          file under a memory-backed mount answered the query, one on an
///          on-disk mount failed it with EINVAL.
///
/// @warning Sealing cannot be retrofitted, so a refused descriptor cannot be
///          repaired — it has to be created differently. Adding the required
///          seals fails with EPERM unless the descriptor came from the
///          anonymous-file primitive WITH its sealing-permitted flag. Measured
///          on the same 6.12 kernel: adding write/shrink/grow succeeded only
///          on an anonymous file created sealing-permitted, and failed with
///          EPERM both on a memory-backed regular file and on an anonymous
///          file created without that flag. So a Linux-side producer cannot
///          fix up an ordinary file or a plainly-created anonymous file after
///          the fact; it must create the payload sealable and seal it, which
///          is what the production Linux producer already does.
///
/// @warning NOT for the signed artifact (`Sign1.Result`). That payload is an
///          arbitrarily large document, and consumers stream it through a
///          bounded copy loop straight into their own output file rather than
///          buffering it whole. Calling this on a signed artifact would both
///          refuse legitimate large documents and defeat the streaming design.
///          This reader is for payloads whose size is bounded by construction,
///          such as a card portrait.
///
/// @note Never logs the bytes: the payload is personal data.
///
/// @param fd The descriptor to read. Ownership stays with the caller's handle;
///           this call neither closes nor consumes it. The file offset is
///           reset defensively before reading, but the read itself is
///           positional and does not depend on it.
///
/// @return An engaged optional holding the payload on success — including an
///         EMPTY `QByteArray` for a zero-length REGULAR file, which is a
///         legitimate result and is deliberately distinguishable from failure.
///         `std::nullopt` on an empty handle, a descriptor that is not a
///         regular file, a refused seal state, a stat failure, a negative
///         reported size, a size above `kMaxBoundedPayloadBytes`, an
///         allocation failure, or a short or failed read.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT std::optional<QByteArray> readBoundedPayload(const FdHandle& fd);

} // namespace LibreSCRS::AgentClient
