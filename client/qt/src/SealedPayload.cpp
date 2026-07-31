// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// A MIXED translation unit: it carries the exported readBoundedPayload() as
// well as internal code. The two decision helpers it leans on deliberately
// live in SealedPayloadInternal.cpp instead, so the suite that drives them can
// compile a pure-internal TU rather than acquiring a second definition of this
// file's exported entry point.

#include <LibreSCRS/AgentClient/SealedPayload.h>

#include "SealedPayloadInternal.h"

#include <cerrno>
#include <new>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// The seal facility is Linux-only, so the header that declares it and every
// branch that uses it are gated HERE, in the translation unit — never in the
// public header (which must compile standalone on every platform this
// component builds on) and never in CMake (the whole file is library source on
// every platform; only the seal check inside it is platform-specific).
#if defined(__linux__)
#include <fcntl.h>
#endif

namespace LibreSCRS::AgentClient {

namespace {

#if defined(__linux__)

/// @brief Decide whether @p fd's seal state is acceptable, on the platform
///        that has a seal facility.
///
/// Three-state, and the middle state is the one a naive check gets wrong:
///   * the query fails with EINVAL -> this descriptor's backing store has no
///     seal support at all, so an unsealed descriptor is the only thing that
///     can ever be presented here. Sealing is hardening where it exists, not a
///     precondition, so this is ACCEPTED — the only real producer on the
///     socket transport passes exactly this shape and can never seal.
///   * the query fails any other way (EBADF on a stale descriptor, say) ->
///     REFUSED. That is a broken descriptor, not an unsealable one.
///   * the query succeeds -> the backing store DOES implement seals, so a
///     sealed payload is expressible here and the absence of seals is
///     meaningful rather than a platform limitation. Require the full set.
///
/// On that third branch, note what a successful query does and does not tell
/// you. It does NOT mean seals can still be added: adding them fails with
/// EPERM unless the descriptor was created sealable in the first place
/// (measured on a 6.12 kernel — adding write/shrink/grow succeeded only on an
/// anonymous file created with the sealing-permitted flag, and failed with
/// EPERM both on a memory-backed regular file and on an anonymous file created
/// without that flag). So an unsealed descriptor on this branch cannot be
/// repaired by anyone; it can only be refused. That is exactly why refusing is
/// right: its bytes and its size are both still mutable, so the size the
/// caller is about to trust is not pinned, and no later step can pin it.
[[nodiscard]] bool sealStateAcceptable(int fd) noexcept
{
    constexpr int kRequiredSeals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW;

    errno = 0;
    const int seals = ::fcntl(fd, F_GET_SEALS);
    if (seals < 0) {
        return errno == EINVAL;
    }
    return (seals & kRequiredSeals) == kRequiredSeals;
}

#endif // __linux__

} // namespace

std::optional<QByteArray> readBoundedPayload(const FdHandle& fd)
{
    if (!fd.valid()) {
        return std::nullopt;
    }
    const int rawFd = fd.get();

#if defined(__linux__)
    if (!sealStateAcceptable(rawFd)) {
        return std::nullopt;
    }
#endif

    struct ::stat st{};
    if (::fstat(rawFd, &st) != 0) {
        return std::nullopt;
    }

    const std::optional<qsizetype> accepted = Internal::acceptablePayloadSize(st.st_mode, st.st_size);
    if (!accepted.has_value()) {
        return std::nullopt;
    }
    const qsizetype size = *accepted;

    // A zero-length payload is a legitimate result, not a read failure —
    // return an engaged, empty array so callers can tell the two apart. Only a
    // regular file reaches this line, so "size zero" really does mean an empty
    // file rather than "this descriptor has no meaningful size".
    if (size == 0) {
        return QByteArray{};
    }

    QByteArray out;
    try {
        out.resize(size);
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    }
    if (out.size() != size) {
        // Qt's container reports a failed grow by staying short rather than
        // throwing under some configurations; treat it the same way.
        return std::nullopt;
    }

    // Rewind defensively: the producer may or may not have repositioned the
    // descriptor after writing it. The descriptor is known to be a regular
    // file by this point, so this seek is well defined; its result is ignored
    // anyway because the read below is positional and does not consult the
    // file offset.
    ::lseek(rawFd, 0, SEEK_SET);

    // Positional reads against a size the kernel has already committed to —
    // never a whole-file mapping. A writer that truncated a mapped file under
    // this process would raise SIGBUS, which cannot be caught and would take
    // the entire hosting process down with it.
    if (!Internal::readExactly(rawFd, out.data(), size)) {
        return std::nullopt;
    }

    return out;
}

} // namespace LibreSCRS::AgentClient
