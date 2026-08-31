// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// readBoundedPayload()'s three-state descriptor contract, its byte cap and the
// cap boundary, and the empty-versus-failure distinction.
//
// The three states are NOT "sealable vs not". They are what the seal query
// answers:
//   * query fails with EINVAL -> the descriptor has no seal support at all
//     -> read under the cap.
//   * query succeeds -> sealing is available -> the FULL write/shrink/grow set
//     is required, anything less is refused. An anonymous file created without
//     sealing permission lands here: the query succeeds and reports only the
//     seal-the-seals flag, which a naive "can it be sealed?" test would read as
//     a pass.
//   * no seal facility on the platform -> no shape check; cap and positional
//     read apply as everywhere.
//
// A note on "an ordinary file", because it is NOT a synonym for "no seal
// support" on Linux and this suite learned that the hard way: whether a
// regular file answers the seal query is a property of its FILESYSTEM, not of
// its being a regular file. On a memory-backed filesystem the query SUCCEEDS
// and reports no seals, so such a file is refused; only on a disk-backed
// filesystem does it fail with EINVAL. The fixtures below therefore locate a
// filesystem of the required kind at run time and skip loudly rather than
// assume one, and both behaviours are pinned by their own case.
//
// Every seal-shape case asserts the PREMISE it depends on (what the seal query
// actually returns for the descriptor the fixture built) before asserting the
// reader's behaviour, so no case can pass because the fixture silently built
// the wrong kind of descriptor.

#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/SealedPayload.h>

#include <gtest/gtest.h>

#include <QByteArray>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/mman.h> // memfd_create / MFD_ALLOW_SEALING
#endif

using LibreSCRS::AgentClient::FdHandle;
using LibreSCRS::AgentClient::kMaxBoundedPayloadBytes;
using LibreSCRS::AgentClient::readBoundedPayload;

namespace {

// Write the whole buffer or fail loudly; a partial write would make a fixture
// silently smaller than the case under test intends.
[[nodiscard]] bool writeAll(int fd, const QByteArray& bytes)
{
    qsizetype written = 0;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.constData() + written, static_cast<std::size_t>(bytes.size() - written));
        if (n > 0) {
            written += static_cast<qsizetype>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

// An ordinary file in @p dir, created then immediately unlinked: no name in
// the filesystem. This is the descriptor shape the macOS producer passes over
// the socket transport.
[[nodiscard]] FdHandle makePlainFileIn(const std::string& dir, const QByteArray& bytes)
{
    std::string path = dir + "/librescrs-bounded-payload-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        return {};
    }
    FdHandle handle{fd};
    ::unlink(path.c_str());
    if (!writeAll(fd, bytes)) {
        return {};
    }
    ::lseek(fd, 0, SEEK_SET);
    return handle;
}

#if defined(__linux__)

// Does a regular file created in @p dir answer the seal query? Returns the
// answer, or nullopt when a file could not be created there at all.
[[nodiscard]] std::optional<bool> dirSupportsSeals(const std::string& dir)
{
    const FdHandle probe = makePlainFileIn(dir, QByteArray{});
    if (!probe.valid()) {
        return std::nullopt;
    }
    errno = 0;
    const int seals = ::fcntl(probe.get(), F_GET_SEALS);
    if (seals >= 0) {
        return true;
    }
    if (errno == EINVAL) {
        return false;
    }
    return std::nullopt;
}

// Find a directory whose regular files have NO seal support (a disk-backed
// filesystem), or nullopt if none of the candidates qualifies.
[[nodiscard]] std::optional<std::string> findNonSealingDir()
{
    // APPEND $HOME rather than replacing a fixed candidate: on a machine whose
    // $HOME is memory-backed, overwriting would discard the /var/tmp candidate
    // that could still have satisfied this case and would skip it needlessly.
    std::vector<std::string> candidates{".", "/var/tmp"};
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        candidates.emplace_back(home);
    }
    for (const std::string& dir : candidates) {
        if (dirSupportsSeals(dir) == std::optional<bool>{false}) {
            return dir;
        }
    }
    return std::nullopt;
}

// Find a directory whose regular files DO answer the seal query (a
// memory-backed filesystem), or nullopt.
[[nodiscard]] std::optional<std::string> findSealingDir()
{
    for (const std::string& dir : {std::string{"/tmp"}, std::string{"/dev/shm"}}) {
        if (dirSupportsSeals(dir) == std::optional<bool>{true}) {
            return dir;
        }
    }
    return std::nullopt;
}

// An anonymous file with sealing PERMITTED, then sealed exactly the way the
// production Linux producer seals: write, shrink and grow all pinned.
[[nodiscard]] FdHandle makeFullySealed(const QByteArray& bytes)
{
    const int fd = ::memfd_create("librescrs-bounded-payload-test", MFD_ALLOW_SEALING);
    if (fd < 0) {
        return {};
    }
    FdHandle handle{fd};
    if (!writeAll(fd, bytes)) {
        return {};
    }
    ::lseek(fd, 0, SEEK_SET);
    if (::fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) != 0) {
        return {};
    }
    return handle;
}

// An anonymous file with sealing NOT permitted. The seal query SUCCEEDS on
// this and reports F_SEAL_SEAL, so it is "sealable" to a naive check while the
// bytes and the size are both still mutable.
[[nodiscard]] FdHandle makeSealSealOnly(const QByteArray& bytes)
{
    const int fd = ::memfd_create("librescrs-bounded-payload-test", 0);
    if (fd < 0) {
        return {};
    }
    FdHandle handle{fd};
    if (!writeAll(fd, bytes)) {
        return {};
    }
    ::lseek(fd, 0, SEEK_SET);
    return handle;
}

// Sealing permitted, but only the write seal applied: the size can still
// shrink or grow under the reader, so the size the reader is about to trust is
// not pinned.
[[nodiscard]] FdHandle makeWriteSealedOnly(const QByteArray& bytes)
{
    const int fd = ::memfd_create("librescrs-bounded-payload-test", MFD_ALLOW_SEALING);
    if (fd < 0) {
        return {};
    }
    FdHandle handle{fd};
    if (!writeAll(fd, bytes)) {
        return {};
    }
    ::lseek(fd, 0, SEEK_SET);
    if (::fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) != 0) {
        return {};
    }
    return handle;
}

#endif // __linux__

// A descriptor the reader is expected to ACCEPT, built the most deterministic
// way each platform allows: the fully sealed anonymous file where seals exist,
// an ordinary file where they do not. Used by the cases that are about the cap
// and the empty/failure distinction rather than about descriptor shape, so
// they do not depend on which filesystem the tests happen to run on.
[[nodiscard]] FdHandle makeAcceptedFd(const QByteArray& bytes)
{
#if defined(__linux__)
    return makeFullySealed(bytes);
#else
    return makePlainFileIn(".", bytes);
#endif
}

} // namespace

TEST(SealedPayloadTest, EmptyHandleIsRefused)
{
    const FdHandle empty;
    ASSERT_FALSE(empty.valid());
    EXPECT_FALSE(readBoundedPayload(empty).has_value())
        << "an empty handle has nothing to read and must not produce an engaged optional";
}

// A pipe is the sharpest case for the empty-versus-failure contract: the size
// query answers zero however many bytes are queued in it, so a reader that
// trusts that answer returns an ENGAGED EMPTY payload and the caller cannot
// tell "the card carried no photo" from "you were handed a pipe".
TEST(SealedPayloadTest, PipeHoldingReadableBytesIsRefused)
{
    int ends[2] = {-1, -1};
    ASSERT_EQ(::pipe(ends), 0) << "fixture failed to create a pipe";
    const QByteArray payload("these are thirty-eight real pipe bytes", 38);
    ASSERT_EQ(::write(ends[1], payload.constData(), static_cast<std::size_t>(payload.size())), payload.size());
    ASSERT_EQ(::close(ends[1]), 0);
    const FdHandle fd{ends[0]};

    // Premise 1: the descriptor really is not a regular file.
    struct ::stat st{};
    ASSERT_EQ(::fstat(fd.get(), &st), 0);
    ASSERT_FALSE(S_ISREG(st.st_mode)) << "a pipe must not present itself as a regular file";
    // Premise 2 USED to be `st.st_size == 0`, and it was a claim about Linux
    // wearing the clothes of a claim about pipes. Linux reports zero for a pipe
    // no matter what it holds; Darwin reports the bytes currently buffered --
    // 38 here -- and both are correct, because st_size describes a FILE EXTENT
    // and a pipe has none. Asserting one platform's answer made this whole file
    // unrunnable on the other, for a premise the case does not rest on.
    //
    // What the case rests on is the pair below and above: the descriptor is not
    // a regular file, and the bytes really are sitting in it. That is the shape
    // a size-bounded read gets wrong, and it is the same shape everywhere.
    //
    // Premise 3: the bytes really are sitting there, readable.
    int queued = 0;
    ASSERT_EQ(::ioctl(fd.get(), FIONREAD, &queued), 0);
    ASSERT_EQ(queued, payload.size()) << "the pipe must actually hold the bytes this case is about";

    EXPECT_FALSE(readBoundedPayload(fd).has_value())
        << "a descriptor whose reported size is meaningless must fail, never return an engaged "
           "empty payload that a caller would read as an absent photo";
}

TEST(SealedPayloadTest, SocketIsRefused)
{
    int ends[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends), 0) << "fixture failed to create a socket pair";
    const QByteArray payload("bytes queued on a socket", 24);
    ASSERT_EQ(::write(ends[1], payload.constData(), static_cast<std::size_t>(payload.size())), payload.size());
    ASSERT_EQ(::close(ends[1]), 0);
    const FdHandle fd{ends[0]};

    struct ::stat st{};
    ASSERT_EQ(::fstat(fd.get(), &st), 0);
    ASSERT_FALSE(S_ISREG(st.st_mode));

    EXPECT_FALSE(readBoundedPayload(fd).has_value()) << "a socket is not a bounded payload";
}

TEST(SealedPayloadTest, CharacterDeviceIsRefused)
{
    const int raw = ::open("/dev/zero", O_RDONLY);
    if (raw < 0) {
        GTEST_SKIP() << "/dev/zero is not openable here, so this descriptor shape cannot be built";
    }
    const FdHandle fd{raw};

    struct ::stat st{};
    ASSERT_EQ(::fstat(fd.get(), &st), 0);
    ASSERT_TRUE(S_ISCHR(st.st_mode)) << "expected a character device";

    EXPECT_FALSE(readBoundedPayload(fd).has_value())
        << "an endless character device must not be read as a bounded payload";
}

TEST(SealedPayloadTest, DirectoryIsRefused)
{
    const int raw = ::open(".", O_RDONLY);
    ASSERT_GE(raw, 0) << "fixture failed to open the working directory";
    const FdHandle fd{raw};

    struct ::stat st{};
    ASSERT_EQ(::fstat(fd.get(), &st), 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    // A directory reports a NON-zero size, so this case is not covered by the
    // zero-size reasoning above — it is refused purely for not being regular.
    EXPECT_GT(st.st_size, 0) << "expected a directory to report a non-zero size";

    EXPECT_FALSE(readBoundedPayload(fd).has_value()) << "a directory is not a payload";
}

TEST(SealedPayloadTest, PayloadIsReadWholeAndUnaltered)
{
    const QByteArray payload("\xFF\xD8\xFF\xE0 portrait bytes\x00 with an embedded NUL", 40);
    const FdHandle fd = makeAcceptedFd(payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an acceptable descriptor";

    const std::optional<QByteArray> out = readBoundedPayload(fd);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, payload) << "the payload must survive byte for byte, embedded NUL included";
}

TEST(SealedPayloadTest, EmptyPayloadIsEngagedNotAFailure)
{
    const FdHandle fd = makeAcceptedFd(QByteArray{});
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an acceptable descriptor";

    const std::optional<QByteArray> out = readBoundedPayload(fd);
    ASSERT_TRUE(out.has_value()) << "a zero-length payload is a legitimate result, not a read failure";
    EXPECT_TRUE(out->isEmpty());
    EXPECT_EQ(out->size(), 0);
}

TEST(SealedPayloadTest, PayloadExactlyAtTheCapIsRead)
{
    QByteArray payload(kMaxBoundedPayloadBytes, 'A');
    ASSERT_EQ(payload.size(), kMaxBoundedPayloadBytes);
    payload[kMaxBoundedPayloadBytes - 1] = 'Z'; // proves the LAST byte survives

    const FdHandle fd = makeAcceptedFd(payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an acceptable descriptor";

    const std::optional<QByteArray> out = readBoundedPayload(fd);
    ASSERT_TRUE(out.has_value()) << "the cap is inclusive: a payload of exactly the cap must be read";
    ASSERT_EQ(out->size(), kMaxBoundedPayloadBytes);
    EXPECT_EQ(out->at(0), 'A');
    EXPECT_EQ(out->at(kMaxBoundedPayloadBytes - 1), 'Z');
}

TEST(SealedPayloadTest, PayloadOneByteOverTheCapIsRefused)
{
    const QByteArray payload(kMaxBoundedPayloadBytes + 1, 'A');
    ASSERT_EQ(payload.size(), kMaxBoundedPayloadBytes + 1);

    const FdHandle fd = makeAcceptedFd(payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an acceptable descriptor";

    EXPECT_FALSE(readBoundedPayload(fd).has_value())
        << "one byte over the cap must be refused outright, not truncated to the cap";
}

#if defined(__linux__)

TEST(SealedPayloadTest, OrdinaryFileWithoutSealSupportIsRead)
{
    const std::optional<std::string> dir = findNonSealingDir();
    if (!dir.has_value()) {
        GTEST_SKIP() << "no writable disk-backed directory found, so the descriptor shape this case "
                        "is about (seal query fails with EINVAL) cannot be built here";
    }

    const QByteArray payload("\xFF\xD8\xFF\xE0 portrait bytes", 21);
    const FdHandle fd = makePlainFileIn(*dir, payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an ordinary file in " << *dir;

    // Premise: this descriptor really has no seal support at all.
    errno = 0;
    const int seals = ::fcntl(fd.get(), F_GET_SEALS);
    ASSERT_LT(seals, 0) << "expected a descriptor with no seal support in " << *dir;
    ASSERT_EQ(errno, EINVAL) << "no seal support must present itself as EINVAL";

    const std::optional<QByteArray> out = readBoundedPayload(fd);
    ASSERT_TRUE(out.has_value()) << "sealing is hardening where it exists, not a precondition: a "
                                    "descriptor that cannot be sealed at all must still be read";
    EXPECT_EQ(*out, payload);
}

TEST(SealedPayloadTest, OrdinaryFileOnASealCapableFilesystemIsRefused)
{
    const std::optional<std::string> dir = findSealingDir();
    if (!dir.has_value()) {
        GTEST_SKIP() << "no memory-backed directory found whose regular files answer the seal query, "
                        "so this case's premise cannot be established here";
    }

    const QByteArray payload("mutable bytes", 13);
    const FdHandle fd = makePlainFileIn(*dir, payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an ordinary file in " << *dir;

    // Premise, and the reason this case exists: "ordinary file" does NOT imply
    // "no seal support". On a memory-backed filesystem the query succeeds and
    // reports no seals at all, which is precisely the mutable-descriptor state
    // the reader refuses.
    const int seals = ::fcntl(fd.get(), F_GET_SEALS);
    ASSERT_GE(seals, 0) << "expected a seal-capable filesystem in " << *dir;
    ASSERT_EQ(seals & (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW), 0);

    EXPECT_FALSE(readBoundedPayload(fd).has_value())
        << "the descriptor answers the seal query, so sealing is available on it and the full "
           "write/shrink/grow set is required";
}

TEST(SealedPayloadTest, FullySealedDescriptorIsRead)
{
    const QByteArray payload("\xFF\xD8\xFF\xE0 sealed portrait bytes", 28);
    const FdHandle fd = makeFullySealed(payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build a sealed anonymous file";

    // Premise: the full set really is applied.
    const int seals = ::fcntl(fd.get(), F_GET_SEALS);
    ASSERT_GE(seals, 0);
    ASSERT_EQ(seals & (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW), F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW);

    const std::optional<QByteArray> out = readBoundedPayload(fd);
    ASSERT_TRUE(out.has_value()) << "the fully sealed shape is the live one on the Linux bus transport";
    EXPECT_EQ(*out, payload);
}

TEST(SealedPayloadTest, SealSealOnlyDescriptorIsRefused)
{
    const QByteArray payload("mutable bytes", 13);
    const FdHandle fd = makeSealSealOnly(payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build an unsealable anonymous file";

    // Premise, and the whole point of this case: the query SUCCEEDS here and
    // reports the seal-the-seals flag, so "the query succeeded" is not on its
    // own evidence that the bytes are immutable.
    const int seals = ::fcntl(fd.get(), F_GET_SEALS);
    ASSERT_GE(seals, 0) << "an anonymous file answers the seal query even without sealing permission";
    ASSERT_EQ(seals, F_SEAL_SEAL) << "expected exactly the seal-the-seals flag and nothing else";
    ASSERT_EQ(seals & (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW), 0);

    EXPECT_FALSE(readBoundedPayload(fd).has_value())
        << "sealing is available on this descriptor, so the full write/shrink/grow set is required";
}

TEST(SealedPayloadTest, PartiallySealedDescriptorIsRefused)
{
    const QByteArray payload("write-sealed but resizable", 26);
    const FdHandle fd = makeWriteSealedOnly(payload);
    ASSERT_TRUE(fd.valid()) << "fixture failed to build a partially sealed anonymous file";

    // Premise: write is pinned, size is not.
    const int seals = ::fcntl(fd.get(), F_GET_SEALS);
    ASSERT_GE(seals, 0);
    ASSERT_EQ(seals & F_SEAL_WRITE, F_SEAL_WRITE);
    ASSERT_EQ(seals & (F_SEAL_SHRINK | F_SEAL_GROW), 0);

    EXPECT_FALSE(readBoundedPayload(fd).has_value())
        << "an unpinned size means the length the reader is about to trust can still change";
}

#endif // __linux__
