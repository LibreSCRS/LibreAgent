// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/SignOptions.h>

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QSaveFile>

#include <cerrno>
#include <sys/types.h>
#include <unistd.h>

namespace LibreSCRS::AgentClient {

namespace {

QString nameFor(const QFileInfo& source, SignatureFormat format, Packaging packaging)
{
    const QString stem = source.completeBaseName();
    const QString name = source.fileName();
    switch (format) {
    case SignatureFormat::PAdES:
        return stem + QStringLiteral("-signed.pdf");
    case SignatureFormat::XAdES:
        return packaging == Packaging::Detached ? name + QStringLiteral(".xsig") : stem + QStringLiteral("-signed.xml");
    case SignatureFormat::CAdES:
        return name + (packaging == Packaging::Detached ? QStringLiteral(".p7s") : QStringLiteral(".p7m"));
    case SignatureFormat::JAdES:
        return name + QStringLiteral(".jose");
    case SignatureFormat::ASiCe:
        return stem + QStringLiteral(".asice");
    }
    return {};
}

/// Claims a name from @p nextName, then streams @p readChunk (bytes read,
/// 0 at the end, < 0 on an error) over the claim in one commit.
template <class ReadChunk>
std::expected<QString, SignedFileError> writeClaimed(const std::function<QString()>& nextName, ReadChunk readChunk)
{
    if (!nextName) {
        return std::unexpected(SignedFileError::NoFreeName);
    }
    // The claim: an empty file of this writer's own, which is all any other
    // writer finds under the name until the commit below replaces it.
    constexpr int kNameAttempts = 8;
    QString path;
    for (int attempt = 0; attempt < kNameAttempts && path.isEmpty(); ++attempt) {
        const QString candidate = nextName();
        if (candidate.isEmpty()) {
            return std::unexpected(SignedFileError::NoFreeName);
        }
        QFile claim(candidate);
        if (claim.open(QIODevice::WriteOnly | QIODevice::NewOnly)) {
            path = candidate;
        } else if (!QFile::exists(candidate)) {
            return std::unexpected(SignedFileError::WriteFailed); // not a lost race: nothing can be created there
        }
    }
    if (path.isEmpty()) {
        return std::unexpected(SignedFileError::NoFreeName);
    }
    const auto release = [&path](SignedFileError error) {
        QFile::remove(path);
        return std::unexpected(error);
    };

    // The artifact goes to a temporary sibling and replaces the claim only
    // when complete; a failure or a crash before that never leaves part of it
    // under the name.
    QSaveFile out(path);
    if (!out.open(QIODevice::WriteOnly)) {
        return release(SignedFileError::WriteFailed);
    }
    // Fixed-size chunks: an artifact (an ASiC-E container above all) has no
    // bound to read it whole against.
    constexpr qint64 kChunkBytes = 64 * 1024;
    QByteArray chunk(kChunkBytes, '\0');
    qint64 total = 0;
    for (;;) {
        const qint64 taken = readChunk(chunk.data(), kChunkBytes);
        if (taken < 0) {
            return release(SignedFileError::UnreadableArtifact);
        }
        if (taken == 0) {
            break;
        }
        if (out.write(chunk.constData(), taken) != taken) {
            return release(SignedFileError::WriteFailed);
        }
        total += taken;
    }
    if (total == 0) {
        return release(SignedFileError::EmptyArtifact);
    }
    if (!out.commit()) {
        return release(SignedFileError::WriteFailed);
    }
    return path;
}

} // namespace

QString signedOutputPath(const QString& inputPath, SignatureFormat format, Packaging packaging, const QString& folder)
{
    const QFileInfo source(inputPath);
    const QString name = nameFor(source, format, packaging);
    if (name.isEmpty() || source.fileName().isEmpty()) {
        return {};
    }
    const QDir directory(folder.isEmpty() ? source.absolutePath() : folder);
    QString path = directory.filePath(name);
    if (!QFileInfo::exists(path)) {
        return path;
    }

    // Never overwrite. The cap only bounds the search: a folder holding ten
    // thousand numbered siblings gets an empty answer, which the caller
    // reports as a failed write rather than this loop spinning on.
    const QFileInfo taken(path);
    const QString base = taken.completeBaseName();
    const QString suffix = taken.suffix();
    constexpr int kMaxSiblings = 10000;
    for (int counter = 2; counter <= kMaxSiblings; ++counter) {
        path = directory.filePath(QStringLiteral("%1 (%2).%3").arg(base).arg(counter).arg(suffix));
        if (!QFileInfo::exists(path)) {
            return path;
        }
    }
    return {};
}

std::expected<QString, SignedFileError> writeSignedFile(int artifactFd, const std::function<QString()>& nextName)
{
    if (artifactFd < 0) {
        return std::unexpected(SignedFileError::UnreadableArtifact);
    }
    if (::lseek(artifactFd, 0, SEEK_SET) == static_cast<off_t>(-1) && errno != ESPIPE) {
        return std::unexpected(SignedFileError::UnreadableArtifact);
    }
    return writeClaimed(nextName, [artifactFd](char* into, qint64 capacity) -> qint64 {
        for (;;) {
            const ssize_t taken = ::read(artifactFd, into, static_cast<std::size_t>(capacity));
            if (taken < 0 && errno == EINTR) {
                continue; // a signal is not a failure
            }
            return static_cast<qint64>(taken);
        }
    });
}

std::expected<QString, SignedFileError> writeSignedFile(QIODevice& artifact, const std::function<QString()>& nextName)
{
    if (!artifact.isReadable()) {
        return std::unexpected(SignedFileError::UnreadableArtifact);
    }
    if (!artifact.isSequential() && !artifact.seek(0)) {
        return std::unexpected(SignedFileError::UnreadableArtifact);
    }
    return writeClaimed(nextName,
                        [&artifact](char* into, qint64 capacity) -> qint64 { return artifact.read(into, capacity); });
}

} // namespace LibreSCRS::AgentClient
