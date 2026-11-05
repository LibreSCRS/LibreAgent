// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one output-naming rule for a signed document: every format and
// packaging, and the collision search that never hands back an existing file.
// Then the one writer of that file: the name claimed exclusively, the artifact
// committed over the claim in one step, nothing left behind by a failure.

#include <LibreSCRS/AgentClient/SignOptions.h>

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QTemporaryDir>
#include <QTemporaryFile>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace LibreSCRS::AgentClient;

namespace {

void touch(const QString& path)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly)) << path.toStdString();
    file.write("x");
}

struct Row
{
    const char* input;
    SignatureFormat format;
    Packaging packaging;
    const char* expected;
};

TEST(SignedOutputPath, EveryFormatAndPackagingHasOneName)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    // Literals, not derived from the code under test.
    const Row rows[] = {
        {"contract.pdf", SignatureFormat::PAdES, Packaging::Enveloped, "contract-signed.pdf"},
        {"contract.pdf", SignatureFormat::PAdES, Packaging::Detached, "contract-signed.pdf"},
        {"invoice.xml", SignatureFormat::XAdES, Packaging::Enveloped, "invoice-signed.xml"},
        {"invoice.xml", SignatureFormat::XAdES, Packaging::Detached, "invoice.xml.xsig"},
        {"data.bin", SignatureFormat::CAdES, Packaging::Detached, "data.bin.p7s"},
        {"data.bin", SignatureFormat::CAdES, Packaging::Enveloped, "data.bin.p7m"},
        {"claims.json", SignatureFormat::JAdES, Packaging::Detached, "claims.json.jose"},
        {"photo.jpg", SignatureFormat::ASiCe, Packaging::Detached, "photo.asice"},
        {"archive.tar.gz", SignatureFormat::PAdES, Packaging::Enveloped, "archive.tar-signed.pdf"},
    };
    for (const Row& row : rows) {
        const QString input = dir.filePath(QString::fromLatin1(row.input));
        EXPECT_EQ(signedOutputPath(input, row.format, row.packaging), dir.filePath(QString::fromLatin1(row.expected)))
            << row.input;
    }
}

TEST(SignedOutputPath, AFolderReplacesTheInputsDirectory)
{
    QTemporaryDir inputs;
    QTemporaryDir outputs;
    ASSERT_TRUE(inputs.isValid() && outputs.isValid());
    EXPECT_EQ(signedOutputPath(inputs.filePath(QStringLiteral("a.pdf")), SignatureFormat::PAdES, Packaging::Enveloped,
                               outputs.path()),
              outputs.filePath(QStringLiteral("a-signed.pdf")));
}

TEST(SignedOutputPath, ATakenNameGetsTheFirstFreeNumberedSibling)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString input = dir.filePath(QStringLiteral("contract.pdf"));
    touch(input);
    touch(dir.filePath(QStringLiteral("contract-signed.pdf")));
    touch(dir.filePath(QStringLiteral("contract-signed (2).pdf")));

    EXPECT_EQ(signedOutputPath(input, SignatureFormat::PAdES, Packaging::Enveloped),
              dir.filePath(QStringLiteral("contract-signed (3).pdf")));
}

TEST(SignedOutputPath, TheNumberGoesBeforeTheLastExtension)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString input = dir.filePath(QStringLiteral("invoice.xml"));
    touch(dir.filePath(QStringLiteral("invoice.xml.xsig")));

    EXPECT_EQ(signedOutputPath(input, SignatureFormat::XAdES, Packaging::Detached),
              dir.filePath(QStringLiteral("invoice.xml (2).xsig")));
}

TEST(SignedOutputPath, AFreeNameIsNeverOneThatExists)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString input = dir.filePath(QStringLiteral("x.pdf"));
    for (int round = 0; round < 5; ++round) {
        const QString path = signedOutputPath(input, SignatureFormat::PAdES, Packaging::Enveloped);
        ASSERT_FALSE(path.isEmpty());
        EXPECT_FALSE(QFile::exists(path)) << path.toStdString();
        touch(path);
    }
}

// ---- writeSignedFile ------------------------------------------------------------

/// A file carrying @p bytes, open, its descriptor's offset left at the end --
/// the shape the agent hands an artifact over in.
std::unique_ptr<QTemporaryFile> artifactAtEnd(const QByteArray& bytes)
{
    auto file = std::make_unique<QTemporaryFile>();
    EXPECT_TRUE(file->open());
    if (!bytes.isEmpty()) {
        EXPECT_EQ(::write(file->handle(), bytes.constData(), static_cast<std::size_t>(bytes.size())), bytes.size());
    }
    return file;
}

QByteArray contentsOf(const QString& path)
{
    QFile file(path);
    EXPECT_TRUE(file.open(QIODevice::ReadOnly)) << path.toStdString();
    return file.readAll();
}

/// The entries of @p dir, hidden ones included: a writer's temporary sibling
/// counts as something left behind.
QStringList entriesOf(const QTemporaryDir& dir)
{
    return QDir(dir.path()).entryList(QDir::Files | QDir::Hidden | QDir::System);
}

TEST(WriteSignedFile, RewindsTheArtifactAndWritesEveryByte)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QByteArray payload = QByteArrayLiteral("%PDF-1.7 signed artifact bytes");
    const auto artifact = artifactAtEnd(payload);
    const QString target = dir.filePath(QStringLiteral("signed.pdf"));

    const auto written = writeSignedFile(artifact->handle(), [&] { return target; });

    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(*written, target);
    EXPECT_EQ(contentsOf(target), payload);
    EXPECT_EQ(entriesOf(dir), QStringList{QStringLiteral("signed.pdf")});
}

TEST(WriteSignedFile, AnEmptyArtifactIsAFailureAndLeavesNoFile)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const auto artifact = artifactAtEnd({});
    const QString target = dir.filePath(QStringLiteral("signed.pdf"));

    EXPECT_EQ(writeSignedFile(artifact->handle(), [&] { return target; }),
              std::unexpected(SignedFileError::EmptyArtifact));
    EXPECT_TRUE(entriesOf(dir).isEmpty()) << "a zero-byte artifact must never become a signed file";
}

TEST(WriteSignedFile, NoArtifactOrNoNameIsAFailure)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString target = dir.filePath(QStringLiteral("x"));
    EXPECT_EQ(writeSignedFile(-1, [&] { return target; }), std::unexpected(SignedFileError::UnreadableArtifact));
    const auto artifact = artifactAtEnd(QByteArrayLiteral("x"));
    EXPECT_EQ(writeSignedFile(artifact->handle(), [] { return QString(); }),
              std::unexpected(SignedFileError::NoFreeName));
    EXPECT_EQ(writeSignedFile(artifact->handle(), {}), std::unexpected(SignedFileError::NoFreeName));
    EXPECT_TRUE(entriesOf(dir).isEmpty());
}

// The name is a snapshot. A file another signer created under it between the
// naming and the write is left exactly as it was, and the artifact goes under
// the next name asked for.
TEST(WriteSignedFile, AFileCreatedAfterTheNamingIsNeverReplaced)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString raced = dir.filePath(QStringLiteral("report-signed.pdf"));
    const QString next = dir.filePath(QStringLiteral("report-signed (2).pdf"));
    const QByteArray theirs = QByteArrayLiteral("the other signer's artifact");
    const QByteArray ours = QByteArrayLiteral("%PDF-1.7 this signer's artifact");

    int asked = 0;
    const auto name = [&] {
        ++asked;
        if (asked == 1) {
            // Free when named; taken by the time this writer creates it.
            QFile other(raced);
            EXPECT_TRUE(other.open(QIODevice::WriteOnly));
            other.write(theirs);
            return raced;
        }
        return next;
    };
    const auto artifact = artifactAtEnd(ours);

    EXPECT_EQ(writeSignedFile(artifact->handle(), name), next);
    EXPECT_EQ(asked, 2);
    EXPECT_EQ(contentsOf(raced), theirs) << "a file that appeared after the naming must not be overwritten";
    EXPECT_EQ(contentsOf(next), ours);
}

// A name that stays taken however often it is asked for is a failure, and the
// file under it is untouched.
TEST(WriteSignedFile, ANameThatStaysTakenIsAFailure)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString taken = dir.filePath(QStringLiteral("signed.pdf"));
    touch(taken);
    const auto artifact = artifactAtEnd(QByteArrayLiteral("ours"));
    int asked = 0;

    EXPECT_EQ(writeSignedFile(artifact->handle(),
                              [&] {
                                  ++asked;
                                  return taken;
                              }),
              std::unexpected(SignedFileError::NoFreeName));
    EXPECT_EQ(asked, 8);
    EXPECT_EQ(contentsOf(taken), QByteArrayLiteral("x"));
}

TEST(WriteSignedFile, AFolderNothingCanBeCreatedInIsAWriteFailure)
{
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root creates files in a read-only folder";
    }
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    ASSERT_EQ(::chmod(dir.path().toLocal8Bit().constData(), 0500), 0);
    const auto artifact = artifactAtEnd(QByteArrayLiteral("ours"));
    int asked = 0;

    EXPECT_EQ(writeSignedFile(artifact->handle(),
                              [&] {
                                  ++asked;
                                  return dir.filePath(QStringLiteral("signed.pdf"));
                              }),
              std::unexpected(SignedFileError::WriteFailed));
    EXPECT_EQ(asked, 1) << "a folder that refuses the file is not a taken name to retry";
    ::chmod(dir.path().toLocal8Bit().constData(), 0700);
}

// While the artifact is being copied the name holds only the empty claim: a
// writer killed half-way leaves no truncated signature under the final name.
// The artifact is a pipe fed in slow chunks, so the copy lasts long enough for
// a second thread to look at the name while it runs.
TEST(WriteSignedFile, TheNameNeverHoldsPartOfTheArtifact)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString target = dir.filePath(QStringLiteral("big-signed.pdf"));
    const QByteArray payload(200 * 1024, 'S');

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    std::thread feeder([&] {
        constexpr qsizetype kChunk = 32 * 1024;
        for (qsizetype at = 0; at < payload.size(); at += kChunk) {
            const qsizetype n = std::min(kChunk, payload.size() - at);
            if (::write(fds[1], payload.constData() + at, static_cast<std::size_t>(n)) != n) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        ::close(fds[1]);
    });
    std::atomic<bool> copying{true};
    std::vector<qint64> sizesSeen;
    std::thread observer([&] {
        while (copying) {
            const QFileInfo info(target);
            if (info.exists()) {
                sizesSeen.push_back(info.size());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });

    const auto written = writeSignedFile(fds[0], [&] { return target; });
    copying = false;
    observer.join();
    feeder.join();
    ::close(fds[0]);

    ASSERT_TRUE(written.has_value());
    ASSERT_FALSE(sizesSeen.empty());
    for (const qint64 size : sizesSeen) {
        if (size != 0) {
            EXPECT_EQ(size, payload.size()) << "part of the artifact was visible under the final name mid-copy";
        }
    }
    EXPECT_EQ(contentsOf(target), payload);
}

// A read that fails gives the claimed name back and leaves nothing -- neither
// the claim nor a partial copy beside it. A directory descriptor opens fine
// and fails every read.
TEST(WriteSignedFile, AReadFailingAfterTheClaimLeavesNothingBehind)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString target = dir.filePath(QStringLiteral("big-signed.pdf"));
    QTemporaryDir source;
    ASSERT_TRUE(source.isValid());
    const int unreadable = ::open(source.path().toLocal8Bit().constData(), O_RDONLY | O_DIRECTORY);
    ASSERT_GE(unreadable, 0);

    EXPECT_EQ(writeSignedFile(unreadable, [&] { return target; }),
              std::unexpected(SignedFileError::UnreadableArtifact));
    ::close(unreadable);
    EXPECT_TRUE(entriesOf(dir).isEmpty()) << entriesOf(dir).join(QLatin1Char(',')).toStdString();
}

} // namespace
