// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one output-naming rule for a signed document: every format and
// packaging, and the collision search that never hands back an existing file.
// Then the one writer of that file: the name claimed exclusively, the artifact
// committed over the claim in one step, nothing left behind by a failure.

#include <LibreSCRS/AgentClient/SignOptions.h>

#include <QBuffer>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QTemporaryDir>
#include <QTemporaryFile>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>
#include <vector>

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
        {"invoice.xml", SignatureFormat::XAdES, Packaging::Enveloping, "invoice-signed.xml"},
        {"invoice.xml", SignatureFormat::XAdES, Packaging::Detached, "invoice.xml.xsig"},
        {"data.bin", SignatureFormat::CAdES, Packaging::Detached, "data.bin.p7s"},
        {"data.bin", SignatureFormat::CAdES, Packaging::Enveloping, "data.bin.p7m"},
        {"data.bin", SignatureFormat::CAdES, Packaging::Enveloped, "data.bin.p7m"},
        {"claims.json", SignatureFormat::JAdES, Packaging::Detached, "claims.json.jose"},
        {"claims.json", SignatureFormat::JAdES, Packaging::Enveloping, "claims.json.jose"},
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

/// Hands out its bytes in chunks no larger than the writer's, and runs
/// @p beforeChunk before every chunk after the first; fails the read once
/// @p failAfter bytes are out, when set.
class ScriptedArtifact : public QIODevice
{
public:
    ScriptedArtifact(QByteArray bytes, qint64 failAfter = -1) : m_bytes(std::move(bytes)), m_failAfter(failAfter)
    {
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
    }
    bool isSequential() const override
    {
        return true;
    }
    std::function<void()> beforeChunk;

protected:
    qint64 readData(char* data, qint64 maxSize) override
    {
        if (m_failAfter >= 0 && m_offset >= m_failAfter) {
            return -1;
        }
        if (m_offset > 0 && beforeChunk) {
            beforeChunk();
        }
        const qint64 n = std::min<qint64>({maxSize, m_bytes.size() - m_offset, 64 * 1024});
        std::memcpy(data, m_bytes.constData() + m_offset, static_cast<std::size_t>(n));
        m_offset += n;
        return n;
    }
    qint64 writeData(const char*, qint64) override
    {
        return -1;
    }

private:
    QByteArray m_bytes;
    qint64 m_failAfter;
    qint64 m_offset = 0;
};

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

TEST(WriteSignedFile, ADeviceIsReadFromItsStartToo)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QByteArray payload = QByteArrayLiteral("<xades/>");
    QByteArray backing = payload;
    QBuffer device(&backing);
    ASSERT_TRUE(device.open(QIODevice::ReadOnly));
    ASSERT_TRUE(device.seek(payload.size()));
    const QString target = dir.filePath(QStringLiteral("doc-signed.xml"));

    const auto written = writeSignedFile(device, [&] { return target; });

    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(contentsOf(target), payload);
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
    QBuffer closed;
    EXPECT_EQ(writeSignedFile(closed, [&] { return target; }), std::unexpected(SignedFileError::UnreadableArtifact));
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
TEST(WriteSignedFile, TheNameNeverHoldsPartOfTheArtifact)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString target = dir.filePath(QStringLiteral("big-signed.pdf"));
    const QByteArray payload(200 * 1024, 'S');
    ScriptedArtifact artifact(payload);
    std::vector<qint64> sizesSeen;
    artifact.beforeChunk = [&] { sizesSeen.push_back(QFileInfo(target).size()); };

    const auto written = writeSignedFile(artifact, [&] { return target; });

    ASSERT_TRUE(written.has_value());
    ASSERT_FALSE(sizesSeen.empty());
    for (const qint64 size : sizesSeen) {
        EXPECT_EQ(size, 0) << "part of the artifact was visible under the final name mid-copy";
    }
    EXPECT_EQ(contentsOf(target), payload);
}

// A read that fails half-way gives the claimed name back and leaves nothing --
// neither the claim nor a partial copy beside it.
TEST(WriteSignedFile, AReadFailingMidCopyLeavesNothingBehind)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    const QString target = dir.filePath(QStringLiteral("big-signed.pdf"));
    ScriptedArtifact artifact(QByteArray(200 * 1024, 'S'), 64 * 1024);

    EXPECT_EQ(writeSignedFile(artifact, [&] { return target; }), std::unexpected(SignedFileError::UnreadableArtifact));
    EXPECT_TRUE(entriesOf(dir).isEmpty()) << entriesOf(dir).join(QLatin1Char(',')).toStdString();
}

} // namespace
