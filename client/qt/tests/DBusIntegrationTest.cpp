// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end corpus over the REAL DBusTransport + a FakeAgent on a private
// session bus (dbus-run-session): availability appear/vanish, discovery,
// identity, photo (content-hash round trip), certificates, sign (typed
// options -> wire dict, fd in/out), credentials list/manage/re-list, cancel,
// the op-stall contract, and lost-Result recovery. The four adapted KDE
// suites (AgentCardTest/AgentDiscoveryTest/AgentOperationTest/
// AgentResultSignatureTest) pin the individual mechanisms in depth; this file
// is the "does it all actually work end to end over the wire" cross-section,
// so a few scenarios below are deliberately terser restatements of cases
// those suites already cover in detail.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/ClientTimeouts.h>
#include <LibreSCRS/AgentClient/IdentityRows.h>

#include "fakes/ClientOnHarness.h"
#include "fakes/TestBus.h"

#include <QCryptographicHash>
#include <QElapsedTimer>
#include <algorithm>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {

FdHandle makeDocumentFd(const QByteArray& bytes)
{
    int fd = memfd_create("integration-doc", 0);
    if (fd < 0) {
        return FdHandle{};
    }
    if (!bytes.isEmpty()) {
        ssize_t w = ::write(fd, bytes.constData(), static_cast<size_t>(bytes.size()));
        (void)w;
    }
    ::lseek(fd, 0, SEEK_SET);
    return FdHandle{fd};
}

QByteArray readFd(int fd)
{
    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
        return {};
    }
    void* p = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        return {};
    }
    QByteArray out(static_cast<const char*>(p), static_cast<int>(st.st_size));
    ::munmap(p, static_cast<size_t>(st.st_size));
    return out;
}

} // namespace

// ---- availability: appear / vanish -----------------------------------------

TEST(DBusIntegration, AvailabilityAppearAndVanish)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(client->readers().size(), 1);

    bool sawUnavailable = false;
    bool sawAvailable = false;
    QObject::connect(client.get(), &AgentClient::availabilityChanged, client.get(), [&](bool available) {
        if (available) {
            sawAvailable = true;
        } else {
            sawUnavailable = true;
        }
    });

    // Vanish: the bus name drops (a live QDBusServiceWatcher notification, no
    // manual refresh needed).
    h.unregisterService();
    ASSERT_TRUE(waitFor([&]() { return sawUnavailable; }));
    EXPECT_FALSE(client->isAvailable());
    EXPECT_TRUE(client->readers().isEmpty());

    // Appear: the SAME name is re-claimed; the watcher fires the other way.
    h.registerService();
    ASSERT_TRUE(waitFor([&]() { return sawAvailable; }));
    EXPECT_TRUE(client->isAvailable());
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 1; }))
        << "re-appearance must re-run discovery, not just flip the flag";
    EXPECT_NE(client->card(h.cardPath()), nullptr);
}

// ---- agent version: Manager1.Version, and empty once the agent is gone ------
//
// The version rides the SAME once-per-connect Manager1 property fetch that
// primes Features, so these two cases pin both halves of its contract: the
// connected agent's string reaches the public surface verbatim, and it goes
// EMPTY when the agent is not reachable — never a stale string for a dead
// agent, and never an error. SocketIntegrationTest's
// AvailabilityHandshakeFeatureTokensAndReappear pins the HelloAck twin, and
// TransportParityTest's AgentVersion* pair proves the two converge.

TEST(DBusIntegration, AgentVersionReflectsManagerVersionProperty)
{
    FakeAgent::Config cfg;
    cfg.agentVersion = QStringLiteral("4.3.0-test"); // fake serves Manager1.Version
    Harness h(cfg);
    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(client->agentVersion(), QStringLiteral("4.3.0-test"));
}

TEST(DBusIntegration, AgentVersionEmptyWhileUnavailable)
{
    FakeAgent::Config cfg;
    cfg.agentVersion = QStringLiteral("4.3.0-test");
    Harness h(cfg);
    auto client = makeClient(h);
    ASSERT_EQ(client->agentVersion(), QStringLiteral("4.3.0-test"));

    h.unregisterService(); // vanish, same as AvailabilityAppearAndVanish
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(client->agentVersion().isEmpty());

    // Re-appearance re-seeds it from the fresh connect, exactly like Features.
    h.registerService();
    ASSERT_TRUE(waitFor([&]() { return client->isAvailable(); }));
    EXPECT_EQ(client->agentVersion(), QStringLiteral("4.3.0-test"));
}

TEST(DBusIntegration, AgentVersionEmptyAgainstAnAgentWithoutManager1)
{
    FakeAgent::Config cfg;
    cfg.agentVersion = QStringLiteral("4.3.0-test"); // never served: no Manager1 at all
    cfg.exportManager1 = false;
    Harness h(cfg);
    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable()) << "a missing Manager1 must not cost availability";
    EXPECT_TRUE(client->agentVersion().isEmpty())
        << "an agent predating the surface degrades to empty, exactly like features()";
    EXPECT_TRUE(client->features().isEmpty());
}

// ---- reader/card discovery --------------------------------------------------

TEST(DBusIntegration, ReaderAndCardDiscovery)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData | Cap::Pki;
    cfg.preReadAuth = QStringLiteral("Can");
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_TRUE(client->agentInstalled());

    ASSERT_EQ(client->readers().size(), 1);
    AgentReader* reader = client->readers().constFirst();
    EXPECT_EQ(reader->id(), h.readerPath());
    EXPECT_EQ(reader->name(), QStringLiteral("Fake"));
    EXPECT_TRUE(reader->hasCard());
    EXPECT_EQ(reader->cardId(), h.cardPath());

    AgentCard* card = reader->card();
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card, client->card(h.cardPath()));
    EXPECT_EQ(card->readerId(), h.readerPath());
    EXPECT_EQ(card->preReadAuth(), QStringLiteral("Can"));
    EXPECT_EQ(uiStateFor(capabilityBits(card->capabilities())), UiState::Hybrid);
}

// ---- identity: grouped fields end to end -----------------------------------

TEST(DBusIntegration, IdentityReadDeliversGroupedFields)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 15;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // Full round trip through the public structural flattener too — proves
    // the wire metadata (labelKey/labelFallback/type) really rides Field::extra
    // under the canonical keys IdentityRows.h documents, not just that a
    // "personal" group exists.
    const QList<IdentityRow> rows = flattenIdentityFields(op->identityResult());
    const auto givenName = std::find_if(
        rows.cbegin(), rows.cend(), [](const IdentityRow& r) { return r.fieldKey == QStringLiteral("given_name"); });
    ASSERT_NE(givenName, rows.cend());
    EXPECT_EQ(givenName->groupKey, QStringLiteral("personal"));
    EXPECT_EQ(givenName->value, QStringLiteral("Ana"));
    EXPECT_EQ(givenName->labelKey, QStringLiteral("label_given_name"));
    EXPECT_EQ(givenName->labelFallback, QStringLiteral("Given name"));
}

// ---- photo: fd round trip, content hash ------------------------------------

TEST(DBusIntegration, PhotoFdRoundTripContentHash)
{
    // Deliberately larger/binary-ish than the other suites' short literals, so
    // the hash comparison is meaningfully exercising more than a couple of
    // bytes across the sealed-memfd hop.
    QByteArray photoBytes = QByteArrayLiteral("\x89PNG\r\n\x1a\n");
    for (int i = 0; i < 256; ++i) {
        photoBytes.append(static_cast<char>(i));
    }
    const QByteArray expectedHash = QCryptographicHash::hash(photoBytes, QCryptographicHash::Sha256);

    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 15;
    cfg.photoBytes = photoBytes;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    std::vector<PhotoItem> photos = op->takePhotos();
    ASSERT_EQ(photos.size(), 1u);
    EXPECT_EQ(photos[0].key, QStringLiteral("personal:photo"));
    ASSERT_TRUE(photos[0].fd.valid());

    const QByteArray received = readFd(photos[0].fd.get());
    EXPECT_EQ(received, photoBytes);
    EXPECT_EQ(QCryptographicHash::hash(received, QCryptographicHash::Sha256), expectedHash)
        << "the received FdHandle's content hash must match the agent-side bytes exactly";
}

// ---- certificates: the non-raw (client operator<<-produced) wire shape ----
//
// AgentCardTest's DemarshalRealShapedCertPayload exercises operator>> against
// a hand-marshalled (rawCertResult) payload; this exercises the OTHER
// direction the same registered metatypes drive: the FakeAgent building its
// Result signal via the client's own CertInfoWire operator<< (buildCertificateList()).
TEST(DBusIntegration, CertificatesEndToEnd)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    FakeCert fc;
    fc.certId = QStringLiteral("cert-integration-1");
    fc.signingCapable = true;
    fc.subjectCn = QStringLiteral("Integration Signer");
    fc.issuerCn = QStringLiteral("Integration CA");
    fc.notBefore = QStringLiteral("2021-06-01T00:00:00Z");
    fc.notAfter = QStringLiteral("2031-06-01T00:00:00Z");
    fc.trustStatus = 0u; // Trusted
    cfg.certScript = FakeCertList{fc};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    const CertificateInfo& c = certs.constFirst();
    EXPECT_EQ(c.id, QStringLiteral("cert-integration-1"));
    EXPECT_TRUE(c.signingCapable);
    EXPECT_EQ(c.subject, QStringLiteral("Integration Signer"));
    EXPECT_EQ(c.issuer, QStringLiteral("Integration CA"));
    EXPECT_EQ(c.notBefore, QDateTime::fromString(QStringLiteral("2021-06-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.notAfter, QDateTime::fromString(QStringLiteral("2031-06-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.trust, TrustStatus::Trusted);
}

// ---- best-effort certificate warm ------------------------------------------
//
// This wire is the one that actually issues a warm (the socket transport's is
// a documented no-op -- SocketIntegrationTest pins that side, and the parity
// corpus pins the two together). What is asserted here is the pair of
// properties the whole verb exists for: the card work really does reach the
// agent, and the caller is never made to wait for it.

TEST(DBusIntegration, WarmCertificatesReachesTheAgentAndMintsNothingForTheCaller)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    ASSERT_EQ(h.operationCount(), 0);
    const qsizetype childrenBefore = card->children().size();

    card->warmCertificates();

    // The card read really happened agent-side -- a warm that reached nothing
    // would be a no-op with a comment, which is the failure mode worth
    // catching here.
    EXPECT_TRUE(waitFor([&]() { return h.operationCount() == 1; }));
    // ... and nothing was minted on the caller's side to hold, finish or leak.
    EXPECT_EQ(card->children().size(), childrenBefore);

    // Discriminating control: the SAME read through the public operation API
    // does mint a child, so the assertion above is about warms specifically.
    AgentOperation* real = card->readCertificates();
    ASSERT_NE(real, nullptr);
    EXPECT_GT(card->children().size(), childrenBefore);
}

// The property that justifies the verb existing separately from
// readCertificates() at all. The agent accepts the entry call and never
// answers it; a warm that waited for the entry reply -- as every other
// operation-entry path in this transport deliberately does -- would block for
// the full kDefaultCallTimeoutMs budget, which in the GUI consumers of this
// library is the shell's own thread. The margin below is wide on purpose: the
// distinction being drawn is "returns at once" versus "blocks for three
// seconds", not a benchmark.
TEST(DBusIntegration, WarmCertificatesDoesNotWaitOnAWedgedAgent)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.wedgeCertificatesEntry = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    QElapsedTimer timer;
    timer.start();
    card->warmCertificates();
    const qint64 elapsedMs = timer.elapsed();

    EXPECT_LT(elapsedMs, kDefaultCallTimeoutMs / 4)
        << "warmCertificates blocked for " << elapsedMs << " ms against an agent that never replies";
    // The wedge really is wedged: the agent accepted the entry call and minted
    // nothing, so the elapsed time above was measured against a call that
    // genuinely had no reply to find -- not against a fast success.
    EXPECT_EQ(h.operationCount(), 0);
    EXPECT_TRUE(card->children().isEmpty());
}

// The debounce the void-returning API took away from callers: they used to
// hold the pending-call handle themselves and skip while it was non-null.
TEST(DBusIntegration, WarmCertificatesIsDebouncedWhileOneIsInFlightAndRearmsAfter)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    // Both calls happen without returning to the event loop, so the first
    // entry call is provably still in flight when the second is issued -- Qt
    // cannot have delivered its reply yet. No timing assumption involved.
    card->warmCertificates();
    card->warmCertificates();

    EXPECT_TRUE(waitFor([&]() { return h.operationCount() >= 1; }));
    // Pump the loop a while longer with an unsatisfiable predicate: the point
    // is to let the first entry reply land (which clears the guard) and to
    // give a NON-debounced second warm every chance to show up in the count
    // before it is read. The transport's guard is private state with nothing
    // observable to wait on, so a plain settle is the honest shape here.
    (void)waitFor([]() { return false; }, 250);
    EXPECT_EQ(h.operationCount(), 1) << "the second warm was not debounced";

    // The guard releases with its call: a later warm is issued normally.
    card->warmCertificates();
    EXPECT_TRUE(waitFor([&]() { return h.operationCount() == 2; }))
        << "the debounce never rearmed -- warms are suppressed forever after the first";
}

// ---- public-data DER fetch (Pkcs11_1.CertDer, no consent, no Operation) ----
//
// Closes a long-standing transport-parity gap: the socket transport's mirror
// (SocketIntegrationTest's CertificateDerFetchDeliversBytes /
// CertificateDerKeyNotFoundMapsErrorCode) had end-to-end coverage over the
// REAL socket transport; this call's D-Bus counterpart was previously only
// exercised at the unit level (AgentClientTest/AgentOperationTest against the
// bare seam), never over a REAL DBusTransport + FakeAgent on a private bus.

TEST(DBusIntegration, CertificateDerFetchDeliversBytes)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.certDerBytes = QByteArrayLiteral("\x30\x03\x02\x01\x2a");
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    AgentOperation* op = client->certificateDer(h.readerPath(), QStringLiteral("cert-der-1"));
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->certificateDerResult(), cfg.certDerBytes);
    EXPECT_EQ(h.lastCertDerReader(), h.readerPath());
    EXPECT_EQ(h.lastCertDerCertId(), QStringLiteral("cert-der-1"));
}

TEST(DBusIntegration, CertificateDerKeyNotFoundMapsErrorCode)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.certDerKeyNotFound = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentOperation* op = client->certificateDer(h.readerPath(), QStringLiteral("missing"));
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::KeyNotFound);
}

// ---- sign: typed SignOptions -> wire dict + fd in, artifact fd + meta out --

TEST(DBusIntegration, SignTypedOptionsToWireAndArtifactBack)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    // tsaUrl is gated on the "tsa-url" feature token (AgentCard::
    // startOperation) — script it so this exercises the wire encoding, not
    // the client's local refusal.
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("tsa-url")};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    const QByteArray document = QByteArrayLiteral("the bytes DBusIntegrationTest signs");
    SignOptions options;
    options.format = SignatureFormat::XAdES;
    options.level = SignatureLevel::BT;
    options.packaging = Packaging::Detached;
    options.tsaUrl = QStringLiteral("http://tsa.example/integration");
    options.extra.insert(QStringLiteral("reason"), QStringLiteral("integration-suite"));

    AgentOperation* op = card->sign(QStringLiteral("cert-for-sign"), makeDocumentFd(document), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // fd in: the fake read the document synchronously inside Sign().
    EXPECT_EQ(h.lastSignCertId(), QStringLiteral("cert-for-sign"));
    EXPECT_EQ(h.lastSignInputBytes(), document);

    // typed options -> wire dict, over the REAL transport (not the fake seam
    // SeamMappingTest already pins) — proves the encoding survives an actual
    // D-Bus round trip, not just the in-process OperationRequest construction.
    const QVariantMap wireOptions = h.lastSignOptions();
    EXPECT_EQ(wireOptions.value(QStringLiteral("format")).toString(), QStringLiteral("xades"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("level")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("packaging")).toString(), QStringLiteral("detached"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("tsaUrl")).toString(), QStringLiteral("http://tsa.example/integration"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("reason")).toString(), QStringLiteral("integration-suite"));

    // artifact fd out + signMeta.
    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid());
    EXPECT_EQ(readFd(artifact.get()), QByteArrayLiteral("FAKE-SIGNED-ARTIFACT"));
    EXPECT_EQ(op->signMeta().value(QStringLiteral("format")).toString(),
              QStringLiteral("pades")); // the fake's fixed meta script
}

// ---- batch signing: happy path, mid-batch halt, entry gates ----------------

TEST(DBusIntegration, SignBatchHappyPathSignsEveryDocumentUnderOneConsent)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("first.pdf"), makeDocumentFd(QByteArrayLiteral("doc one bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("second.pdf"), makeDocumentFd(QByteArrayLiteral("doc two bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("third.pdf"), makeDocumentFd(QByteArrayLiteral("doc three bytes"))});

    SignOptions options;
    options.format = SignatureFormat::PAdES;
    options.level = SignatureLevel::BB;

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->errorCode(), ErrorCode::None);

    // fd in: the fake read every document synchronously inside SignBatch().
    EXPECT_EQ(h.lastSignBatchCertId(), QStringLiteral("cert-for-batch"));
    EXPECT_EQ(h.lastSignBatchDisplayNames(),
              (QStringList{QStringLiteral("first.pdf"), QStringLiteral("second.pdf"), QStringLiteral("third.pdf")}));
    const QList<QByteArray> receivedDocs = h.lastSignBatchDocumentBytes();
    ASSERT_EQ(receivedDocs.size(), 3);
    EXPECT_EQ(receivedDocs.at(0), QByteArrayLiteral("doc one bytes"));
    EXPECT_EQ(receivedDocs.at(1), QByteArrayLiteral("doc two bytes"));
    EXPECT_EQ(receivedDocs.at(2), QByteArrayLiteral("doc three bytes"));

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 3U);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        EXPECT_EQ(rows[i].error, ErrorCode::None);
        ASSERT_TRUE(rows[i].artifact.valid());
        EXPECT_EQ(readFd(rows[i].artifact.get()), QByteArrayLiteral("FAKE-SIGNED-ARTIFACT"));
        EXPECT_EQ(rows[i].meta.value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    }
    EXPECT_EQ(rows[0].displayName, QStringLiteral("first.pdf"));
    EXPECT_EQ(rows[1].displayName, QStringLiteral("second.pdf"));
    EXPECT_EQ(rows[2].displayName, QStringLiteral("third.pdf"));

    // Second call returns an empty vector — takeBatchResults() takes ownership once.
    EXPECT_TRUE(op->takeBatchResults().empty());
}

// A wrong/blocked signing credential halts the remaining documents: every row
// from the halt point onward (inclusive) carries the SAME halt code and a
// valid-but-zero-length artifact — never an invalid fd (the frozen
// zero-length-sealed-memfd convention). Rows before the halt point still
// carry their real signed bytes. Because >=1 row succeeded, the aggregate
// Finished status is still Ok (the pinned "successCount > 0" terminal rule).
TEST(DBusIntegration, SignBatchMidBatchHaltPreservesEarlierRowsAndZeroesLaterOnes)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    cfg.batchHaltAtIndex = 2;
    cfg.batchHaltErrorCode = static_cast<uint>(ErrorCode::CredentialWrong);
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    for (int i = 0; i < 4; ++i) {
        docs.push_back(BatchDocument{QStringLiteral("doc-%1.pdf").arg(i), makeDocumentFd(QByteArrayLiteral("bytes"))});
    }

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok) << "successCount > 0 (rows 0-1 signed) keeps the aggregate Ok";

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 4U);
    for (int i = 0; i < 2; ++i) {
        EXPECT_EQ(rows[static_cast<std::size_t>(i)].error, ErrorCode::None) << "row " << i;
        ASSERT_TRUE(rows[static_cast<std::size_t>(i)].artifact.valid()) << "row " << i;
        EXPECT_FALSE(readFd(rows[static_cast<std::size_t>(i)].artifact.get()).isEmpty()) << "row " << i;
    }
    for (int i = 2; i < 4; ++i) {
        EXPECT_EQ(rows[static_cast<std::size_t>(i)].error, ErrorCode::CredentialWrong) << "row " << i;
        // Failed row: a VALID, open, zero-length descriptor — never invalid.
        ASSERT_TRUE(rows[static_cast<std::size_t>(i)].artifact.valid()) << "row " << i;
        EXPECT_TRUE(readFd(rows[static_cast<std::size_t>(i)].artifact.get()).isEmpty()) << "row " << i;
    }
}

// A batch halted from the FIRST document (zero rows signed) finishes Error —
// but Operation.SignBatch1.Result still delivers the per-row detail (>=1 row
// attempted), so the client's typed result is never silently empty.
TEST(DBusIntegration, SignBatchHaltedFromFirstDocumentDeliversRowsEvenOnAggregateError)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    cfg.batchHaltAtIndex = 0;
    cfg.batchHaltErrorCode = static_cast<uint>(ErrorCode::CredentialBlocked);
    cfg.finalStatus = 2u; // Error — zero rows signed
    cfg.finalErrorCode = static_cast<uint>(ErrorCode::CredentialBlocked);
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("a.pdf"), makeDocumentFd(QByteArrayLiteral("bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("b.pdf"), makeDocumentFd(QByteArrayLiteral("bytes"))});

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CredentialBlocked);

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 2U) << "rows must still be delivered — the aggregate Error must not swallow them";
    for (const BatchSignRow& row : rows) {
        EXPECT_EQ(row.error, ErrorCode::CredentialBlocked);
        ASSERT_TRUE(row.artifact.valid());
        EXPECT_TRUE(readFd(row.artifact.get()).isEmpty());
    }
}

// The FakeAgent's raceResultBeforeReturn mode (see the Sign lost-result test
// above) applies identically to a batch: the Result signal fires before the
// client subscribes, so recovery goes through Operation.SignBatch1.GetResult
// — the SAME mechanism Sign1 uses, re-sealing every row (including a would-be
// zero-length one) fresh.
TEST(DBusIntegration, SignBatchLostResultRecoveredViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    cfg.raceResultBeforeReturn = true; // Finished (+ Result) fires before the client ever subscribes
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("x.pdf"), makeDocumentFd(QByteArrayLiteral("race doc bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("y.pdf"), makeDocumentFd(QByteArrayLiteral("race doc bytes 2"))});

    AgentOperation* op = card->signBatch(QStringLiteral("certid"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr);

    // Recovered SYNCHRONOUSLY in the ctor via GetResult — no waitFor needed.
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 2U) << "GetResult must recover the rows the live signal never delivered";
    for (const BatchSignRow& row : rows) {
        ASSERT_TRUE(row.artifact.valid());
        EXPECT_EQ(readFd(row.artifact.get()), QByteArrayLiteral("FAKE-SIGNED-ARTIFACT"));
    }
}

// ---- batch signing: entry gates (never reach the wire) ---------------------

TEST(DBusIntegration, MissingBatchSignFeatureRefusesLocally)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "batch-sign"
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("batch-sign")));

    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("a.pdf"), makeDocumentFd(QByteArrayLiteral("bytes"))});

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    EXPECT_EQ(h.operationCount(), 0) << "the gate must refuse before SignBatch ever reaches the wire";
}

// signBatch shares Sign's own tsaUrl/visualSignature feature-token gate (the
// SAME code path in AgentCard::startOperation, not a parallel copy) — proven
// directly against signBatch here rather than assumed from Sign's own test.
TEST(DBusIntegration, SignBatchWithTsaUrlOrVisualSignatureWithoutTheirFeatureTokensRefusesLocally)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")}; // no tsa-url / visual-sign
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> tsaDocs;
    tsaDocs.push_back(BatchDocument{QStringLiteral("a.pdf"), makeDocumentFd(QByteArrayLiteral("bytes"))});
    SignOptions tsaOptions;
    tsaOptions.tsaUrl = QStringLiteral("https://tsa.example/gated-batch");
    AgentOperation* tsaOp = card->signBatch(QStringLiteral("cert-for-batch"), std::move(tsaDocs), tsaOptions);
    ASSERT_NE(tsaOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return tsaOp->isFinished(); }));
    EXPECT_EQ(tsaOp->status(), OperationStatus::Error);
    EXPECT_EQ(tsaOp->errorCode(), ErrorCode::CapabilityMissing);

    std::vector<BatchDocument> visualDocs;
    visualDocs.push_back(BatchDocument{QStringLiteral("b.pdf"), makeDocumentFd(QByteArrayLiteral("bytes"))});
    SignOptions visualOptions;
    visualOptions.visualSignature =
        QVariantMap{{QStringLiteral("page"), 0},      {QStringLiteral("x"), 0.0},
                    {QStringLiteral("y"), 0.0},       {QStringLiteral("width"), 100.0},
                    {QStringLiteral("height"), 50.0}, {QStringLiteral("text"), QStringLiteral("Signed")}};
    AgentOperation* visualOp = card->signBatch(QStringLiteral("cert-for-batch"), std::move(visualDocs), visualOptions);
    ASSERT_NE(visualOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return visualOp->isFinished(); }));
    EXPECT_EQ(visualOp->status(), OperationStatus::Error);
    EXPECT_EQ(visualOp->errorCode(), ErrorCode::CapabilityMissing);

    EXPECT_EQ(h.operationCount(), 0) << "both refusals must fire before SignBatch ever reaches the wire";
}

TEST(DBusIntegration, SignBatchDocumentCountOutsideBoundsRefusesLocally)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    // Zero documents.
    AgentOperation* emptyOp = card->signBatch(QStringLiteral("cert-for-batch"), {}, SignOptions{});
    ASSERT_NE(emptyOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return emptyOp->isFinished(); }));
    EXPECT_EQ(emptyOp->status(), OperationStatus::Error);
    EXPECT_EQ(emptyOp->callError(), CallError::InvalidArguments);
    EXPECT_EQ(emptyOp->errorCode(), ErrorCode::None)
        << "a local argument refusal is a CallError, never a wire ErrorCode";

    // Thirteen documents (kMaxBatchDocuments == 12).
    std::vector<BatchDocument> tooMany;
    for (int i = 0; i < 13; ++i) {
        tooMany.push_back(BatchDocument{QStringLiteral("doc-%1.pdf").arg(i), makeDocumentFd(QByteArrayLiteral("b"))});
    }
    AgentOperation* tooManyOp = card->signBatch(QStringLiteral("cert-for-batch"), std::move(tooMany), SignOptions{});
    ASSERT_NE(tooManyOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return tooManyOp->isFinished(); }));
    EXPECT_EQ(tooManyOp->status(), OperationStatus::Error);
    EXPECT_EQ(tooManyOp->callError(), CallError::InvalidArguments);

    EXPECT_EQ(h.operationCount(), 0) << "both refusals must fire before SignBatch ever reaches the wire";
}

// ---- HelloAck-equivalent feature-token gate (Manager1.Features) ------------
//
// The token-info entry gate is transport-neutral (AgentCard::startOperation),
// not a socket-only special case: an agent whose Manager1.Features never
// advertises "token-info" predates this surface and is refused LOCALLY,
// before ReadTokenInfo ever reaches the wire. Before this gate was lifted
// here, this exact scenario dialed the D-Bus wire, got back UnknownMethod,
// and surfaced as CallError::InvalidArguments/ErrorCode::None instead of the
// CapabilityMissing a version-skewed agent should report — mirrors
// SocketIntegrationTest's MissingTokenInfoFeatureTokenRefusesLocally (the
// SAME gate; TransportParityTest.cpp's
// MissingTokenInfoFeatureRefusesIdenticallyAcrossTransports proves the two
// converge).
TEST(DBusIntegration, MissingTokenInfoFeatureRefusesLocally)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "token-info"
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("token-info")));

    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr) << "a ReadTokenInfo that is refused at entry mints a FAILED operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    // The gate is mandatory: the request must never have reached the wire —
    // no Operation1 is minted at all (the lazy-card-I/O probe: see
    // FakeAgent::operationCount()'s doc comment).
    EXPECT_EQ(h.operationCount(), 0);
    EXPECT_TRUE(client->isAvailable()) << "the local refusal must not cost the session";
}

// ---- credentials: list / manage(PinVerb) / re-list --------------------------

TEST(DBusIntegration, CredentialsListManagePinVerbThenRequiresReList)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.operationDelayMs = 15;
    cfg.credResult = QVariantMap{{QStringLiteral("outcome"), QStringLiteral("ok")}, {QStringLiteral("blocked"), false}};
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("user:0x86")},
                                   {QStringLiteral("kind"), QStringLiteral("user")},
                                   {QStringLiteral("state"), QStringLiteral("operational")},
                                   {QStringLiteral("can_change"), true}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    // 1) list.
    AgentOperation* listOp = card->listCredentials();
    ASSERT_NE(listOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return listOp->isFinished(); }));
    EXPECT_EQ(listOp->status(), OperationStatus::Ok);
    ASSERT_EQ(listOp->credentialsResult().size(), 1);
    EXPECT_EQ(listOp->credentialsResult().constFirst().id, QStringLiteral("user:0x86"));
    EXPECT_TRUE(listOp->credentialsResult().constFirst().canChange);

    // 2) manage(PinVerb::Change) on the listed id.
    AgentOperation* manageOp = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(manageOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return manageOp->isFinished(); }));
    EXPECT_EQ(manageOp->status(), OperationStatus::Ok);
    EXPECT_EQ(manageOp->pinResult().outcome, CredentialOutcome::Ok);

    // 3) re-list is mandatory: the mutation dropped the listing cache, so an
    // immediate second manage() on the SAME id is refused (never nullptr —
    // a non-null failed op) until a fresh listCredentials().
    AgentOperation* refused = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(refused, nullptr);
    EXPECT_TRUE(refused->isFinished());
    EXPECT_EQ(refused->callError(), CallError::InvalidArguments);

    AgentOperation* relistOp = card->listCredentials();
    ASSERT_NE(relistOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return relistOp->isFinished(); }));
    EXPECT_EQ(relistOp->status(), OperationStatus::Ok);

    AgentOperation* manageAgain = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(manageAgain, nullptr);
    EXPECT_FALSE(manageAgain->isFinished()) << "the re-list must restore mutability";
    ASSERT_TRUE(waitFor([&]() { return manageAgain->isFinished(); }));
    EXPECT_EQ(manageAgain->status(), OperationStatus::Ok);
}

// ---- cancel -----------------------------------------------------------------

TEST(DBusIntegration, CancelStopsAnInFlightOperation)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // never fires on its own within the test
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->sign(QStringLiteral("certid"), makeDocumentFd({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    int cancelledBefore = h.cancelledOperationCount();
    op->cancel();

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Cancelled);
    EXPECT_GT(h.cancelledOperationCount(), cancelledBefore) << "Cancel() must reach the agent-side operation";
}

// ---- op-stall: the library has no INTERNAL watchdog ------------------------
//
// kLongOperationTimeoutMs (ClientTimeouts.h) is a documented BUDGET for a
// caller's own watchdog — grep-verified nowhere in AgentOperation/DBusTransport
// is it read to auto-fail a stalled op, and there is no public way to inject a
// shorter budget without adding new surface. Driving the real 35s cap end to
// end would make this suite needlessly slow for no additional coverage (the
// constant's VALUE is already pinned by TypesTest.cpp). What IS this
// integration suite's job: prove the actual contract a caller relies on — an
// op the agent never completes stays un-finished indefinitely (no silent
// auto-fail), and `cancel()` is the escape valve a caller's own watchdog would
// invoke. The socket suite's OpStallHasNoInternalWatchdogCancelIsTheEscapeValve
// pins the identical contract over that transport; TransportParityTest.cpp
// deliberately excludes the literal 35 s wait (see its file header) since both
// suites already independently pin the SAME transport-neutral behavior.
TEST(DBusIntegration, OpStallHasNoInternalWatchdogCancelIsTheEscapeValve)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // the agent never finishes this op on its own
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    // Well past every OTHER budget in this library (kDefaultCallTimeoutMs,
    // kHandshakeTimeoutMs) but nowhere near kLongOperationTimeoutMs: if any
    // internal timeout auto-failed the op, it would have fired by now.
    QDeadlineTimer settle(kDefaultCallTimeoutMs * 2);
    while (!settle.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(1);
    }
    EXPECT_FALSE(op->isFinished())
        << "no internal watchdog exists — a caller must enforce kLongOperationTimeoutMs itself";

    // A caller's own watchdog would call cancel() at its budget; prove it
    // still works after the op has been sitting un-finished.
    op->cancel();
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Cancelled);
}

// ---- lost-Result recovery: Finished fires before the subscriber -----------
//
// The FakeAgent's raceResultBeforeReturn mode fires the typed Result AND
// Finished SYNCHRONOUSLY inside the method-entry call, before Sign()/
// ReadIdentity()/etc. even returns the operation's path — so by the time
// AgentOperation subscribes, both signals are already gone. The ctor's
// terminal-triple probe must recover the outcome, and — because the typed
// result was never seen live — pull the payload through GetResult().
TEST(DBusIntegration, LostResultRecoveredWhenFinishedFiresBeforeSubscription)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.raceResultBeforeReturn = true; // Finished (+ Result) fires before the client ever subscribes
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    const QByteArray document = QByteArrayLiteral("pre-subscription-race-document");
    AgentOperation* op = card->sign(QStringLiteral("certid"), makeDocumentFd(document), SignOptions{});
    ASSERT_NE(op, nullptr);

    // Recovered SYNCHRONOUSLY in the ctor — no waitFor needed, and none of
    // this required a live signal delivery at all.
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid()) << "GetResult must recover the artifact the live signal never delivered";
    EXPECT_EQ(readFd(artifact.get()), QByteArrayLiteral("FAKE-SIGNED-ARTIFACT"));

    // The queued finished() signal still reaches a consumer that connects
    // right after the minting call returns (the entry-refusal contract
    // extends to every pre-subscription-race recovery, not just refusals).
    int finishedCount = 0;
    QObject::connect(op, &AgentOperation::finished, op, [&finishedCount]() { ++finishedCount; });
    QCoreApplication::processEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(finishedCount, 1);
}
