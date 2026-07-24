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
// is the "does it all actually work end to end over the wire" cross-section
// the brief asks for, so a few scenarios below are deliberately terser
// restatements of cases those suites already cover in detail.

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

// ---- reader/card discovery --------------------------------------------------

TEST(DBusIntegration, ReaderAndCardDiscovery)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData | Cap::Pki;
    cfg.preReadAuth = QStringLiteral("PaceCan");
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
    EXPECT_EQ(card->preReadAuth(), QStringLiteral("PaceCan"));
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

// ---- sign: typed SignOptions -> wire dict + fd in, artifact fd + meta out --

TEST(DBusIntegration, SignTypedOptionsToWireAndArtifactBack)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 15;
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
// invoke. The literal 35s-budget behavior (a caller-built watchdog actually
// firing at the cap) belongs in the transport-parity suite (Task 13), per the
// brief's own fallback for this case.
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
