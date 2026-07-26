// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentCard / AgentReader typed proxies over a real DBusTransport + FakeAgent:
// properties reflect the fake, update on PropertiesChanged, and sign() mints a
// working AgentOperation. Adapted from the lifted KDE suite of the same name
// (see fakes/FakeAgent.h) to the scrubbed public API: AgentCard/AgentReader
// have no public constructor anymore (only AgentClient mints them), a card
// only reachable via discovery is exercised through `AgentClient::card()`/
// `reader()`; entry refusals mint a non-null FAILED operation instead of
// nullptr; `managePin()` takes a typed `PinVerb`, not a wire-verb string.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/ClientTimeouts.h>

#include "fakes/ClientOnHarness.h"
#include "fakes/TestBus.h"

#include <QElapsedTimer>
#include <QSignalSpy>
#include <QThread>
#include <QTimer>
#include <algorithm>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {
// Build an FdHandle over a memfd holding @p bytes, rewound for reading — a
// stand-in for the document fd a real Sign caller would pass. FdHandle owns
// the descriptor end to end; the caller must NOT also close it.
FdHandle makeDocumentFd(const QByteArray& bytes)
{
    int fd = memfd_create("fake-doc", 0);
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
} // namespace

TEST(AgentCard, PropertiesReflectFake)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData | Cap::Pki;
    cfg.preReadAuth = QStringLiteral("Can");
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // capabilityTokens() enumerates in ascending bit order: Pki (bit0) before
    // IdentityData (bit1), regardless of the OR order the fake was configured with.
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki"), QStringLiteral("IdentityData")}));
    EXPECT_EQ(card->preReadAuth(), QStringLiteral("Can"));
    EXPECT_EQ(card->readerId(), h.readerPath());
}

TEST(AgentCard, PreReadAuthAllThreeVocabularyValues)
{
    for (const auto& [wire, expected] :
         {std::pair{QStringLiteral("None"), PreReadAuth::None}, std::pair{QStringLiteral("Mrz"), PreReadAuth::Mrz},
          std::pair{QStringLiteral("Can"), PreReadAuth::Can}}) {
        FakeAgent::Config cfg;
        cfg.capabilities = Cap::IdentityData;
        cfg.preReadAuth = wire;
        Harness h(cfg);
        auto client = makeClient(h);
        AgentCard* card = client->card(h.cardPath());
        ASSERT_NE(card, nullptr);
        // The verbatim token round-trips as-is (forwarded, never re-encoded)...
        EXPECT_EQ(card->preReadAuth(), wire) << wire.toStdString();
        // ...and decodes to the same enum the lifted client used to expose directly.
        EXPECT_EQ(preReadAuthFromToken(card->preReadAuth()), expected) << wire.toStdString();
    }
}

// Insertion carries atrHex always, and cardType when the fake scripts an
// unambiguous single-candidate value (empty otherwise -- "empty until known").
TEST(AgentCard, InsertionCarriesAtrHexAndScriptedCardType)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.cardType = QStringLiteral("SRB-eID");
    cfg.atrHex = QStringLiteral("3B7F96000080318065B085040132900085");
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->cardType(), QStringLiteral("SRB-eID"));
    EXPECT_EQ(card->atrHex(), QStringLiteral("3B7F96000080318065B085040132900085"));
}

TEST(AgentCard, InsertionLeavesCardTypeEmptyWhenNotScripted)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    // cfg.cardType left at its default (empty) -- models the ambiguous/
    // not-yet-known multi-candidate case.
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_TRUE(card->cardType().isEmpty());
}

// The post-read authoritative update flips cardType and fires the
// DEDICATED cardTypeChanged() signal (in addition to the generic changed()).
TEST(AgentCard, CardTypePropertiesChangedFlipsValueAndFiresDedicatedSignal)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_TRUE(card->cardType().isEmpty());

    QSignalSpy changedSpy(card, &AgentCard::changed);
    QSignalSpy cardTypeChangedSpy(card, &AgentCard::cardTypeChanged);
    h.emitCardTypeChanged(QStringLiteral("SRB-eID"));

    ASSERT_TRUE(waitFor([&]() { return card->cardType() == QStringLiteral("SRB-eID"); }));
    EXPECT_GE(changedSpy.count(), 1);
    EXPECT_GE(cardTypeChangedSpy.count(), 1);
}

TEST(AgentCard, SignReturnsOperationThatFinishesOk)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 5;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* op = card->sign(QStringLiteral("certid"), makeDocumentFd({}), SignOptions{});
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_TRUE(op->takeSignedArtifact().valid());
}

TEST(AgentCard, ReadIdentityDeliversFieldMap)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 20;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    // FakeAgent scripts one group ("personal"); the demarshaled result carries it.
    const QList<FieldGroup> groups = op->identityResult();
    const bool hasPersonal = std::any_of(groups.cbegin(), groups.cend(),
                                         [](const FieldGroup& g) { return g.key == QStringLiteral("personal"); });
    EXPECT_TRUE(hasPersonal);
}

// ReadTokenInfo rides the SAME Identity1 result path as ReadIdentity —
// the FakeAgent scripts a DISTINCT "token" group (label/serial_number/
// manufacturer) for it, so this proves the client demarshals it correctly
// through the identical Identity1 wire shape.
TEST(AgentCard, ReadTokenInfoDeliversTokenGroup)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    // The transport-neutral entry gate (AgentCard::startOperation) requires
    // the agent to advertise "token-info" — script it explicitly rather than
    // relying on the default feature set, which does not include it.
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    const QList<FieldGroup> groups = op->identityResult();
    ASSERT_EQ(groups.size(), 1);
    EXPECT_EQ(groups.front().key, QStringLiteral("token"));
    const QList<Field>& fields = groups.front().fields;
    const bool hasLabel =
        std::any_of(fields.cbegin(), fields.cend(), [](const Field& f) { return f.key == QStringLiteral("label"); });
    const bool hasSerial = std::any_of(fields.cbegin(), fields.cend(),
                                       [](const Field& f) { return f.key == QStringLiteral("serial_number"); });
    const bool hasManufacturer = std::any_of(fields.cbegin(), fields.cend(),
                                             [](const Field& f) { return f.key == QStringLiteral("manufacturer"); });
    EXPECT_TRUE(hasLabel);
    EXPECT_TRUE(hasSerial);
    EXPECT_TRUE(hasManufacturer);
}

// The spec's empty-group resilience: an unsupported/best-effort-miss plugin
// answers a present-but-EMPTY "token" group — a SUCCESS, never an error.
TEST(AgentCard, ReadTokenInfoEmptyGroupIsStillSuccess)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.tokenInfoEmpty = true;
    // See ReadTokenInfoDeliversTokenGroup's comment: the transport-neutral
    // entry gate requires the "token-info" feature token to be scripted.
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->errorCode(), ErrorCode::None);
    // The empty group carries no wire entry at all (the outer map's "token"
    // key is absent -- see FakeOperation::buildIdentityFields); the client
    // correctly reports zero groups, not an error.
    EXPECT_TRUE(op->identityResult().isEmpty());
}

// Capability-refused entry: without the PKI bit, ReadTokenInfo throws
// UnsupportedOnThisCard at method entry (no Operation minted) — the fake
// enforces the real gate for real (lacksPkiCapability()), so a regression
// that drops the server-side check cannot pass while throwing against the
// real agent.
TEST(AgentCard, ReadTokenInfoRequiresPkiCapability)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData; // NO Pki
    // Script "token-info" so the client's OWN feature gate (AgentCard::
    // startOperation) does not intercept the call before it ever reaches the
    // fake — this test is specifically about the AGENT-SIDE capability gate.
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr) << "a ReadTokenInfo that errors at entry mints a FAILED operation, never nullptr";
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
}

// a PropertiesChanged whose `changed` map carries the full new value must
// be applied directly — the cached property updates without any blocking Get.
TEST(AgentCard, PropertiesChangedAppliesFromChangedMapDirectly)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}));

    QSignalSpy changedSpy(card, &AgentCard::changed);
    const auto next = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    h.emitCardCapabilitiesChanged(next);

    ASSERT_TRUE(waitFor([&]() { return capabilityBits(card->capabilities()) == next; }));
    EXPECT_GE(changedSpy.count(), 1);
}

// when a property is `invalidated` (empty `changed`), the client takes its
// single-GetAll fallback and still ends up with the current value.
TEST(AgentCard, PropertiesChangedInvalidatedTakesGetAllFallback)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}));

    const auto next = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    h.invalidateCardCapabilities(next); // server now reports `next` via GetAll

    ASSERT_TRUE(waitFor([&]() { return capabilityBits(card->capabilities()) == next; }))
        << "invalidated property should be recovered via the GetAll fallback";
}

// the client's CertInfoWire operator>> must demarshal a REAL-shaped,
// foreign-marshalled (sba{sa{s(ssv)}}uasasu) payload — built by the FakeAgent
// with raw beginStructure/beginMap, NOT the client's own operator<< — carrying
// issuer + notBefore/notAfter field-groups, a non-empty EKU list, a
// multi-entry CN chain, and a non-Trusted trust verdict. operator>> must
// populate subject/issuer/notBefore/notAfter and tolerate/retain the trailing
// members in `extra`.
TEST(AgentCard, DemarshalRealShapedCertPayload)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20; // result arrives after we subscribe
    cfg.rawCertResult = true;  // hand-marshalled raw signal, bypasses operator<<
    FakeCert fc;
    fc.certId = QStringLiteral("sha256-handle");
    fc.signingCapable = true;
    fc.subjectCn = QStringLiteral("Ana Anić");
    fc.issuerCn = QStringLiteral("MUP CA Građani");
    fc.notBefore = QStringLiteral("2020-01-01T00:00:00Z");
    fc.notAfter = QStringLiteral("2030-12-31T23:59:59Z");
    fc.keyUsageBits = 0x80u;
    fc.extendedKeyUsageOids = QStringList{QStringLiteral("1.3.6.1.5.5.7.3.4")};
    fc.chainSubjectCns = QStringList{QStringLiteral("Ana Anić"), QStringLiteral("MUP CA Građani")};
    fc.trustStatus = 2u; // BrokenChain (non-Trusted, non-Unknown)
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
    EXPECT_EQ(c.id, QStringLiteral("sha256-handle"));
    EXPECT_TRUE(c.signingCapable);
    EXPECT_EQ(c.subject, QStringLiteral("Ana Anić"));
    EXPECT_EQ(c.issuer, QStringLiteral("MUP CA Građani"));
    EXPECT_EQ(c.notBefore, QDateTime::fromString(QStringLiteral("2020-01-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.notAfter, QDateTime::fromString(QStringLiteral("2030-12-31T23:59:59Z"), Qt::ISODate));
    EXPECT_EQ(c.trust, TrustStatus::Untrusted); // wire BrokenChain collapses into Untrusted

    // The trailing wire members (u keyUsageBits, as EKU, as chain, u
    // trustStatus) are RETAINED in `extra` for a consumer that renders them.
    EXPECT_EQ(c.extra.value(QStringLiteral("keyUsageBits")).toUInt(), 0x80u);
    EXPECT_EQ(c.extra.value(QStringLiteral("extendedKeyUsageOids")).toStringList(),
              (QStringList{QStringLiteral("1.3.6.1.5.5.7.3.4")}));
    EXPECT_EQ(c.extra.value(QStringLiteral("chainSubjectCns")).toStringList(),
              (QStringList{QStringLiteral("Ana Anić"), QStringLiteral("MUP CA Građani")}));
    EXPECT_EQ(c.extra.value(QStringLiteral("trustStatusWire")).toUInt(), 2u);
}

// trustStatus=5 (Revoked) maps to the client's own Revoked case, and the
// "security" fields-group tokens land in CertificateInfo::securityStatus.
// Exercised over the raw hand-marshalled path (bypasses operator<<), so this
// is a genuine wire decode, not a round-trip of the client's own encoder.
TEST(AgentCard, TrustStatusRevokedMapsToRevokedWithSecurityToken)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.rawCertResult = true;
    FakeCert fc;
    fc.certId = QStringLiteral("revoked-cert");
    fc.trustStatus = 5u;
    fc.securityStatus = QStringList{QStringLiteral("revoked")};
    cfg.certScript = FakeCertList{fc};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    const CertificateInfo& c = certs.constFirst();
    EXPECT_EQ(c.trust, TrustStatus::Revoked);
    EXPECT_EQ(c.securityStatus, (QStringList{QStringLiteral("revoked")}));
    EXPECT_EQ(c.extra.value(QStringLiteral("trustStatusWire")).toUInt(), 5u);
}

// trustStatus=6 (OfflineUnverified) collapses to the client's Unknown case
// (no dedicated client-side enum value for it), but the "offline-unverified"
// token still rides securityStatus for a consumer that wants the nuance.
TEST(AgentCard, TrustStatusOfflineUnverifiedMapsToUnknownWithSecurityToken)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.rawCertResult = true;
    FakeCert fc;
    fc.certId = QStringLiteral("offline-cert");
    fc.trustStatus = 6u;
    fc.securityStatus = QStringList{QStringLiteral("offline-unverified")};
    cfg.certScript = FakeCertList{fc};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    const CertificateInfo& c = certs.constFirst();
    EXPECT_EQ(c.trust, TrustStatus::Unknown);
    EXPECT_EQ(c.securityStatus, (QStringList{QStringLiteral("offline-unverified")}));
    EXPECT_EQ(c.extra.value(QStringLiteral("trustStatusWire")).toUInt(), 6u);
}

// A trustStatus value this build does not recognise at all (neither the
// frozen 0-4 range nor this task's 5/6 append) must still degrade to Unknown
// rather than fail the decode -- the wire-law tolerance policy pinned in
// TokenMap-equivalent client mapping code.
TEST(AgentCard, UnknownFutureTrustStatusMapsToUnknown)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.rawCertResult = true;
    FakeCert fc;
    fc.certId = QStringLiteral("future-cert");
    fc.trustStatus = 42u; // not yet defined by any agent build
    cfg.certScript = FakeCertList{fc};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    const CertificateInfo& c = certs.constFirst();
    EXPECT_EQ(c.trust, TrustStatus::Unknown);
    EXPECT_TRUE(c.securityStatus.isEmpty());
    EXPECT_EQ(c.extra.value(QStringLiteral("trustStatusWire")).toUInt(), 42u);
}

// the FakeAgent's Sign must honor + expose its in-args. Assert verbatim
// certId forwarding, fd readback == the document bytes (read synchronously
// inside Sign() before the client closes its fd), and that the typed
// SignOptions encode to the exact wire tokens over the REAL transport (not
// just the fake-seam mapping SeamMappingTest already pins) — PAdES enveloped.
TEST(AgentCard, SignForwardsCertIdInputAndPadesOptionsVerbatim)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 5;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    const QByteArray doc = QByteArrayLiteral("%PDF-1.7\nthe-document-bytes\n");
    SignOptions options; // typed default: PAdES / BB / Enveloped
    AgentOperation* op = card->sign(QStringLiteral("cert-handle-42"), makeDocumentFd(doc), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));

    EXPECT_EQ(h.lastSignCertId(), QStringLiteral("cert-handle-42"));
    EXPECT_EQ(h.lastSignInputBytes(), doc);

    const QVariantMap seen = h.lastSignOptions();
    ASSERT_TRUE(seen.value(QStringLiteral("format")).metaType() == QMetaType::fromType<QString>());
    EXPECT_EQ(seen.value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    EXPECT_EQ(seen.value(QStringLiteral("packaging")).toString(), QStringLiteral("enveloped"));
}

// Second shape: CAdES detached, to prove the options map is not hard-coded.
TEST(AgentCard, SignForwardsCadesDetachedOptions)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 5;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    const QByteArray doc = QByteArrayLiteral("arbitrary-bytes-for-cades");
    SignOptions options;
    options.format = SignatureFormat::CAdES;
    options.packaging = Packaging::Detached;

    AgentOperation* op = card->sign(QStringLiteral("cid"), makeDocumentFd(doc), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));

    EXPECT_EQ(h.lastSignInputBytes(), doc);
    const QVariantMap seen = h.lastSignOptions();
    EXPECT_EQ(seen.value(QStringLiteral("format")).toString(), QStringLiteral("cades"));
    EXPECT_EQ(seen.value(QStringLiteral("packaging")).toString(), QStringLiteral("detached"));
}

// DELTA (entry refusal never nullptr): a method-entry error (no Operation
// minted) must surface as a non-null, immediately-terminal operation carrying
// the mapped CapabilityMissing errorCode — the scrub's uniform failure surface.
TEST(AgentCard, MethodEntryErrorSurfacesAsFailedOperation)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.failMethodEntry = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    AgentOperation* signOp = card->sign(QStringLiteral("cid"), makeDocumentFd({}), SignOptions{});
    ASSERT_NE(signOp, nullptr) << "a Sign that errors at entry mints a FAILED operation, never nullptr";
    EXPECT_TRUE(signOp->isFinished());
    EXPECT_EQ(signOp->status(), OperationStatus::Error);
    EXPECT_EQ(signOp->errorCode(), ErrorCode::CapabilityMissing);

    AgentOperation* certOp = card->readCertificates();
    ASSERT_NE(certOp, nullptr) << "a ReadCertificates that errors at entry mints a FAILED operation, never nullptr";
    EXPECT_TRUE(certOp->isFinished());
    EXPECT_EQ(certOp->status(), OperationStatus::Error);
    EXPECT_EQ(certOp->errorCode(), ErrorCode::CapabilityMissing);
}

// ADAPTED (structural): the KDE original pointed a directly-constructed
// AgentCard/AgentReader at a side-channel wedged path, bypassing discovery —
// impossible now (AgentCard/AgentReader have no public constructor; only
// AgentClient mints them from a discovered object). Instead: the CARD's own
// Properties interface is wedged from construction (Config::wedgeCardProperties),
// and the assertion moves to the whole discovery round-trip that populates the
// registry — discovery (GetManagedObjects) never touches an object's
// Properties.GetAll at all, so it must complete promptly even with every
// object's property refresh wedged, and the card's properties come from the
// discovery snapshot (never a blocked GetAll).
TEST(AgentCard, ConstructionDoesNotBlockOnWedgedProperties)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.wedgeCardProperties = true;
    Harness h(cfg);

    QElapsedTimer t;
    t.start();
    auto client = makeClient(h);
    const qint64 elapsed = t.elapsed();

    // No blocking GetAll anywhere in discovery → far under the cap.
    EXPECT_LT(elapsed, kDefaultCallTimeoutMs)
        << "client construction took " << elapsed << "ms — discovery must not block on a wedged card GetAll";
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // The discovery snapshot carries the real props — never the wedge.
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}));
}

// the invalidated-fallback GetAll is ASYNC: with the card's Properties wedged
// (never answers), the PropertiesChanged slot must return — and emit changed()
// — near-immediately, far below the cap, and NO state update may land while
// the GetAll hangs. Once the wedge is lifted (a scripted reply), a later
// invalidation's refresh must fetch and apply the current value.
TEST(AgentCard, InvalidatedFallbackDoesNotBlockAndRecoversOnceUnwedged)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.wedgeCardProperties = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    bool changedSeen = false;
    QObject::connect(card, &AgentCard::changed, card, [&]() { changedSeen = true; });

    QElapsedTimer t;
    t.start();
    h.emitCardPropertiesChanged({}, {QStringLiteral("Capabilities")});
    ASSERT_TRUE(waitFor([&]() { return changedSeen; }))
        << "onPropertiesChanged(invalidated) must emit changed() without waiting on the GetAll";
    const qint64 elapsed = t.elapsed();
    EXPECT_LT(elapsed, 1000) << "slot took " << elapsed << "ms — it must not block on the wedged GetAll at all";
    // Nothing clears a cached property on invalidation (only a resolved fetch
    // ever overwrites it) — the STALE (pre-invalidation) value must persist
    // unchanged while the wedged GetAll hangs, never some intermediate "unset".
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}))
        << "the stale value must persist while the wedged GetAll hangs";

    // Unwedge: script an immediate reply carrying the current value, then drive
    // another invalidation — the (new) async refresh must apply it. The first,
    // still-wedged GetAll is superseded and its eventual timeout is discarded.
    const auto next = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    h.scriptCardGetAll(0, QVariantMap{{QStringLiteral("Capabilities"), next}});
    h.emitCardPropertiesChanged({}, {QStringLiteral("Capabilities")});
    ASSERT_TRUE(waitFor([&]() { return capabilityBits(card->capabilities()) == next; }))
        << "the post-unwedge refresh must fetch and apply the value";
}

// a SLOW (not hung) agent: GetAll answers only after a delay. While the refresh
// is pending the proxy's event loop must stay responsive (a 0-ms timer fires
// within a tight bound), the delayed value must eventually land, and every
// changed() — the slot burst and the async apply alike — must be delivered on
// the proxy's own thread (the watcher completes via its owner's event loop).
TEST(AgentCard, SlowGetAllKeepsEventLoopResponsiveThenApplies)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.wedgeCardProperties = true;
    Harness h(cfg);

    const auto next = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    h.scriptCardGetAll(400, QVariantMap{{QStringLiteral("Capabilities"), next}});

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    int changedCount = 0;
    QThread* lastDeliveryThread = nullptr;
    QObject::connect(card, &AgentCard::changed, card, [&]() {
        ++changedCount;
        lastDeliveryThread = QThread::currentThread();
    });

    h.emitCardPropertiesChanged({}, {QStringLiteral("Capabilities")});
    ASSERT_TRUE(waitFor([&]() { return changedCount >= 1; })) << "slot must run (and start the refresh) promptly";
    // The stale (pre-invalidation) value persists — nothing clears it while
    // the delayed GetAll reply is still pending.
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}))
        << "the delayed GetAll reply must not have landed yet";
    EXPECT_EQ(lastDeliveryThread, QThread::currentThread());

    // Responsiveness probe while the refresh is in flight: a 0-ms timer must
    // fire promptly — the loop is NOT being held by the pending GetAll.
    bool timerFired = false;
    qint64 firedAfterMs = -1;
    QElapsedTimer t;
    t.start();
    QTimer::singleShot(0, [&]() {
        timerFired = true;
        firedAfterMs = t.elapsed();
    });
    ASSERT_TRUE(waitFor([&]() { return timerFired; }, 1000));
    EXPECT_LT(firedAfterMs, 200) << "event loop stalled " << firedAfterMs << "ms while the refresh was pending";

    ASSERT_TRUE(waitFor([&]() { return capabilityBits(card->capabilities()) == next; }, kDefaultCallTimeoutMs + 2000))
        << "the slow agent's delayed reply must eventually apply";
    EXPECT_GE(changedCount, 2) << "the async apply must emit changed() again";
    EXPECT_EQ(lastDeliveryThread, QThread::currentThread())
        << "the watcher's apply must be delivered on the proxy's own thread";
}

// stale-reply ordering: a GetAll still in flight (older snapshot) must never
// clobber a newer direct `changed`-map apply that lands while it is pending.
// Discarding a raced refresh also RE-ISSUES it (the invalidated property that
// motivated the fetch has not converged), so a coherent agent's GetAll — which
// serves the post-change state — is re-scripted to the fresh value; the
// recovery fetch must converge there, and the stale snapshot must never show.
TEST(AgentCard, StaleGetAllReplyDoesNotClobberNewerDirectApply)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.wedgeCardProperties = true;
    Harness h(cfg);

    const auto stale = static_cast<unsigned>(Cap::Pki);
    const auto fresh = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    h.scriptCardGetAll(400, QVariantMap{{QStringLiteral("Capabilities"), stale}});

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    int changedCount = 0;
    QObject::connect(card, &AgentCard::changed, card, [&]() { ++changedCount; });

    h.emitCardPropertiesChanged({}, {QStringLiteral("Capabilities")}); // starts the slow (older-snapshot) GetAll
    ASSERT_TRUE(waitFor([&]() { return changedCount >= 1; }));

    h.emitCardPropertiesChanged({{QStringLiteral("Capabilities"), fresh}}); // newer, applied directly
    ASSERT_TRUE(waitFor([&]() { return capabilityBits(card->capabilities()) == fresh; }));
    // From here a coherent agent's GetAll serves the post-change snapshot; the
    // in-flight call already captured the stale script at arrival time.
    h.scriptCardGetAll(100, QVariantMap{{QStringLiteral("Capabilities"), fresh}});

    // The stale reply lands (~400 ms), is discarded, and the re-issued recovery
    // fetch applies the fresh snapshot — the third changed() emission.
    ASSERT_TRUE(waitFor([&]() { return changedCount >= 3; }, kDefaultCallTimeoutMs + 2000))
        << "the discarded raced refresh must re-issue a GetAll that applies";
    EXPECT_EQ(capabilityBits(card->capabilities()), fresh) << "an older GetAll reply clobbered a newer direct apply";

    // Settle a little longer and assert no late flip back to the stale value.
    QDeadlineTimer settle(300);
    while (!settle.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(1);
    }
    EXPECT_EQ(capabilityBits(card->capabilities()), fresh) << "the stale snapshot must never be applied";
}

// pin the raced-refresh recovery exactly: invalidated(P=Capabilities) starts a
// slow GetAll; while it is in flight a direct changed-map for a DIFFERENT
// property (Q=PreReadAuthMethod) bumps the generation, so the old reply — a
// pre-Q snapshot that would revert Q — must be discarded; the client must then
// RE-ISSUE the fetch (assert via the server-side GetAll call count) so P still
// converges to its post-invalidation value.
TEST(AgentCard, DirectApplyRacingRefreshReissuesGetAllAndConverges)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.preReadAuth = QStringLiteral("None");
    cfg.wedgeCardProperties = true;
    Harness h(cfg);

    const auto newCaps = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    // Coherent snapshot at invalidation time: P already new, Q still old.
    h.scriptCardGetAll(400, QVariantMap{{QStringLiteral("Capabilities"), newCaps},
                                        {QStringLiteral("PreReadAuthMethod"), QStringLiteral("None")}});

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    int changedCount = 0;
    QObject::connect(card, &AgentCard::changed, card, [&]() { ++changedCount; });

    h.emitCardPropertiesChanged({}, {QStringLiteral("Capabilities")}); // invalidates P; slow GetAll in flight
    ASSERT_TRUE(waitFor([&]() { return changedCount >= 1; }));
    // P's stale (pre-invalidation) value persists while the GetAll is pending.
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}))
        << "P must still be unconverged while the GetAll is pending";
    ASSERT_TRUE(waitFor([&]() { return h.cardGetAllCallCount() >= 1; })) << "the first GetAll must reach the agent";

    // Q changes and arrives as a direct full-value apply (no new invalidation).
    h.emitCardPropertiesChanged({{QStringLiteral("PreReadAuthMethod"), QStringLiteral("Can")}});
    ASSERT_TRUE(waitFor([&]() { return card->preReadAuth() == QStringLiteral("Can"); }));
    // A coherent agent's GetAll now serves the post-Q state; the in-flight call
    // already captured the pre-Q script at arrival time.
    h.scriptCardGetAll(100, QVariantMap{{QStringLiteral("Capabilities"), newCaps},
                                        {QStringLiteral("PreReadAuthMethod"), QStringLiteral("Can")}});

    // The pre-Q reply lands, is discarded (it would revert Q to None), and the
    // refresh is re-issued: P converges, Q never flickers, and the server saw a
    // second GetAll.
    ASSERT_TRUE(
        waitFor([&]() { return capabilityBits(card->capabilities()) == newCaps; }, kDefaultCallTimeoutMs + 2000))
        << "the invalidated property must converge via the re-issued GetAll";
    EXPECT_EQ(card->preReadAuth(), QStringLiteral("Can"))
        << "the discarded pre-Q snapshot must not have reverted the newer direct apply";
    EXPECT_GE(h.cardGetAllCallCount(), 2) << "the discard must re-issue a GetAll";
}

// AgentReader mirrors AgentCard's async invalidated-fallback: with Properties
// wedged the slot must not block, and once a reply is scripted a later
// invalidation refresh applies the fetched value.
TEST(AgentReader, InvalidatedFallbackDoesNotBlockAndRecoversOnceUnwedged)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.readerName = QStringLiteral("StaleName");
    cfg.wedgeReaderProperties = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentReader* reader = client->reader(h.readerPath());
    ASSERT_NE(reader, nullptr);

    bool changedSeen = false;
    QObject::connect(reader, &AgentReader::changed, reader, [&]() { changedSeen = true; });

    QElapsedTimer t;
    t.start();
    h.emitReaderPropertiesChanged({}, {QStringLiteral("Name")});
    ASSERT_TRUE(waitFor([&]() { return changedSeen; }));
    EXPECT_LT(t.elapsed(), 1000) << "reader slot must not block on the wedged GetAll";
    // The stale (pre-invalidation, discovery-primed) value persists — nothing
    // clears it while the wedged GetAll hangs.
    EXPECT_EQ(reader->name(), QStringLiteral("StaleName")) << "no state may change while the wedged GetAll hangs";

    h.scriptReaderGetAll(0, QVariantMap{{QStringLiteral("Name"), QStringLiteral("Unwedged")}});
    h.emitReaderPropertiesChanged({}, {QStringLiteral("Name")});
    ASSERT_TRUE(waitFor([&]() { return reader->name() == QStringLiteral("Unwedged"); }))
        << "the post-unwedge refresh must fetch and apply the value";
}

TEST(AgentReader, TracksCardId)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentReader* reader = client->reader(h.readerPath());
    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(reader->name(), QStringLiteral("Fake"));
    EXPECT_TRUE(reader->hasCard());
    EXPECT_EQ(reader->cardId(), h.cardPath());
    EXPECT_EQ(reader->card(), client->card(h.cardPath()));
}

// listCredentials mints an Operation the same way readIdentity/readCertificates
// do: the entry succeeds (the returned operation is NOT immediately terminal —
// an entry refusal is), and the op resolves through the card. Its typed
// Operation.Credentials1 result is AgentOperationTest's job — not asserted here.
TEST(AgentCard, ListCredentialsMintsOperation)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->listCredentials();
    ASSERT_NE(op, nullptr);
    EXPECT_FALSE(op->isFinished()) << "a successful entry mints a live operation, not an immediately-terminal one";
}

// The only Credentials1 mint method that had no AgentCard-level mint test: a
// wire-method-name typo would not ship silently. Id-less on the wire; gated on
// the capability bit alone.
TEST(AgentCard, ActivateSigningKeyMintsOperation)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->activateSigningKey();
    ASSERT_NE(op, nullptr);
    EXPECT_FALSE(op->isFinished());
}

// DELTA (entry refusal never nullptr): the agent's Credentials1 capability
// entry gate (without Card1 bit 3 / PinManagement, ALL THREE methods throw
// UnsupportedOnThisCard at entry and mint NO Operation) must surface as a
// non-null, immediately Error-terminal operation with errorCode ==
// CapabilityMissing — the fake enforces the real gate, so a regression that
// drops the client-side check cannot pass while throwing against the real agent.
TEST(AgentCard, CredentialsMethodsRequirePinManagementCapability)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki | Cap::IdentityData; // NO PinManagement
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    const auto assertCapabilityMissing = [](AgentOperation* op) {
        ASSERT_NE(op, nullptr);
        EXPECT_TRUE(op->isFinished());
        EXPECT_EQ(op->status(), OperationStatus::Error);
        EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    };
    assertCapabilityMissing(card->listCredentials());
    assertCapabilityMissing(card->managePin(QStringLiteral("user:0x86"), PinVerb::Change));
    assertCapabilityMissing(card->activateSigningKey());
}

// List-before-mutate is a REAL agent-side contract, not a client courtesy: an
// id-bearing ManagePin without a current listing is refused (CallError::
// InvalidArguments — the mapped UnknownCredential), and any mutation drops the
// agent's listing cache — so a second mutate without the mandatory re-list is
// refused too. The fake enforces both halves so a client that skips the
// re-list fails the suite.
TEST(AgentCard, ManagePinRequiresCurrentListingAndMutationDropsIt)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    // The listing must carry the mutated id — the fake also resolves pinIds
    // against the current listing snapshot.
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("user:0x86")},
                                   {QStringLiteral("kind"), QStringLiteral("user")},
                                   {QStringLiteral("state"), QStringLiteral("operational")}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    // Never listed on this card -> the id cannot be from a current listing.
    AgentOperation* refused1 = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(refused1, nullptr) << "a mutate before any list must be refused, never nullptr";
    EXPECT_TRUE(refused1->isFinished());
    EXPECT_EQ(refused1->callError(), CallError::InvalidArguments);

    // List, then mutate: mints a live operation.
    AgentOperation* listOp = card->listCredentials();
    ASSERT_NE(listOp, nullptr);
    AgentOperation* mutateOp = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(mutateOp, nullptr);
    EXPECT_FALSE(mutateOp->isFinished());

    // The mutation invalidated the listing cache: a stale-id reuse without the
    // mandatory re-list is refused until a fresh ListCredentials.
    AgentOperation* refused2 = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(refused2, nullptr) << "a mutation must drop the listing cache (mandatory re-list before the next mutate)";
    EXPECT_TRUE(refused2->isFinished());
    EXPECT_EQ(refused2->callError(), CallError::InvalidArguments);

    ASSERT_NE(card->listCredentials(), nullptr);
    AgentOperation* recovered = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(recovered, nullptr);
    EXPECT_FALSE(recovered->isFinished()) << "a fresh list restores mutability";
}

// An id absent from the CURRENT listing snapshot is refused (InvalidArguments —
// the mapped UnknownCredential) — the agent resolves ids only against what it
// last listed, so a stale/foreign id from a client-side cache bug fails the
// suite. The refusal itself does not drop the listing (nothing reached the card).
TEST(AgentCard, ManagePinRefusesIdOutsideCurrentListing)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("user:0x86")},
                                   {QStringLiteral("kind"), QStringLiteral("user")},
                                   {QStringLiteral("state"), QStringLiteral("operational")}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    ASSERT_NE(card->listCredentials(), nullptr);

    AgentOperation* refused = card->managePin(QStringLiteral("user:0x99"), PinVerb::Change);
    ASSERT_NE(refused, nullptr) << "an id absent from the current listing cannot be mutated";
    EXPECT_TRUE(refused->isFinished());
    EXPECT_EQ(refused->callError(), CallError::InvalidArguments);

    // The listed id still mints against the surviving listing.
    AgentOperation* ok = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(ok, nullptr);
    EXPECT_FALSE(ok->isFinished());
}

// DELTA (entry refusal never nullptr, no more lastCredentialError() string): a
// Credentials1 method-entry error (no Operation minted) must surface as a
// non-null, immediately-terminal operation with the mapped CallError — the
// typed classification replaces the wire error-name string the KDE original
// exposed via lastCredentialError().
TEST(AgentCard, ManagePinEntryErrorSurfacesMappedCallError)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.credEntryError = true;
    cfg.credEntryErrorName = QStringLiteral("org.librescrs.Agent.Error.UnknownCredential");
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->managePin(QStringLiteral("user:stale"), PinVerb::Change);
    ASSERT_NE(op, nullptr) << "a ManagePin that errors at entry mints a FAILED operation, never nullptr";
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->callError(), CallError::InvalidArguments);
}

// CAPABILITY GAP (deliberately not adapted): the KDE original's
// "ManagePinEnforcesVerbAndOptionsVocabulary" drove the fake with a raw wire
// verb STRING and an ad hoc options map to prove the agent's request-side
// vocabulary gate (verb in {change,unblock,activate_pin}; options limited to
// {activateKey: bool}, legal only with activate_pin) catches a client
// regression. The scrubbed `AgentCard::managePin(pinId, PinVerb)` takes a
// CLOSED enum and no options parameter at all — there is no way to construct
// an invalid verb or an option through this public API anymore, so the
// regression the test guarded against is now prevented at compile time
// instead of runtime. Intentionally not reproduced here.
