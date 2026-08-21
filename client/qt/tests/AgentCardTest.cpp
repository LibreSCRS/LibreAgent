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
#include <LibreSCRS/AgentClient/SyncError.h>

#include "fakes/ClientOnHarness.h"
#include "fakes/TestBus.h"

#include <QElapsedTimer>
#include <QSignalSpy>
#include <QThread>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>
#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <utility>
#include <vector>
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

// Issue a ListCredentials and wait for it to COMPLETE. Completion — not the
// method returning an operation path — is what makes ids resolvable: the agent
// writes its snapshot at the end of the read (CredentialListFlow). Every
// mutation below therefore lists THROUGH this helper.
[[nodiscard]] bool listAndAwait(AgentCard* card)
{
    AgentOperation* op = card->listCredentials();
    return op != nullptr && waitFor([op]() { return op->isFinished(); });
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
// populate subject/issuer/notBefore/notAfter plus the typed certificate-
// metadata members (keyUsageBits/extendedKeyUsageOids/chainSubjectCns), and
// retain the raw trust verdict in `extra`.
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

    // The certificate-metadata wire members (u keyUsageBits, as EKU, as
    // chain) reach the consumer as TYPED members, not string-keyed `extra`
    // entries -- so a producer-side rename is a compile error rather than a
    // silently empty value. Asserted here over the RAW hand-marshalled path,
    // i.e. a genuine wire decode.
    EXPECT_EQ(c.keyUsageBits, 0x80u);
    EXPECT_EQ(c.extendedKeyUsageOids, (QStringList{QStringLiteral("1.3.6.1.5.5.7.3.4")}));
    EXPECT_EQ(c.chainSubjectCns, (QStringList{QStringLiteral("Ana Anić"), QStringLiteral("MUP CA Građani")}));
    // Those three keys are GONE from `extra` -- one source of truth, so a
    // consumer cannot read a stale duplicate that nothing keeps in step.
    EXPECT_FALSE(c.extra.contains(QStringLiteral("keyUsageBits")));
    EXPECT_FALSE(c.extra.contains(QStringLiteral("extendedKeyUsageOids")));
    EXPECT_FALSE(c.extra.contains(QStringLiteral("chainSubjectCns")));
    // trustStatusWire stays in `extra`: no typed member mirrors it, and the
    // raw verdict is the only way to recover the cause a non-Trusted value
    // collapsed away.
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

// ---- cert-info `fields` dict, one decode case per wire group ---------------
//
// The wire has always carried the whole grouped dict; until now the decode
// read four named cells plus the security tokens out of it and dropped every
// other group on the floor, so a viewer had no way to reach the data even
// though it had arrived. `extra["fields"]` is that dict, surfaced whole and
// keyed exactly as the agent grouped it.
//
// One case per group key the CDDL enumerates, because the value under test is
// the VOCABULARY surviving the decode, not the loop that copies it: a decode
// that special-cased group names (as the old one did) passes a single-group
// scenario and drops the other twelve. Every case runs over
// `rawCertResult` — the hand-marshalled payload that bypasses the client's own
// operator<< — so this is a genuine foreign wire decode, not a round trip of
// the encoder against itself.
namespace {

struct CertFieldsGroupCase
{
    const char* name; // gtest case name (also the wire group key)
    FakeCertFieldGroups scripted;
    QVariantMap expected; // the expected extra["fields"] value, whole
};

// One group's cells, in both the scripted-in and the expected-out shape, so
// the two can never be written to disagree by a typo.
CertFieldsGroupCase makeCase(const char* group, const QList<std::array<QString, 4>>& cells)
{
    CertFieldsGroupCase c;
    c.name = group;
    QMap<QString, FakeCertField> in;
    QVariantMap out;
    for (const auto& cell : cells) {
        in.insert(cell[0], FakeCertField{cell[1], cell[2], cell[3]});
        out.insert(cell[0], QVariantList{cell[1], cell[2], cell[3]});
    }
    c.scripted.insert(QString::fromLatin1(group), in);
    c.expected.insert(QString::fromLatin1(group), out);
    return c;
}

std::vector<CertFieldsGroupCase> certFieldsGroupCases()
{
    // Keys, labels and values are the agent's own spellings for each group
    // (LmSeams' cert-snapshot builder), not invented ones: a decode that
    // mangled a real key would otherwise pass against a scenario that never
    // used one.
    return {
        makeCase("subject",
                 {{QStringLiteral("o"), QStringLiteral("cert.subject.o"), QStringLiteral("Organization"),
                   QStringLiteral("Republika Srbija")},
                  {QStringLiteral("ou"), QStringLiteral("cert.subject.ou"), QStringLiteral("Organizational Unit"),
                   QStringLiteral("Sertifikaciono telo")},
                  {QStringLiteral("dn"), QStringLiteral("cert.subject.dn"), QStringLiteral("Distinguished Name"),
                   QStringLiteral("CN=Ana Anić, O=Republika Srbija")}}),
        makeCase("issuer", {{QStringLiteral("o"), QStringLiteral("cert.issuer.o"), QStringLiteral("Organization"),
                             QStringLiteral("Republika Srbija")},
                            {QStringLiteral("dn"), QStringLiteral("cert.issuer.dn"),
                             QStringLiteral("Distinguished Name"), QStringLiteral("CN=CA, O=Republika Srbija")}}),
        makeCase("validity", {{QStringLiteral("notBefore"), QStringLiteral("cert.validity.notBefore"),
                               QStringLiteral("Not Before"), QStringLiteral("2020-01-01T00:00:00Z")},
                              {QStringLiteral("notAfter"), QStringLiteral("cert.validity.notAfter"),
                               QStringLiteral("Not After"), QStringLiteral("2030-12-31T23:59:59Z")}}),
        makeCase("publicKey", {{QStringLiteral("algorithm"), QStringLiteral("cert.publicKey.algorithm"),
                                QStringLiteral("Algorithm"), QStringLiteral("ECDSA")},
                               {QStringLiteral("sizeBits"), QStringLiteral("cert.publicKey.sizeBits"),
                                QStringLiteral("Key Size"), QStringLiteral("256")},
                               {QStringLiteral("curveOid"), QStringLiteral("cert.publicKey.curveOid"),
                                QStringLiteral("Curve"), QStringLiteral("1.2.840.10045.3.1.7")}}),
        makeCase("cert", {{QStringLiteral("serial"), QStringLiteral("cert.cert.serial"),
                           QStringLiteral("Serial Number"), QStringLiteral("1A:2B:3C:4D")},
                          {QStringLiteral("version"), QStringLiteral("cert.cert.version"), QStringLiteral("Version"),
                           QStringLiteral("v3")},
                          {QStringLiteral("signatureAlgorithm"), QStringLiteral("cert.cert.signatureAlgorithm"),
                           QStringLiteral("Signature Algorithm"), QStringLiteral("sha256WithRSAEncryption")},
                          {QStringLiteral("subjectKeyIdentifier"), QStringLiteral("cert.cert.subjectKeyIdentifier"),
                           QStringLiteral("Subject Key Identifier"), QStringLiteral("AA:BB:CC")},
                          {QStringLiteral("authorityKeyIdentifier"), QStringLiteral("cert.cert.authorityKeyIdentifier"),
                           QStringLiteral("Authority Key Identifier"), QStringLiteral("DD:EE:FF")}}),
        makeCase("ext",
                 {{QStringLiteral("2.5.29.9"), QStringLiteral("cert.ext.2.5.29.9"),
                   QStringLiteral("X509v3 Subject Directory Attributes (Critical)"), QStringLiteral("30820103")}}),
        // The "critical" cell is how a typed extension group reports that the
        // issuer marked it critical: an ordinary cell, with an empty labelKey
        // marking it as group metadata rather than a row. It is here to prove
        // the wire carries it — the group's own label has no slot on either
        // transport, which is exactly why criticality became a field.
        makeCase("basicConstraints",
                 {{QStringLiteral("isCa"), QStringLiteral("cert.basicConstraints.isCa"), QStringLiteral("CA"),
                   QStringLiteral("false")},
                  {QStringLiteral("pathLen"), QStringLiteral("cert.basicConstraints.pathLen"),
                   QStringLiteral("Path Length Constraint"), QStringLiteral("0")},
                  {QStringLiteral("critical"), QString(), QStringLiteral("Critical"), QStringLiteral("true")}}),
        makeCase("san", {{QStringLiteral("email0"), QStringLiteral("cert.san.email"), QStringLiteral("Email"),
                          QStringLiteral("ana@example.invalid")},
                         {QStringLiteral("dns1"), QStringLiteral("cert.san.dns"), QStringLiteral("DNS"),
                          QStringLiteral("example.invalid")},
                         {QStringLiteral("otherName2"), QStringLiteral("cert.san.otherName"),
                          QStringLiteral("Other Name"), QStringLiteral("A0143012")}}),
        makeCase("ian", {{QStringLiteral("uri0"), QStringLiteral("cert.ian.uri"), QStringLiteral("URI"),
                          QStringLiteral("https://ca.example.invalid/")}}),
        makeCase("crlDp", {{QStringLiteral("url0"), QStringLiteral("cert.crlDp.url0"),
                            QStringLiteral("CRL Distribution Point"), QStringLiteral("http://crl.example.invalid/a")},
                           {QStringLiteral("url1"), QStringLiteral("cert.crlDp.url1"),
                            QStringLiteral("CRL Distribution Point"), QStringLiteral("http://crl.example.invalid/b")}}),
        makeCase("aia", {{QStringLiteral("ocsp0"), QStringLiteral("cert.aia.ocsp0"), QStringLiteral("OCSP Responder"),
                          QStringLiteral("http://ocsp.example.invalid/")},
                         {QStringLiteral("caIssuers0"), QStringLiteral("cert.aia.caIssuers0"),
                          QStringLiteral("CA Issuers"), QStringLiteral("http://aia.example.invalid/ca.cer")}}),
        makeCase("certificatePolicies", {{QStringLiteral("policy0"), QStringLiteral("cert.certificatePolicies.policy0"),
                                          QStringLiteral("Certificate Policy"), QStringLiteral("1.3.6.1.4.1.1.1.1")}}),
        // The agent renders extended key usages by NAME here and falls back to
        // the dotted OID for one the database cannot resolve; both forms are
        // just cell values to this decode, and the case exists to prove that a
        // group appended AFTER this decode was written needs nothing added to
        // it.
        makeCase("eku", {{QStringLiteral("usage0"), QStringLiteral("cert.eku.usage0"),
                          QStringLiteral("Extended Key Usage"), QStringLiteral("E-mail Protection")},
                         {QStringLiteral("usage1"), QStringLiteral("cert.eku.usage1"),
                          QStringLiteral("Extended Key Usage"), QStringLiteral("1.3.6.1.4.1.99999.1")}}),
    };
}

class CertFieldsGroupDecode : public testing::TestWithParam<CertFieldsGroupCase>
{};

} // namespace

TEST_P(CertFieldsGroupDecode, GroupReachesExtraFieldsWhole)
{
    const CertFieldsGroupCase& c = GetParam();

    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.rawCertResult = true; // hand-marshalled raw signal, bypasses operator<<
    FakeCert fc;
    fc.certId = QStringLiteral("fields-group-cert");
    // Nothing else is scripted: the four derived cells would otherwise add
    // groups this case does not own, and the whole-map comparison below is the
    // point — a decode that surfaced only SOME groups must fail here.
    fc.extraFields = c.scripted;
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
    const CertificateInfo& info = certs.constFirst();

    ASSERT_TRUE(info.extra.contains(QStringLiteral("fields")))
        << "the cert-info fields dict must reach the consumer on extra[\"fields\"]";
    EXPECT_EQ(info.extra.value(QStringLiteral("fields")).toMap(), c.expected)
        << "every cell of the '" << c.name << "' group must arrive whole — key, labelKey, labelFallback and value";
}

INSTANTIATE_TEST_SUITE_P(CertInfoWireGroups, CertFieldsGroupDecode, testing::ValuesIn(certFieldsGroupCases()),
                         [](const testing::TestParamInfo<CertFieldsGroupCase>& info) { return info.param.name; });

// The "security" group is the thirteenth CDDL group and the one case that is
// NOT scripted through extraFields: it is derived from the security tokens, so
// scripting it as a raw group would test the fake rather than the decode. It
// must reach `extra["fields"]` like every other group WHILE still populating
// the typed `securityStatus` member — the dict is surfaced in ADDITION to the
// extraction, never instead of it.
TEST(AgentCard, SecurityGroupReachesBothTheTypedMemberAndTheFieldsDict)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.rawCertResult = true;
    FakeCert fc;
    fc.certId = QStringLiteral("security-group-cert");
    fc.trustStatus = 4u; // Expired
    fc.securityStatus = QStringList{QStringLiteral("expired")};
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
    const CertificateInfo& info = certs.constFirst();
    EXPECT_EQ(info.securityStatus, (QStringList{QStringLiteral("expired")}));

    const QVariantMap fields = info.extra.value(QStringLiteral("fields")).toMap();
    const QVariantMap security = fields.value(QStringLiteral("security")).toMap();
    EXPECT_EQ(
        security.value(QStringLiteral("expired")).toList(),
        (QVariantList{QStringLiteral("cert.security.expired"), QStringLiteral("expired"), QStringLiteral("expired")}));
}

// A cert whose wire carried no fields dict at all must not grow an empty
// `fields` key: a consumer distinguishes "the agent sent nothing" from "the
// agent sent an empty group" by the key's absence, and an unconditional insert
// would erase that distinction on every cert.
TEST(AgentCard, ACertWithNoFieldsDictCarriesNoFieldsKey)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20;
    cfg.rawCertResult = true;
    FakeCert fc;
    fc.certId = QStringLiteral("bare-cert");
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
    EXPECT_FALSE(certs.constFirst().extra.contains(QStringLiteral("fields")));
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
//
// The half that matters most is WHEN a listing starts counting: the agent writes
// its snapshot at the END of the read (CredentialListFlow), so having merely
// ISSUED a ListCredentials buys nothing. A client that re-lists and mutates in
// the same turn — without waiting for the listing to finish — is refused exactly
// as if it had never listed.
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

    // Issuing the list is NOT listing: until it completes, the id is still
    // unresolvable. This is the shape a re-list-and-retry recovery takes when it
    // fires both calls in one turn.
    AgentOperation* listOp = card->listCredentials();
    ASSERT_NE(listOp, nullptr);
    AgentOperation* tooEarly = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(tooEarly, nullptr);
    EXPECT_TRUE(tooEarly->isFinished()) << "a mutation issued before the listing COMPLETED must be refused";
    EXPECT_EQ(tooEarly->callError(), CallError::InvalidArguments);

    // Once the read finishes, the same id mints a live operation.
    ASSERT_TRUE(waitFor([&]() { return listOp->isFinished(); }));
    AgentOperation* mutateOp = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(mutateOp, nullptr);
    EXPECT_FALSE(mutateOp->isFinished());

    // The mutation invalidated the listing cache: a stale-id reuse without the
    // mandatory re-list is refused until a fresh ListCredentials.
    AgentOperation* refused2 = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(refused2, nullptr) << "a mutation must drop the listing cache (mandatory re-list before the next mutate)";
    EXPECT_TRUE(refused2->isFinished());
    EXPECT_EQ(refused2->callError(), CallError::InvalidArguments);

    ASSERT_TRUE(listAndAwait(card));
    AgentOperation* recovered = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(recovered, nullptr);
    EXPECT_FALSE(recovered->isFinished()) << "a fresh COMPLETED list restores mutability";
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
    ASSERT_TRUE(listAndAwait(card));

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

// The fake enforces the agent's REQUEST-side wire vocabulary, so a client
// regression in verb spelling fails the suite instead of passing against a
// permissive double. Adapted from the KDE suite's case of the same purpose,
// which drove `managePin()` with a raw wire-verb STRING and an ad hoc options
// map and covered four refusals: an unknown verb, an unknown option key,
// `activateKey` paired with the wrong verb, and `activateKey` mistyped.
//
// Two of those four are unconstructible against this API and so are prevented
// at compile time instead: `ManagePinOptions` is a struct with a single
// `bool`, leaving no unknown option key and no mistyped option value to send.
// A third IS constructible — `ManagePinOptions{true}` paired with a verb it
// does not apply to — but cannot reach the wire, because
// `AgentCard::managePin()` forwards `activateKey` only alongside
// `ActivatePin`; that is asserted from the client end by
// `ManagePinIgnoresActivateKeyOptionOutsideActivatePin` below.
//
// The verb half stays reachable, and this is the case that keeps it covered.
// `PinVerb` is a `std::uint8_t`-backed enum in a shipped header: its
// underlying type is fixed, so a value outside its three enumerators is a
// well-formed value of the type, and `detail::toToken()` answers it with the
// empty token. That is how an out-of-vocabulary verb actually reaches this
// wire — from a consumer that rebuilds the enum from an integer — not by
// anyone writing a bad spelling by hand.
//
// The KDE original identified its refusals by raw wire error name, read off a
// `lastCredentialError()` accessor this API does not have. That discrimination
// survives the scrub on a different axis rather than being lost with the
// accessor: `InvalidRequest` and `UnknownCredential` do collapse onto one
// `CallError` bucket, but `AgentOperation::syncError()` carries the name
// itself, and the assertion below pins it. So this case distinguishes a
// vocabulary refusal from the listing-gate refusal its neighbours cover, by
// assertion and not merely by fixture construction.
//
// What is NOT covered here, because nothing upstream can reach it: the fake's
// option-gate REFUSAL arm. That gate still runs on every ActivatePin call
// below and accepts, but its refusal branch needs a request this API cannot
// construct — an unknown option key or a mistyped one. Its only exerciser was
// the KDE case this one is adapted from, so that branch is unguarded here.
// Recorded so it reads as a known limit rather than as dead code someone
// later deletes for looking unreachable.
TEST(AgentCard, ManagePinEnforcesVerbVocabularyAndKeepsListingOnRefusal)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("user:0x86")},
                                   {QStringLiteral("kind"), QStringLiteral("user")},
                                   {QStringLiteral("state"), QStringLiteral("transport")}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    // Every named verb is inside the agent's closed request-side set: the
    // mutation starts rather than being refused, and the token the fake read
    // off the wire is the contract spelling. A mutation drops the listing, so
    // each iteration re-lists first.
    const std::pair<PinVerb, QString> accepted[] = {
        {PinVerb::Change, QStringLiteral("change")},
        {PinVerb::Unblock, QStringLiteral("unblock")},
        {PinVerb::ActivatePin, QStringLiteral("activate_pin")},
    };
    for (const auto& [verb, token] : accepted) {
        ASSERT_TRUE(listAndAwait(card));
        AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), verb);
        ASSERT_NE(op, nullptr);
        EXPECT_FALSE(op->isFinished()) << "a verb inside the agent's closed set must start, not be refused";
        EXPECT_EQ(h.lastManagePinVerb(), token);
    }

    // A verb outside the three named values maps to the empty token and is
    // refused by the agent's request-side gate.
    ASSERT_TRUE(listAndAwait(card));
    AgentOperation* refused = card->managePin(QStringLiteral("user:0x86"), static_cast<PinVerb>(99));
    ASSERT_NE(refused, nullptr) << "a refused ManagePin mints a FAILED operation, never nullptr";
    EXPECT_TRUE(refused->isFinished());
    EXPECT_EQ(refused->callError(), CallError::InvalidArguments);
    // The axis that says WHICH refusal this was. The bucket above is shared
    // with UnknownCredential -- the listing gate's refusal, which the two
    // neighbouring cases cover -- so without this line the assertions above
    // would pass just as well had the request been refused for the wrong
    // reason entirely.
    ASSERT_TRUE(refused->syncError().has_value()) << "a named entry refusal must carry its name to the consumer";
    EXPECT_EQ(*refused->syncError(), SyncError::InvalidRequest);
    // Non-vacuous only because the loop above left a NON-empty capture behind:
    // an empty reading here is the fake overwriting "activate_pin" with this
    // request's verb, not the absence of any request at all. A build whose
    // managePin() refused locally without sending would leave the loop's last
    // verb standing here, and this line would fail.
    EXPECT_TRUE(h.lastManagePinVerb().isEmpty())
        << "the request reached the agent's gate carrying a verb outside its closed set";

    // That refusal never reached the card, so the listing it would otherwise
    // have invalidated is still current: a well-formed request afterwards
    // mints WITHOUT an intervening re-list.
    AgentOperation* recovered = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(recovered, nullptr);
    EXPECT_FALSE(recovered->isFinished()) << "a vocabulary refusal must not drop the listing cache";
}

// What IS newly reachable through this API — that `activateKey` is actually
// forwarded, and only alongside `ActivatePin` — is exercised here and below.
TEST(AgentCard, ManagePinActivatePinAcceptsActivateKeyOption)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("sign:0x87")},
                                   {QStringLiteral("kind"), QStringLiteral("sign")},
                                   {QStringLiteral("state"), QStringLiteral("operational")}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    ASSERT_TRUE(listAndAwait(card));

    // The fake enforces the SAME closed request-side vocabulary the real
    // agent does (CredentialsAdaptor::ManagePin): activateKey is a known,
    // well-typed key, legal here because the verb is ActivatePin. A client
    // that failed to forward it, or forwarded it under the wrong key/type,
    // would still pass this assertion by accident (an empty options map is
    // ALSO legal here) — the negative test below is what actually pins the
    // forwarding behavior down.
    AgentOperation* activated =
        card->managePin(QStringLiteral("sign:0x87"), PinVerb::ActivatePin, ManagePinOptions{true});
    ASSERT_NE(activated, nullptr);
    EXPECT_FALSE(activated->isFinished()) << "activateKey=true is a legal option paired with ActivatePin";
}

// The defaulted third argument keeps every pre-existing 2-argument call site
// (this file and every sibling suite) source-compatible, and the DEFAULT
// value itself (activateKey=false) must still be a legal ActivatePin call —
// not just the explicit-true form above.
TEST(AgentCard, ManagePinActivatePinDefaultOptionIsStillLegal)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("sign:0x87")},
                                   {QStringLiteral("kind"), QStringLiteral("sign")},
                                   {QStringLiteral("state"), QStringLiteral("operational")}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    ASSERT_TRUE(listAndAwait(card));

    AgentOperation* activated = card->managePin(QStringLiteral("sign:0x87"), PinVerb::ActivatePin);
    ASSERT_NE(activated, nullptr);
    EXPECT_FALSE(activated->isFinished()) << "the default ManagePinOptions must still be a legal ActivatePin call";
}

// Regression guard for the one-sentence implementation contract
// `ManagePinOptions`'s doc comment makes explicit: activateKey is sent ONLY
// alongside ActivatePin. `activateKey` paired with `Change` is a combination
// the fake's request-side gate refuses outright (InvalidRequest, mapped to
// CallError::InvalidArguments) — the SAME gate the positive test above
// exercises. If a future change started forwarding this option
// unconditionally, THIS call would start failing with exactly that refusal
// instead of minting a live operation.
TEST(AgentCard, ManagePinIgnoresActivateKeyOptionOutsideActivatePin)
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
    ASSERT_TRUE(listAndAwait(card));

    AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change, ManagePinOptions{true});
    ASSERT_NE(op, nullptr);
    EXPECT_FALSE(op->isFinished())
        << "activateKey is not applicable to Change; it must not be sent, so this mutation still starts normally";
}
