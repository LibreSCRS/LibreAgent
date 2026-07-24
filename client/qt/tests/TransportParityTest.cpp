// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Transport parity suite: ONE shared scenario corpus, run twice — once over
// the REAL DBusTransport + FakeAgent (see fakes/TestBus.h / fakes/FakeAgent.h),
// once over the REAL SocketTransport + FakeSocketAgent (see
// fakes/FakeSocketAgent.h) — via gtest typed tests (TransportParity<DBusPolicy>
// / TransportParity<SocketPolicy>), asserting the client sees IDENTICAL
// outcomes regardless of which transport backs it: result payloads (identity
// FieldGroups, certificate lists, credential records, sign meta), fd content
// hashes (photo, signed artifact), phase/finished sequencing, ErrorCode/
// CallError classification, and availability transitions.
//
// Each scenario below scripts BOTH fakes from the SAME `ParityConfig` (a
// small transport-neutral struct each `Env::toConfig()` translates into its
// own fake's `Config` shape) and drives the SAME assertions against
// `TypeParam::Env` — the two fakes' scripting surfaces were kept close enough
// on purpose (see FakeSocketAgent.h's file comment: "mirroring the D-Bus
// FakeAgent's scripting surface where the two wires overlap") that one
// scenario body reads as ONE driver, not two.
//
// ---- corpus (shared subset of DBusIntegrationTest.cpp / SocketIntegrationTest.cpp) ----
//   identity            IdentityReadDeliversGroupedFields
//   photo               PhotoFdRoundTripContentHash (fd content-hash compared)
//   certificates        CertificatesEndToEnd (field-for-field)
//   sign                SignWithTsaUrlProducesIdenticalArtifactAndMeta
//                         (artifact fd content-hash + signMeta compared;
//                         tsaUrl forwarding asymmetry pinned, not "fixed" —
//                         see the note on that test below)
//   credentials         CredentialsListManagePinThenRequiresReList
//                         (list -> manage -> refused-until-relist -> relist ->
//                         manage again)
//   cancel              CancelStopsAnInFlightOperation
//   refusal             MethodEntryRefusalProducesFailedOperation
//   agent-loss mid-op   AgentLossMidOperationTerminalizesLoudly
//   availability        AvailabilityAppearAndVanish
//
// ---- exclusion table (transport-specific; not parametrized here) ----
//   Socket-only, no D-Bus counterpart:
//     - HelloAck feature-token capture/gating (AvailabilityHandshake...,
//       MissingCredentialsFeatureTokenRefusesLocally) — D-Bus has no Hello.
//     - AgentQuiesced availability semantics — a socket-wire-only event.
//     - Non-canonical-frame fail-closed policy, the wedged-GetState bounded
//       probe, the write-after-peer-close EPIPE/SIGPIPE guard, the stale-
//       ConnectionLost-after-reconnect race, and the awaited-reply+malformed-
//       trailer-in-one-batch case — all socket byte-framing mechanics with no
//       D-Bus analogue (D-Bus's own wedge/robustness cases are unit-level, in
//       AgentCardTest.cpp, not this corpus).
//     - The FIFO-delivery / GetSignResult recovery-window cases
//       (ResultWrittenBeforeEntryReturnsIsDeliveredInOrder,
//       SignLostResultRecoveredViaGetSignResult,
//       SignSuppressedResultWithNoRecoveryFailsLoud) — the OBSERVABLE recovery
//       mechanism genuinely differs (D-Bus recovers synchronously inside the
//       AgentOperation ctor via the terminal-triple probe; the socket wire
//       recovers on the next event-loop turn via GetSignResult), so there is
//       no single assertion shape to share; each transport's own suite pins
//       its mechanism already.
//     - SocketPathResolutionOrder — exercises a private filesystem-path
//       helper with no D-Bus counterpart at all (D-Bus resolves a bus name).
//   Present on both fakes, but not part of this corpus:
//     - certificateDer (Pkcs11_1.CertDer / GetCertDer) — both fakes implement
//       it, but only SocketIntegrationTest.cpp exercises it end-to-end today;
//       there is no existing D-Bus FakeAgent integration coverage to
//       parametrize against, so adding it here would be new coverage, not
//       parity — left for a follow-up increment.
//     - op-stall / kLongOperationTimeoutMs "no internal watchdog" contract
//       (OpStallHasNoInternalWatchdogCancelIsTheEscapeValve on both suites) —
//       the contract is already identical and independently pinned on both
//       transports through the SAME transport-neutral AgentOperation code
//       path (no per-transport special-casing exists to diverge). The
//       constant itself is a caller-side budget grep-verified nowhere read by
//       library code, so exercising the literal 35 s wait here would only
//       cost wall-clock time against the <60 s suite budget for zero
//       additional coverage.
//     - Bare discovery (initial reader/card listing, live card insert) — not
//       a standalone scenario here because every scenario below already
//       proves it as setup (`env.card()` resolving non-null on construction);
//       a dedicated bare-discovery case would be redundant with
//       AgentDiscoveryTest.cpp / the D-Bus and socket integration suites.
//
// ---- the pinned tsaUrl asymmetry ----
// SignOptions::tsaUrl (SignOptions.h) rides in AgentCard::sign()'s wire-keyed
// options map on BOTH transports, but the two transports do not carry it the
// same way once it reaches the wire: DBusTransport forwards the whole options
// a{sv} verbatim, so tsaUrl crosses (agent-side ignored today); the socket
// wire's sign-opts shape has no tsaUrl field — it is Config-owned there, not
// per-sign — so SocketTransport::toSignOpts (src/socket/SocketTransport.cpp)
// drops it with a qCWarning rather than inventing a key the agent never
// specified. This is a DOCUMENTED divergence, not a bug: the sign scenario
// below asserts BOTH transports still complete Ok with byte-identical
// artifacts/meta despite it, and asserts the divergent key-forwarding
// explicitly instead of pretending it is uniform. It stays this way until the
// wire's sign-options vocabulary grows a tsaUrl field.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/IdentityRows.h>

#include "ClientTestAccess.h"
#include "fakes/ClientOnHarness.h"
#include "fakes/FakeSocketAgent.h"
#include "fakes/TestBus.h"
#include "socket/MemfdSource.h"
#include "socket/SocketTransport.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QMetaObject>
#include <QObject>
#include <QTemporaryDir>
#include <QThread>
#include <QVariantMap>

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <string>
#include <type_traits>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {

// ---- shared, transport-neutral scenario configuration ----------------------
// Each Env below translates this into its own fake's Config shape; a
// scenario fills in only the fields it needs.

struct ParityCert
{
    QString certId;
    bool signingCapable = false;
    QString subjectCn;
    QString issuerCn;
    QString notBefore;
    QString notAfter;
    quint32 trustStatus = 0; // 0 = Trusted, matching both fakes' CertTrustStatus wire numbering
};

struct ParityCredRecord
{
    QString id;
    QString label;
    bool canChange = true;
};

struct ParityConfig
{
    quint32 capabilities = 0;
    int operationDelayMs = 15;
    bool failMethodEntry = false;
    QByteArray photoBytes;
    QList<ParityCert> certScript;
    QList<ParityCredRecord> credRecords;
    // Sign scenario only: scripted identically on both fakes so the artifact
    // fd content hash and signMeta can be asserted byte-for-byte /
    // field-for-field equal across transports (see the file header — neither
    // fake's historical hardcoded default agrees with the other's).
    QByteArray signArtifactBytes = QByteArrayLiteral("PARITY-SIGNED-ARTIFACT");
    QVariantMap signMeta = QVariantMap{{QStringLiteral("format"), QStringLiteral("pades")},
                                       {QStringLiteral("level"), QStringLiteral("b-lt")},
                                       {QStringLiteral("tsaUsed"), true},
                                       {QStringLiteral("chainComplete"), true}};
};

LibreSCRS::Agent::Wire::SignMeta toWireSignMeta(const QVariantMap& meta)
{
    LibreSCRS::Agent::Wire::SignMeta out;
    out.format = meta.value(QStringLiteral("format")).toString().toStdString();
    out.level = meta.value(QStringLiteral("level")).toString().toStdString();
    out.tsaUsed = meta.value(QStringLiteral("tsaUsed")).toBool();
    out.chainComplete = meta.value(QStringLiteral("chainComplete")).toBool();
    return out;
}

// ---- D-Bus environment: a real DBusTransport + FakeAgent on a private bus --

class DBusEnv
{
public:
    explicit DBusEnv(const ParityConfig& cfg) : m_harness(toConfig(cfg))
    {
        m_client = LibreSCRS::AgentClient::Fakes::makeClient(m_harness);
    }

    [[nodiscard]] AgentClient* client()
    {
        return m_client.get();
    }
    [[nodiscard]] AgentCard* card()
    {
        return m_client->card(m_harness.cardPath());
    }

    // Connection blip only (mirrors DBusIntegrationTest/AgentDiscoveryTest's
    // agent-death-mid-operation scenario): the bus name drops but nothing
    // else changes.
    void vanishAgentMidOp()
    {
        m_harness.unregisterService();
    }
    // Full availability cycle (mirrors DBusIntegrationTest's
    // AvailabilityAppearAndVanish): name drop, then the SAME name re-claimed.
    void vanishAgent()
    {
        m_harness.unregisterService();
    }
    void reappearAgent()
    {
        m_harness.registerService();
    }

    [[nodiscard]] int cancelledOperationCount()
    {
        return m_harness.cancelledOperationCount();
    }
    [[nodiscard]] QString lastSignCertId()
    {
        return m_harness.lastSignCertId();
    }
    [[nodiscard]] QVariantMap lastSignOptions()
    {
        return m_harness.lastSignOptions();
    }
    [[nodiscard]] QByteArray lastSignInputBytes()
    {
        return m_harness.lastSignInputBytes();
    }

private:
    static FakeAgent::Config toConfig(const ParityConfig& cfg)
    {
        FakeAgent::Config out;
        out.capabilities = cfg.capabilities;
        out.operationDelayMs = cfg.operationDelayMs;
        out.failMethodEntry = cfg.failMethodEntry;
        out.photoBytes = cfg.photoBytes;
        for (const ParityCert& c : cfg.certScript) {
            FakeCert fc;
            fc.certId = c.certId;
            fc.signingCapable = c.signingCapable;
            fc.subjectCn = c.subjectCn;
            fc.issuerCn = c.issuerCn;
            fc.notBefore = c.notBefore;
            fc.notAfter = c.notAfter;
            fc.trustStatus = c.trustStatus;
            out.certScript.append(fc);
        }
        for (const ParityCredRecord& r : cfg.credRecords) {
            out.credRecords.append(QVariantMap{{QStringLiteral("id"), r.id},
                                               {QStringLiteral("label"), r.label},
                                               {QStringLiteral("kind"), QStringLiteral("user")},
                                               {QStringLiteral("state"), QStringLiteral("operational")},
                                               {QStringLiteral("can_change"), r.canChange}});
        }
        // Unconditional: only read for a Credentials-kind result, delivered
        // for every completed manage attempt (Ok here — every credentials
        // scenario in this corpus scripts a successful mutation).
        out.credResult =
            QVariantMap{{QStringLiteral("outcome"), QStringLiteral("ok")}, {QStringLiteral("blocked"), false}};
        out.signArtifactBytes = cfg.signArtifactBytes;
        out.signMeta = cfg.signMeta;
        return out;
    }

    Harness m_harness;
    std::unique_ptr<AgentClient> m_client;
};

// ---- socket environment: a real SocketTransport + FakeSocketAgent ----------

constexpr const char* kSocketCardId = "card/0";

class SocketEnv
{
public:
    explicit SocketEnv(const ParityConfig& cfg) : m_dir(QStringLiteral("/tmp/laqt-parity-XXXXXX"))
    {
        EXPECT_TRUE(m_dir.isValid());
        m_path = m_dir.path() + QStringLiteral("/agent.sock");
        FakeSocketAgent::Config agentConfig = toConfig(cfg);
        agentConfig.socketPath = m_path;

        m_thread = new QThread();
        m_thread->start();
        m_context = new QObject();
        m_context->moveToThread(m_thread);

        bool listening = false;
        runOnThread(m_context, [this, &agentConfig, &listening]() {
            m_agent = std::make_unique<FakeSocketAgent>(agentConfig);
            listening = m_agent->listening();
        });
        EXPECT_TRUE(listening) << "could not bind " << m_path.toStdString();

        auto transport = std::make_unique<SocketTransport>(m_path);
        m_client = std::unique_ptr<AgentClient>(ClientTestAccess::create(std::move(transport)));
    }

    ~SocketEnv()
    {
        // Tear the client (and its transport/connection) down BEFORE the
        // agent's worker thread, mirroring SocketIntegrationTest's harness
        // destruction order (the client is always declared/destroyed after
        // the harness there).
        m_client.reset();
        runOnThread(m_context, [this]() { m_agent.reset(); });
        m_context->deleteLater();
        m_thread->quit();
        m_thread->wait();
        delete m_thread;
    }

    [[nodiscard]] AgentClient* client()
    {
        return m_client.get();
    }
    [[nodiscard]] AgentCard* card()
    {
        return m_client->card(QLatin1String(kSocketCardId));
    }

    // Connection blip only (mirrors SocketIntegrationTest's
    // AgentCloseMidOperationFailsInFlightOps): the accepted connection drops,
    // the bound socket stays live.
    void vanishAgentMidOp()
    {
        runOnThread(m_context, [this]() { m_agent->closeAllConnections(); });
    }
    // Full availability cycle (mirrors SocketIntegrationTest's
    // AvailabilityHandshakeFeatureTokensAndReappear): connection dropped AND
    // the socket unbound, so a probe genuinely finds nothing until relisten();
    // there is no bus watcher on this transport, so reappearAgent() also
    // drives the manual reconcile probe a real caller would.
    void vanishAgent()
    {
        runOnThread(m_context, [this]() {
            m_agent->closeAllConnections();
            m_agent->stopListening();
        });
    }
    void reappearAgent()
    {
        runOnThread(m_context, [this]() { m_agent->relisten(); });
        m_client->refreshDiscovery();
    }

    [[nodiscard]] int cancelledOperationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->cancelledOperationCount(); });
        return out;
    }
    [[nodiscard]] QString lastSignCertId()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignCertId(); });
        return out;
    }
    [[nodiscard]] QVariantMap lastSignOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignOptions(); });
        return out;
    }
    [[nodiscard]] QByteArray lastSignInputBytes()
    {
        QByteArray out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignInputBytes(); });
        return out;
    }

private:
    static FakeSocketAgent::Config toConfig(const ParityConfig& cfg)
    {
        FakeSocketAgent::Config out;
        out.capabilities = cfg.capabilities;
        out.operationDelayMs = cfg.operationDelayMs;
        out.failMethodEntry = cfg.failMethodEntry;
        out.photoBytes = cfg.photoBytes;
        for (const ParityCert& c : cfg.certScript) {
            FakeSocketCert fc;
            fc.certId = c.certId;
            fc.signingCapable = c.signingCapable;
            fc.subjectCn = c.subjectCn;
            fc.issuerCn = c.issuerCn;
            fc.notBefore = c.notBefore;
            fc.notAfter = c.notAfter;
            fc.trustStatus = c.trustStatus;
            out.certScript.append(fc);
        }
        for (const ParityCredRecord& r : cfg.credRecords) {
            FakeSocketCredRecord record;
            record.id = r.id;
            record.label = r.label;
            record.canChange = r.canChange;
            out.credRecords.append(record);
        }
        // credOutcome/credBlocked default to Ok/false already — matches the
        // D-Bus side's explicit credResult set above.
        out.signArtifactBytes = cfg.signArtifactBytes;
        out.signMetaOverride = toWireSignMeta(cfg.signMeta);
        return out;
    }

    QTemporaryDir m_dir;
    QString m_path;
    QThread* m_thread = nullptr;
    QObject* m_context = nullptr;
    std::unique_ptr<FakeSocketAgent> m_agent;
    std::unique_ptr<AgentClient> m_client;
};

// ---- typed-test policies ----------------------------------------------------

struct DBusPolicy
{
    using Env = DBusEnv;
};
struct SocketPolicy
{
    using Env = SocketEnv;
};

class ParityPolicyNames
{
public:
    template <typename T>
    static std::string GetName(int index)
    {
        if constexpr (std::is_same_v<T, DBusPolicy>) {
            return "DBus";
        } else if constexpr (std::is_same_v<T, SocketPolicy>) {
            return "Socket";
        } else {
            return std::to_string(index);
        }
    }
};

} // namespace

template <typename Policy>
class TransportParity : public ::testing::Test
{};

using ParityPolicies = ::testing::Types<DBusPolicy, SocketPolicy>;
TYPED_TEST_SUITE(TransportParity, ParityPolicies, ParityPolicyNames);

// ---- identity ---------------------------------------------------------------

TYPED_TEST(TransportParity, IdentityReadDeliversGroupedFields)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::IdentityData;
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // Both fakes script the SAME "personal:given_name" = "Ana" field
    // (identical group/label/value); asserted through the public structural
    // flattener so the comparison covers the wire metadata (labelKey/
    // labelFallback/type riding Field::extra), not just the raw value.
    const QList<IdentityRow> rows = flattenIdentityFields(op->identityResult());
    const auto givenName = std::find_if(
        rows.cbegin(), rows.cend(), [](const IdentityRow& r) { return r.fieldKey == QStringLiteral("given_name"); });
    ASSERT_NE(givenName, rows.cend());
    EXPECT_EQ(givenName->groupKey, QStringLiteral("personal"));
    EXPECT_EQ(givenName->value, QStringLiteral("Ana"));
    EXPECT_EQ(givenName->labelKey, QStringLiteral("label_given_name"));
    EXPECT_EQ(givenName->labelFallback, QStringLiteral("Given name"));
}

// ---- photo: fd content hash --------------------------------------------------

TYPED_TEST(TransportParity, PhotoFdRoundTripContentHash)
{
    using Env = typename TypeParam::Env;
    QByteArray photoBytes = QByteArrayLiteral("\x89PNG\r\n\x1a\n");
    for (int i = 0; i < 256; ++i) {
        photoBytes.append(static_cast<char>(i));
    }
    const QByteArray expectedHash = QCryptographicHash::hash(photoBytes, QCryptographicHash::Sha256);

    ParityConfig cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.photoBytes = photoBytes;
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    std::vector<PhotoItem> photos = op->takePhotos();
    ASSERT_EQ(photos.size(), 1u);
    EXPECT_EQ(photos[0].key, QStringLiteral("personal:photo"));
    ASSERT_TRUE(photos[0].fd.valid());

    const QByteArray received = readFdAll(photos[0].fd.get());
    EXPECT_EQ(received, photoBytes);
    EXPECT_EQ(QCryptographicHash::hash(received, QCryptographicHash::Sha256), expectedHash)
        << "the received FdHandle's content hash must match the agent-side bytes exactly, identically on both "
           "transports";
}

// ---- certificates: field-for-field ------------------------------------------

TYPED_TEST(TransportParity, CertificatesEndToEnd)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    ParityCert pc;
    pc.certId = QStringLiteral("cert-parity-1");
    pc.signingCapable = true;
    pc.subjectCn = QStringLiteral("Parity Signer");
    pc.issuerCn = QStringLiteral("Parity CA");
    pc.notBefore = QStringLiteral("2021-06-01T00:00:00Z");
    pc.notAfter = QStringLiteral("2031-06-01T00:00:00Z");
    pc.trustStatus = 0; // Trusted
    cfg.certScript = {pc};
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    const CertificateInfo& c = certs.constFirst();
    EXPECT_EQ(c.id, QStringLiteral("cert-parity-1"));
    EXPECT_TRUE(c.signingCapable);
    EXPECT_EQ(c.subject, QStringLiteral("Parity Signer"));
    EXPECT_EQ(c.issuer, QStringLiteral("Parity CA"));
    EXPECT_EQ(c.notBefore, QDateTime::fromString(QStringLiteral("2021-06-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.notAfter, QDateTime::fromString(QStringLiteral("2031-06-01T00:00:00Z"), Qt::ISODate));
    EXPECT_EQ(c.trust, TrustStatus::Trusted);
}

// ---- sign: identical artifact/meta, the tsaUrl asymmetry pinned ------------

TYPED_TEST(TransportParity, SignWithTsaUrlProducesIdenticalArtifactAndMeta)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    const QByteArray document = QByteArrayLiteral("the bytes TransportParityTest signs");
    SignOptions options;
    options.format = SignatureFormat::XAdES;
    options.level = SignatureLevel::BT;
    options.packaging = Packaging::Detached;
    options.tsaUrl = QStringLiteral("http://tsa.example/parity"); // the pinned asymmetry — see the file header
    options.extra.insert(QStringLiteral("reason"), QStringLiteral("parity-suite"));

    AgentOperation* op = card->sign(QStringLiteral("cert-for-sign"), makeMemfdDocument(document), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok) << "both transports must complete Ok despite the tsaUrl asymmetry";

    // fd in: both fakes read the document synchronously.
    EXPECT_EQ(env.lastSignCertId(), QStringLiteral("cert-for-sign"));
    EXPECT_EQ(env.lastSignInputBytes(), document);

    // The shared sign-opts vocabulary is identical on both wires.
    const QVariantMap wireOptions = env.lastSignOptions();
    EXPECT_EQ(wireOptions.value(QStringLiteral("format")).toString(), QStringLiteral("xades"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("level")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("packaging")).toString(), QStringLiteral("detached"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("reason")).toString(), QStringLiteral("parity-suite"));

    // The pinned asymmetry itself: D-Bus forwards tsaUrl in the options
    // a{sv}; the socket wire's sign-opts shape has no such field and
    // SocketTransport drops it (with a qCWarning) instead. NOT a bug to
    // "fix" here — see SignOptions.h's tsaUrl doc comment and
    // SocketTransport::toSignOpts's comment (src/socket/SocketTransport.cpp).
    if constexpr (std::is_same_v<TypeParam, DBusPolicy>) {
        EXPECT_EQ(wireOptions.value(QStringLiteral("tsaUrl")).toString(), options.tsaUrl);
    } else {
        EXPECT_FALSE(wireOptions.contains(QStringLiteral("tsaUrl"))) << "tsaUrl must not cross the socket wire";
    }

    // fd content hash + sign meta: both fakes were scripted with the SAME
    // signArtifactBytes/signMeta (ParityConfig's defaults), so these ARE
    // asserted byte-for-byte / field-for-field identical across transports.
    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid());
    const QByteArray receivedArtifact = readFdAll(artifact.get());
    EXPECT_EQ(receivedArtifact, cfg.signArtifactBytes);
    EXPECT_EQ(QCryptographicHash::hash(receivedArtifact, QCryptographicHash::Sha256),
              QCryptographicHash::hash(cfg.signArtifactBytes, QCryptographicHash::Sha256));
    EXPECT_EQ(op->signMeta(), cfg.signMeta);
}

// ---- credentials: list / manage(PinVerb) / mandatory re-list ---------------

TYPED_TEST(TransportParity, CredentialsListManagePinThenRequiresReList)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::PinManagement;
    ParityCredRecord record;
    record.id = QStringLiteral("user:0x86");
    record.label = QStringLiteral("User PIN");
    record.canChange = true;
    cfg.credRecords = {record};
    Env env(cfg);

    AgentCard* card = env.card();
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

    // 3) the mutation drops the listing cache: an immediate second manage on
    // the SAME id is refused (never nullptr) until a fresh listCredentials().
    AgentOperation* refused = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(refused, nullptr);
    ASSERT_TRUE(waitFor([&]() { return refused->isFinished(); }));
    EXPECT_EQ(refused->callError(), CallError::InvalidArguments);

    AgentOperation* relistOp = card->listCredentials();
    ASSERT_NE(relistOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return relistOp->isFinished(); }));
    EXPECT_EQ(relistOp->status(), OperationStatus::Ok);

    AgentOperation* manageAgain = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(manageAgain, nullptr);
    ASSERT_TRUE(waitFor([&]() { return manageAgain->isFinished(); }));
    EXPECT_EQ(manageAgain->status(), OperationStatus::Ok) << "the re-list must restore mutability";
}

// ---- cancel -------------------------------------------------------------------

TYPED_TEST(TransportParity, CancelStopsAnInFlightOperation)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // never fires on its own within the test
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    const int cancelledBefore = env.cancelledOperationCount();
    op->cancel();

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Cancelled);
    EXPECT_GT(env.cancelledOperationCount(), cancelledBefore) << "cancel() must reach the agent-side operation";
}

// ---- method-entry refusal -> failed operation --------------------------------

TYPED_TEST(TransportParity, MethodEntryRefusalProducesFailedOperation)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.failMethodEntry = true; // CapabilityMissing at entry, no operation minted
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
}

// ---- agent loss mid-operation -------------------------------------------------

TYPED_TEST(TransportParity, AgentLossMidOperationTerminalizesLoudly)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // the agent never finishes this op on its own
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    bool finishedSeen = false;
    OperationStatus seenStatus = OperationStatus::Ok;
    ErrorCode seenErrorCode = ErrorCode::None;
    CallError seenCallError = CallError::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        finishedSeen = true;
        seenStatus = op->status();
        seenErrorCode = op->errorCode();
        seenCallError = op->callError();
    });

    env.vanishAgentMidOp();

    ASSERT_TRUE(waitFor([&]() { return finishedSeen; }))
        << "agent loss must terminalize the live operation, not leave it hanging";
    // The SAME transport-neutral sweep (AgentClient::onServiceUnregistered)
    // drives this on both transports, so the outcome is identical: Cancelled
    // / CommunicationError / AgentUnavailable, never Ok.
    EXPECT_EQ(seenStatus, OperationStatus::Cancelled);
    EXPECT_EQ(seenErrorCode, ErrorCode::CommunicationError);
    EXPECT_EQ(seenCallError, CallError::AgentUnavailable);
    EXPECT_FALSE(env.client()->isAvailable());
}

// ---- availability: appear / vanish --------------------------------------------

TYPED_TEST(TransportParity, AvailabilityAppearAndVanish)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(client->readers().size(), 1);

    bool sawUnavailable = false;
    bool sawAvailable = false;
    QObject::connect(client, &AgentClient::availabilityChanged, client,
                     [&](bool available) { (available ? sawAvailable : sawUnavailable) = true; });

    env.vanishAgent();
    ASSERT_TRUE(waitFor([&]() { return sawUnavailable; }));
    EXPECT_FALSE(client->isAvailable());
    EXPECT_TRUE(client->readers().isEmpty());

    env.reappearAgent();
    ASSERT_TRUE(waitFor([&]() { return sawAvailable; }));
    EXPECT_TRUE(client->isAvailable());
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 1; }))
        << "re-appearance must re-run discovery, not just flip the flag";
}
