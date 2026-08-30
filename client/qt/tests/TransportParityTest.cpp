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
//   identity            IdentityReadDeliversGroupedFields,
//                         IdentityFieldKeysArriveVerbatimWithNoNormalization
//                         (an unusual, agent-scripted group/field key --
//                         mixed case, underscores, a dot, a dash -- arrives
//                         at FieldGroup::key/Field::key byte-for-byte on
//                         both transports; the pass-through law)
//   token info          TokenInfoDeliversTokenGroupAcrossTransports (rides the
//                         SAME Identity1 result shape as identity)
//   photo               PhotoFdRoundTripContentHash (fd content-hash compared)
//   certificates        CertificatesEndToEnd (field-for-field, INCLUDING the
//                         typed certificate-metadata members keyUsageBits /
//                         extendedKeyUsageOids / chainSubjectCns -- each
//                         marshaller populates those in its own private .cpp,
//                         so a one-sided change is exactly the failure this
//                         one shared body catches and a per-transport
//                         assertion cannot)
//   trust verdict       CertificateTrustVerdictAndSecurityTokenMatchAcrossTransports
//                         (trustStatus + the "security" fields-group
//                         token surface identically on both wires)
//   sign                SignWithTsaUrlAndVisualSignatureForwardsIdenticallyAcrossTransports
//                         (artifact fd content-hash + signMeta compared;
//                         tsaUrl + visualSignature now forward identically on
//                         both transports — the historical asymmetry this
//                         scenario used to pin is retired)
//   credentials         CredentialsListManagePinThenRequiresReList
//                         (list -> manage -> refused-until-relist -> relist ->
//                         manage again),
//                         ManagePinActivatePinForwardsActivateKeyIdenticallyAcrossTransports
//                         (the wire's one structural ManagePin option reaches
//                         BOTH wires identically, and only for ActivatePin —
//                         the parity companion to Sign's own tsaUrl/
//                         visualSignature scenario above)
//   cancel              CancelStopsAnInFlightOperation
//   refusal             MethodEntryRefusalProducesFailedOperation
//   agent-loss mid-op   AgentLossMidOperationTerminalizesLoudly
//   availability        AvailabilityAppearAndVanish
//   future ErrorCode    FutureErrorCodeSurfacesIdenticallyAcrossTransports
//                         (wire tolerance: a raw uint32 value past this
//                         build's last known ErrorCode surfaces identically —
//                         end to end — on both transports)
//   feature tokens      FeatureTokensMatchAcrossTransports (Manager1.Features /
//                         HelloAck.features from the same kAgentFeatures source;
//                         an unrecognised extra token surfaces identically)
//   agent version       AgentVersionMatchesAcrossTransports and
//                         AgentVersionEmptyWhileUnavailableAcrossTransports
//                         (the one datum whose two wires share no mechanism at
//                         all — a D-Bus Manager1.Version PROPERTY read vs a
//                         retained HelloAck HANDSHAKE field — surfaces
//                         identically, INCLUDING going empty for a connection
//                         that died and re-seeding on the next connect)
//   feature lifetime    FeaturesEmptyWhileUnavailableAcrossTransports (the
//                         version pair's twin, and the consequential half:
//                         the optional-surface gating reads features(), so a
//                         token set surviving a dead agent offers a consumer
//                         capabilities nothing is behind)
//   agent config        ConfigSnapshotMatchesAcrossTransports (incl. the
//                         canonical TslSources and CscaSources rows — typed
//                         a(sbb)/a(sb) arrays on one wire, a bare `any` on the
//                         other),
//                         SetConfigValueRoundTripsAndAnnouncesAcrossTransports
//                         (the write plus the cache-then-announce ordering
//                         both change notifications owe),
//                         CscaSourcesRoundTripAsRowsAcrossTransports (the
//                         WRITE direction of the second structured value: a
//                         settable key with no marshal arm does not fail, it
//                         degrades to a string and reports success), and
//                         NonSettableConfigKeyRefusesIdenticallyAcrossTransports
//                         / UnknownConfigKeyRefusesIdenticallyAcrossTransports
//                         (an agent-named refusal on D-Bus and a
//                         locally-decided one on the socket — whose
//                         `set-config` grammar cannot encode the key at all —
//                         reaching the caller as ONE enumerator)
//   feature-gated entry MissingTokenInfoFeatureRefusesIdenticallyAcrossTransports
//                         (readTokenInfo() with "token-info" absent from
//                         features() refuses at entry — CapabilityMissing,
//                         operationCount()==0 — before EITHER transport ever
//                         dials the wire; the gate lives in the transport-
//                         neutral AgentCard::startOperation)
//   feature-gated sign  MissingTsaUrlOrVisualSignFeatureRefusesIdenticallyAcrossTransports
//                         (a sign() carrying tsaUrl/visualSignature with
//                         "tsa-url"/"visual-sign" absent from features()
//                         refuses at entry on BOTH transports, exactly like
//                         the token-info gate above; a plain sign with
//                         neither option stays ungated)
//   batch sign          SignBatchHappyPathForwardsIdenticallyAcrossTransports
//                         (rows/meta/artifact fd content-hash compared),
//                         SignBatchMidBatchHaltProducesIdenticalRowsAcrossTransports
//                         (identical per-row halt codes + zero-length
//                         artifacts from the halt point onward; aggregate Ok
//                         since >=1 row signed), and
//                         MissingBatchSignFeatureRefusesIdenticallyAcrossTransports
//                         (the "batch-sign" gate refuses before either
//                         transport dials the wire — the document-count gate
//                         and the shared tsaUrl/visualSignature gate above
//                         are unit-pinned per-transport in DBusIntegrationTest/
//                         SocketIntegrationTest instead of duplicated here)
//   layout preview      LayoutVisualSignatureAndAppearanceFontMatchAcrossTransports
//                         (card-independent, no-Operation
//                         LayoutVisualSignature/GetAppearanceFont — result
//                         fields + font fd content-hash compared;
//                         appearanceFont() caching proven via
//                         appearanceFontCallCount()==1 across two calls),
//                         LayoutTinyBoxClippedArrivesAcrossTransports
//                         (clipped==true arrives identically), and
//                         MissingLayoutPreviewFeatureRefusesLocallyAcrossTransports
//                         (the "layout-preview" gate refuses before either
//                         transport dials the wire, via
//                         layoutCallCount()/appearanceFontCallCount()==0)
//
// ---- exclusion table (transport-specific; not parametrized here) ----
//   Socket-only, no D-Bus counterpart:
//     - HelloAck handshake capture (AvailabilityHandshakeFeatureTokensAndReappear)
//       — the Hello/HelloAck exchange itself is socket-wire-only machinery;
//       D-Bus's own feature-token exposure (Manager1.Features) is pinned by
//       AgentDiscoveryTest.cpp, and this corpus's own
//       FeatureTokensMatchAcrossTransports scenario above already proves the
//       two converge. NOTE: "D-Bus has no Hello" no longer implies "D-Bus has
//       no feature-token GATE" — the token-info entry gate is transport-
//       neutral since it moved into AgentCard::startOperation (see the new
//       scenario above).
//     - MissingCredentialsFeatureTokenRefusesLocally (SocketIntegrationTest.cpp)
//       — the credentials-family gate stays socket-only BY SCOPE, not
//       architecture: this fix round lifted only the token-info gate to the
//       transport-neutral entry point; a pre-contract agent's D-Bus
//       ListCredentials/ManagePin/ActivateSigningKey today still dials the
//       wire and gets UnknownMethod (mapped to CallError::InvalidArguments,
//       not CapabilityMissing) — extending the SAME lift there is a tracked
//       follow-up, not something this corpus already proves converged.
//     - AgentQuiesced availability semantics — a socket-wire-only event.
//     - Non-canonical-frame fail-closed policy, the wedged-GetState bounded
//       probe, the write-after-peer-close EPIPE/SIGPIPE guard, the stale-
//       ConnectionLost-after-reconnect race, and the awaited-reply+malformed-
//       trailer-in-one-batch case — all socket byte-framing mechanics with no
//       D-Bus analogue (D-Bus's own wedge/robustness cases are unit-level, in
//       AgentCardTest.cpp, not this corpus).
//     - SocketPathResolutionOrder — exercises a private filesystem-path
//       helper with no D-Bus counterpart at all (D-Bus resolves a bus name).
//   Present on both fakes, but not part of this corpus:
//     - Lost-result recovery (ResultWrittenBeforeEntryReturnsIsDeliveredInOrder,
//       SignLostResultRecoveredViaGetSignResult,
//       SignSuppressedResultWithNoRecoveryFailsLoud on the socket side;
//       LostResultRecoveredWhenFinishedFiresBeforeSubscription on the D-Bus
//       side) — both transports guarantee recovery, but the OBSERVABLE
//       mechanism genuinely differs (D-Bus recovers synchronously inside the
//       AgentOperation ctor via the terminal-triple probe; the socket wire
//       recovers on the next event-loop turn via GetSignResult), so there is
//       no single assertion shape to share; each transport's own suite pins
//       its mechanism already.
//     - requestProperties/subscribeProperties (the property-refresh seam
//       methods) — no standalone parity scenario because every scenario below
//       exercises them incidentally as setup (AgentCard construction issues
//       the initial property fetch + subscription on both transports); the
//       direct end-to-end case lives in SocketIntegrationTest.cpp, and the
//       D-Bus property/wedge behavior is unit-pinned in AgentCardTest.cpp.
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
// ---- the retired tsaUrl asymmetry ----
// SignOptions::tsaUrl/::visualSignature (SignOptions.h) used to ride in
// AgentCard::sign()'s wire-keyed options map asymmetrically: DBusTransport
// forwarded the whole options a{sv} verbatim (tsaUrl crossed, agent-side
// ignored), while the socket wire's sign-opts shape had no tsaUrl/
// visualSignature field at all, so SocketTransport::toSignOpts
// (src/socket/SocketTransport.cpp) dropped both with a qCWarning. Now that
// the wire's sign-opts vocabulary carries both fields (CDDL's `? tsaUrl`,
// `? visualSignature`), the drop-with-warning branch is gone: both
// transports forward both options identically, and the agent honours them
// end to end. The sign scenario below asserts this directly — identical
// wire-keyed options AND identical artifact/meta on both transports — rather
// than pinning a divergence.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/IdentityRows.h>

#include "ClientTestAccess.h"
#include "CscaAnchorKeys.h"
#include "fakes/ClientOnHarness.h"
#include "fakes/FakeSocketAgent.h"
#include "fakes/TestBus.h"
#include "socket/MemfdSource.h"
#include "socket/SocketTransport.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QMetaObject>
#include <QObject>
#include <QRectF>
#include <QTemporaryDir>
#include <QThread>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>

// The import scenarios below hand over a real descriptor and then read the
// SENDER's own file position back, which is the only thing that tells a
// descriptor from a name (see that scenario's comment).
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

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
    quint32 trustStatus = 0;    // 0 = Trusted, matching both fakes' CertTrustStatus wire numbering
    QStringList securityStatus; // tokens riding the "security" fields-group, mirroring trustStatus
    // The certificate-metadata trailing members, scripted identically on both
    // fakes so the typed CertificateInfo members they land in can be asserted
    // by ONE scenario body against BOTH wires. chainSubjectCns is scripted
    // NON-empty on purpose where it matters: an empty script means "no path
    // resolved", which both fakes substitute [subjectCn] for, and that
    // substitution would mask a marshaller that dropped the member outright.
    quint32 keyUsageBits = 0;
    QStringList extendedKeyUsageOids;
    QStringList chainSubjectCns;
    /// The rest of the `fields` dict — every group beyond the four cells the
    /// members above derive. Scripted ONCE here and re-encoded by each fake
    /// into its own wire form (a nested `a{sa{s(ssv)}}` D-Bus map on one side,
    /// a CBOR map of 3-element arrays on the other), which is the only way a
    /// scenario can assert the two decodes agree on the shape they surface.
    Fakes::FakeCertFieldGroups extraFields;
};

struct ParityCredRecord
{
    QString id;
    QString label;
    bool canChange = true;
};

// One scripted progressive field, transport-neutral (each Env::toConfig
// below hands it to its own fake's wire-typed script). An explicit ORDERED
// list, unlike the final grouped result map, because streaming order is the
// entire point of this feature.
struct ParityIdentityField
{
    QString fieldKey;
    QString labelKey;
    QString labelFallback;
    QString type = QStringLiteral("text");
    QString value;
};
struct ParityIdentityGroup
{
    QString groupKey;
    QList<ParityIdentityField> fields;
};

struct ParityConfig
{
    quint32 capabilities = 0;
    int operationDelayMs = 15;
    // Card-state's cardType/atr, scripted identically on both fakes.
    QString cardType;
    QString atrHex;
    // Manager1.Features / HelloAck.features — mirrors both fakes' default
    // ({"credentials"}); a scenario overrides it to script an extra,
    // unrecognised token or an agent predating the surface (empty).
    QStringList features = {QStringLiteral("credentials")};
    // Manager1.Version / HelloAck.agentVer — the two wires' single version
    // surface, scripted identically so the client-observed string can be
    // compared verbatim across transports (each fake's own default differs
    // on purpose, so a scenario that cares must set this).
    QString agentVersion = QStringLiteral("4.3.0-parity");
    // The Config1 property set, in the canonical client-side shape both fakes
    // accept (see fakes/FakeConfig.h): scripted ONCE here and re-encoded by
    // each fake into its own wire form — a typed a(sbb) property array on
    // D-Bus, a CBOR value the grammar types as bare `any` on the socket.
    QVariantMap agentConfig = Fakes::defaultAgentConfig();
    // The anchor-state dict an ACCEPTED Config1.ImportCscaMasterList answers
    // with, scripted ONCE here in the canonical client-side shape (see
    // fakes/FakeConfig.h) and re-encoded by each fake into its own wire form
    // — a plain `a{sv}` out-arg on D-Bus, a typed CBOR reply arm on the
    // socket. Same reason `agentConfig` above is scripted once: two default
    // dicts, one per fake, would let the thing under test be scripted
    // differently on each side of the comparison.
    QVariantMap cscaAnchorState = Fakes::defaultCscaAnchorState();
    // Engaged -> every import is REFUSED with this named error and installs
    // nothing, on whichever wire the fake speaks.
    std::optional<SyncError> cscaImportError;
    bool failMethodEntry = false;
    // The public-data fetch answers a reply that is OUTSIDE this request's
    // contract — the same fault expressed in each wire's own terms (D-Bus: a
    // reply with no arguments; socket: a reply carrying the wrong arm). Not a
    // refusal: the peer named nothing, the client diagnosed it.
    bool certDerReplyOutsideContract = false;
    quint32 finalStatus = 0;    // 0 Ok / 1 Cancelled / 2 Error
    quint32 finalErrorCode = 0; // Finished errorCode when finalStatus == Error (may be a future/raw value)
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
    // LayoutVisualSignature / GetAppearanceFont, scripted identically on
    // both fakes so a client-observed result can be asserted byte-for-byte /
    // field-for-field equal across transports.
    double layoutFontSize = 9.5;
    double layoutLineHeight = 11.4;
    QStringList layoutLines = {QStringLiteral("Signed by"), QStringLiteral("John Doe")};
    bool layoutClipped = false;
    QByteArray appearanceFontBytes = QByteArrayLiteral("PARITY-LIBERATION-SANS-TTF");
    // Progressive identity-group streaming: an ordered sequence scripted
    // identically on both fakes so groupReady() order + the final union can
    // be asserted byte-for-byte / field-for-field equal across transports.
    // Empty (default): the pre-existing single "personal:given_name" script
    // on both fakes, unaffected.
    QList<ParityIdentityGroup> identityGroupScript;
    // Race the WHOLE op (every scripted group + the final result + Finished)
    // before the minting call even returns — a late subscriber that missed
    // every progressive hint must still converge via the terminal result.
    bool raceResultBeforeReturn = false;
    // SignBatch scenario only: from THIS 0-based row index onward
    // (inclusive), every row's artifact is a ZERO-LENGTH sealed/anonymous fd
    // and its errorCode is batchHaltErrorCode, scripted identically on both
    // fakes (see FakeAgent::Config::batchHaltAtIndex's own doc comment). -1
    // (default) means no halt: every row succeeds.
    int batchHaltAtIndex = -1;
    quint32 batchHaltErrorCode = 0;
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
    /// The lazy-card-I/O probe: a non-zero count means a content read reached
    /// the wire (see FakeAgent::operationCount()'s doc comment).
    [[nodiscard]] int operationCount()
    {
        return m_harness.operationCount();
    }
    [[nodiscard]] int layoutCallCount()
    {
        return m_harness.layoutCallCount();
    }
    [[nodiscard]] int appearanceFontCallCount()
    {
        return m_harness.appearanceFontCallCount();
    }
    [[nodiscard]] QString lastSignCertId()
    {
        return m_harness.lastSignCertId();
    }
    [[nodiscard]] QVariantMap lastSignOptions()
    {
        return m_harness.lastSignOptions();
    }
    [[nodiscard]] QVariantMap lastManagePinOptions()
    {
        return m_harness.lastManagePinOptions();
    }
    [[nodiscard]] QByteArray lastSignInputBytes()
    {
        return m_harness.lastSignInputBytes();
    }
    [[nodiscard]] QString lastSignBatchCertId()
    {
        return m_harness.lastSignBatchCertId();
    }
    [[nodiscard]] QVariantMap lastSignBatchOptions()
    {
        return m_harness.lastSignBatchOptions();
    }
    [[nodiscard]] QStringList lastSignBatchDisplayNames()
    {
        return m_harness.lastSignBatchDisplayNames();
    }
    [[nodiscard]] QList<QByteArray> lastSignBatchDocumentBytes()
    {
        return m_harness.lastSignBatchDocumentBytes();
    }
    [[nodiscard]] int cscaImportCallCount()
    {
        return m_harness.cscaImportCallCount();
    }
    [[nodiscard]] QByteArray lastImportedMasterList()
    {
        return m_harness.lastImportedMasterList();
    }
    /// The post-read authoritative cardType update.
    void triggerCardTypeChanged(const QString& cardType)
    {
        m_harness.emitCardTypeChanged(cardType);
    }

private:
    static FakeAgent::Config toConfig(const ParityConfig& cfg)
    {
        FakeAgent::Config out;
        out.capabilities = cfg.capabilities;
        out.operationDelayMs = cfg.operationDelayMs;
        out.features = cfg.features;
        out.agentVersion = cfg.agentVersion;
        out.config = cfg.agentConfig;
        out.cardType = cfg.cardType;
        out.atrHex = cfg.atrHex;
        out.failMethodEntry = cfg.failMethodEntry;
        out.certDerEmptyReply = cfg.certDerReplyOutsideContract;
        out.finalStatus = cfg.finalStatus;
        out.finalErrorCode = cfg.finalErrorCode;
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
            fc.securityStatus = c.securityStatus;
            fc.keyUsageBits = c.keyUsageBits;
            fc.extendedKeyUsageOids = c.extendedKeyUsageOids;
            fc.chainSubjectCns = c.chainSubjectCns;
            fc.extraFields = c.extraFields;
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
        out.layoutFontSize = cfg.layoutFontSize;
        out.layoutLineHeight = cfg.layoutLineHeight;
        out.layoutLines = cfg.layoutLines;
        out.layoutClipped = cfg.layoutClipped;
        out.appearanceFontBytes = cfg.appearanceFontBytes;
        for (const ParityIdentityGroup& g : cfg.identityGroupScript) {
            Fakes::FakeIdentityGroup fg;
            fg.key = g.groupKey;
            for (const ParityIdentityField& f : g.fields) {
                fg.fields.insert(f.fieldKey, LibreSCRS::AgentClient::IdentityFieldWire{f.labelKey, f.labelFallback,
                                                                                       f.type, QDBusVariant(f.value)});
            }
            out.identityGroupScript.append(fg);
        }
        out.raceResultBeforeReturn = cfg.raceResultBeforeReturn;
        out.batchHaltAtIndex = cfg.batchHaltAtIndex;
        out.batchHaltErrorCode = cfg.batchHaltErrorCode;
        out.cscaAnchorState = cfg.cscaAnchorState;
        // This fake refuses by agent-namespace SHORT NAME (it mints a real
        // D-Bus error reply), so the neutral enumerator is spelled back out
        // through the wire library's own name table rather than a second
        // hand-kept mapping here.
        if (cfg.cscaImportError) {
            const std::string_view name = LibreSCRS::Agent::Wire::syncErrorName(*cfg.cscaImportError);
            out.cscaImportError = QString::fromLatin1(name.data(), static_cast<qsizetype>(name.size()));
        }
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
    /// The lazy-card-I/O probe: a non-zero count means a content read reached
    /// the wire (see FakeSocketAgent::operationCount()'s doc comment).
    [[nodiscard]] int operationCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->operationCount(); });
        return out;
    }
    [[nodiscard]] int layoutCallCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->layoutCallCount(); });
        return out;
    }
    [[nodiscard]] int appearanceFontCallCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->appearanceFontCallCount(); });
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
    [[nodiscard]] QVariantMap lastManagePinOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastManagePinOptions(); });
        return out;
    }
    [[nodiscard]] QByteArray lastSignInputBytes()
    {
        QByteArray out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignInputBytes(); });
        return out;
    }
    [[nodiscard]] QString lastSignBatchCertId()
    {
        QString out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchCertId(); });
        return out;
    }
    [[nodiscard]] QVariantMap lastSignBatchOptions()
    {
        QVariantMap out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchOptions(); });
        return out;
    }
    [[nodiscard]] QStringList lastSignBatchDisplayNames()
    {
        QStringList out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchDisplayNames(); });
        return out;
    }
    [[nodiscard]] QList<QByteArray> lastSignBatchDocumentBytes()
    {
        QList<QByteArray> out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastSignBatchDocumentBytes(); });
        return out;
    }
    [[nodiscard]] int cscaImportCallCount()
    {
        int out = 0;
        runOnThread(m_context, [this, &out]() { out = m_agent->cscaImportCallCount(); });
        return out;
    }
    [[nodiscard]] QByteArray lastImportedMasterList()
    {
        QByteArray out;
        runOnThread(m_context, [this, &out]() { out = m_agent->lastImportedMasterList(); });
        return out;
    }
    /// The post-read authoritative cardType update.
    void triggerCardTypeChanged(const QString& cardType)
    {
        runOnThread(m_context, [this, cardType]() { m_agent->emitCardTypeChanged(cardType); });
    }

private:
    static FakeSocketAgent::Config toConfig(const ParityConfig& cfg)
    {
        FakeSocketAgent::Config out;
        out.capabilities = cfg.capabilities;
        out.operationDelayMs = cfg.operationDelayMs;
        out.features = cfg.features;
        out.agentVersion = cfg.agentVersion;
        out.config = cfg.agentConfig;
        out.cardType = cfg.cardType;
        out.atrHex = cfg.atrHex;
        out.failMethodEntry = cfg.failMethodEntry;
        out.certDerUnexpectedArm = cfg.certDerReplyOutsideContract;
        out.finalStatus = cfg.finalStatus;
        out.finalErrorCode = cfg.finalErrorCode;
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
            fc.securityStatus = c.securityStatus;
            fc.keyUsageBits = c.keyUsageBits;
            fc.extendedKeyUsageOids = c.extendedKeyUsageOids;
            fc.chainSubjectCns = c.chainSubjectCns;
            fc.extraFields = c.extraFields;
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
        out.layoutFontSize = cfg.layoutFontSize;
        out.layoutLineHeight = cfg.layoutLineHeight;
        out.layoutLines = cfg.layoutLines;
        out.layoutClipped = cfg.layoutClipped;
        out.appearanceFontBytes = cfg.appearanceFontBytes;
        for (const ParityIdentityGroup& g : cfg.identityGroupScript) {
            FakeSocketIdentityGroup fg;
            fg.key = g.groupKey;
            for (const ParityIdentityField& f : g.fields) {
                fg.fields[f.fieldKey.toStdString()] =
                    LibreSCRS::Agent::Wire::IdentityField{f.labelKey.toStdString(), f.labelFallback.toStdString(),
                                                          f.type.toStdString(), f.value.toStdString()};
            }
            out.identityGroupScript.append(fg);
        }
        out.raceResultBeforeReturn = cfg.raceResultBeforeReturn;
        out.batchHaltAtIndex = cfg.batchHaltAtIndex;
        out.batchHaltErrorCode = cfg.batchHaltErrorCode;
        out.cscaAnchorState = cfg.cscaAnchorState;
        out.cscaImportError = cfg.cscaImportError;
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

// `kWarmOperationsOnTheWire` is the ONE place in this corpus where the two
// transports are expected to differ rather than match, so it is spelled as a
// named constant per policy instead of an `if` inside a scenario body: the
// divergence is reviewable in one place, and a transport that silently changed
// sides would have to change this line to stay green.
//
// D-Bus issues the warm; the socket transport's is a documented no-op (see
// SocketTransport::warmCertificates for why -- a warm makes the agent mint an
// operation this wire has no way to release without cancelling the read).
// Everything else about the verb IS parity, and the scenario below asserts
// that part against both wires with one body.
// kAutoLevelOnTheWire: how a request that DEFERS the level is spelled on this
// transport. nullptr means "the key is absent". This is the ONE place these
// two wires deliberately differ, and it is dated, not idiomatic: a PUBLISHED
// D-Bus agent rejects the "auto" token, while the socket's sign-opts REQUIRES
// the field, so the deferral is spelled as an absent key on one and as the
// token on the other. Both resolve to the agent's configured DefaultLevel.
//
// Retire this constant and emit "auto" on both wires once the patched D-Bus
// agent is deployed everywhere.
struct DBusPolicy
{
    using Env = DBusEnv;
    static constexpr int kWarmOperationsOnTheWire = 1;
    static constexpr const char* kAutoLevelOnTheWire = nullptr;
};
struct SocketPolicy
{
    using Env = SocketEnv;
    static constexpr int kWarmOperationsOnTheWire = 0;
    static constexpr const char* kAutoLevelOnTheWire = "auto";
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

// Pass-through law, client side: a group/field key the agent ships MUST reach
// `FieldGroup::key`/`Field::key` byte-for-byte, whatever shape it has -- an
// unusual key (mixed case, underscores, a dot, a dash, a digit) is scripted
// here precisely because it is the kind of string a case-folding or
// slug-ifying normalization bug would visibly mangle. Both DBusTransport
// (Marshal.cpp's toFieldGroup, keyed off the QMap iteration key) and
// SocketTransport (its own toFieldGroup, keyed off the CBOR map key) are
// proven identical and untouched by this ONE typed-test body.
TYPED_TEST(TransportParity, IdentityFieldKeysArriveVerbatimWithNoNormalization)
{
    using Env = typename TypeParam::Env;
    static const QString kOddGroupKey = QStringLiteral("Mixed_CASE.Group-1");
    static const QString kOddFieldKey = QStringLiteral("Weird_Field.Key-2");

    ParityConfig cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.identityGroupScript = {
        ParityIdentityGroup{kOddGroupKey,
                            {ParityIdentityField{kOddFieldKey, QStringLiteral("label.odd"), QStringLiteral("Odd Field"),
                                                 QStringLiteral("text"), QStringLiteral("odd-value")}}},
    };
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<FieldGroup> groups = op->identityResult();
    const auto group =
        std::find_if(groups.cbegin(), groups.cend(), [](const FieldGroup& g) { return g.key == kOddGroupKey; });
    ASSERT_NE(group, groups.cend()) << "the scripted group key must arrive UNCHANGED, not case-folded or slugified";
    const auto field = std::find_if(group->fields.cbegin(), group->fields.cend(),
                                    [](const Field& f) { return f.key == kOddFieldKey; });
    ASSERT_NE(field, group->fields.cend()) << "the scripted field key must arrive UNCHANGED";
    EXPECT_EQ(field->value, QStringLiteral("odd-value"));
}

// ---- progressive per-group streaming -----------------------------------------

namespace {
ParityConfig threeGroupStreamingConfig()
{
    ParityConfig cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("identity-stream")};
    cfg.identityGroupScript = {
        ParityIdentityGroup{
            QStringLiteral("personal"),
            {ParityIdentityField{QStringLiteral("given_name"), QStringLiteral("label.given_name"),
                                 QStringLiteral("Given name"), QStringLiteral("text"), QStringLiteral("Ana")}}},
        ParityIdentityGroup{
            QStringLiteral("address"),
            {ParityIdentityField{QStringLiteral("city"), QStringLiteral("label.city"), QStringLiteral("City"),
                                 QStringLiteral("text"), QStringLiteral("Belgrade")}}},
        ParityIdentityGroup{QStringLiteral("document"),
                            {ParityIdentityField{QStringLiteral("number"), QStringLiteral("label.number"),
                                                 QStringLiteral("Document number"), QStringLiteral("text"),
                                                 QStringLiteral("AB1234567")}}},
    };
    return cfg;
}
} // namespace

TYPED_TEST(TransportParity, IdentityGroupStreamingDeliversGroupsInOrderBeforeResult)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg = threeGroupStreamingConfig();
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    QStringList streamedGroupKeys;
    bool finishedSeenBeforeAllGroups = false;
    QObject::connect(op, &AgentOperation::groupReady, op, [&](const FieldGroup& g) {
        if (op->isFinished()) {
            finishedSeenBeforeAllGroups = true;
        }
        streamedGroupKeys.append(g.key);
    });

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    EXPECT_FALSE(finishedSeenBeforeAllGroups) << "every groupReady must fire before finished()";
    ASSERT_EQ(streamedGroupKeys.size(), 3);
    EXPECT_EQ(streamedGroupKeys.at(0), QStringLiteral("personal"));
    EXPECT_EQ(streamedGroupKeys.at(1), QStringLiteral("address"));
    EXPECT_EQ(streamedGroupKeys.at(2), QStringLiteral("document"));

    // The final result is the UNION of every streamed group -- byte-identical
    // to what a non-streaming consumer (one that never connects to
    // groupReady() at all) would see.
    const QList<FieldGroup> groups = op->identityResult();
    ASSERT_EQ(groups.size(), 3);
    QStringList resultGroupKeys;
    for (const FieldGroup& g : groups) {
        resultGroupKeys.append(g.key);
    }
    std::sort(resultGroupKeys.begin(), resultGroupKeys.end());
    QStringList expected{QStringLiteral("address"), QStringLiteral("document"), QStringLiteral("personal")};
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(resultGroupKeys, expected);
}

TYPED_TEST(TransportParity, IdentityGroupStreamingLateSubscriberMissesRacedGroupsButResultConverges)
{
    // The whole op (every scripted group + the final result + Finished)
    // races before the minting call even returns -- the deterministic
    // "subscribed too late to see any progressive hint" case. groupReady()
    // has no recovery (unlike the terminal result): a late subscriber must
    // still see the COMPLETE, correct identityResult() once finished() fires.
    using Env = typename TypeParam::Env;
    ParityConfig cfg = threeGroupStreamingConfig();
    cfg.raceResultBeforeReturn = true;
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QList<FieldGroup> groups = op->identityResult();
    ASSERT_EQ(groups.size(), 3) << "a late subscriber must still converge on the complete result";
    QStringList resultGroupKeys;
    for (const FieldGroup& g : groups) {
        resultGroupKeys.append(g.key);
    }
    EXPECT_TRUE(resultGroupKeys.contains(QStringLiteral("personal")));
    EXPECT_TRUE(resultGroupKeys.contains(QStringLiteral("address")));
    EXPECT_TRUE(resultGroupKeys.contains(QStringLiteral("document")));
}

TYPED_TEST(TransportParity, IdentityGroupStreamingAbsentFromFeatureAgentYieldsNoGroupSignals)
{
    // An agent predating (or simply not advertising) "identity-stream" never
    // streams -- identityGroupScript stays empty (the default) exactly as
    // every other pre-existing scenario leaves it. groupReady() must fire
    // zero times and the result must still arrive intact.
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.features = {QStringLiteral("credentials")}; // no "identity-stream"
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    int groupSignalCount = 0;
    QObject::connect(op, &AgentOperation::groupReady, op, [&](const FieldGroup&) { ++groupSignalCount; });

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(groupSignalCount, 0);
    EXPECT_FALSE(op->identityResult().isEmpty()) << "the result must stay intact even with no progressive delivery";
}

// ---- token info (rides the SAME Identity1 result shape as identity) ------

TYPED_TEST(TransportParity, TokenInfoDeliversTokenGroupAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("token-info")};
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // Both fakes script the SAME "token" group (label/serial_number/
    // manufacturer) for ReadTokenInfo, rendered through the IDENTICAL
    // Identity1 result path readIdentity() uses — no new result shape.
    const QList<FieldGroup> groups = op->identityResult();
    ASSERT_EQ(groups.size(), 1);
    EXPECT_EQ(groups.front().key, QStringLiteral("token"));
    const QList<Field>& fields = groups.front().fields;
    EXPECT_TRUE(
        std::any_of(fields.cbegin(), fields.cend(), [](const Field& f) { return f.key == QStringLiteral("label"); }));
    EXPECT_TRUE(std::any_of(fields.cbegin(), fields.cend(),
                            [](const Field& f) { return f.key == QStringLiteral("serial_number"); }));
    EXPECT_TRUE(std::any_of(fields.cbegin(), fields.cend(),
                            [](const Field& f) { return f.key == QStringLiteral("manufacturer"); }));
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
    // Certificate metadata: two KeyUsage bits set (nonRepudiation ordinal 1 +
    // keyEncipherment ordinal 2 -> 0x06), so a marshaller that shipped a
    // constant, a truncated value or a single bit is visibly wrong; a
    // multi-entry EKU list and a multi-entry leaf..root chain, so order and
    // arity are both under test rather than just presence.
    pc.keyUsageBits = 0x06u;
    pc.extendedKeyUsageOids = QStringList{QStringLiteral("1.3.6.1.5.5.7.3.4"), QStringLiteral("1.3.6.1.5.5.7.3.2")};
    pc.chainSubjectCns = QStringList{QStringLiteral("Parity Signer"), QStringLiteral("Parity CA")};
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

    // The certificate-metadata members, asserted by this ONE body against
    // BOTH wires. Each marshaller populates them in its own private .cpp, so
    // a change made to only one of the two would leave these three green on
    // that transport and empty/zero on the other -- exactly the asymmetry a
    // per-transport assertion cannot see and this scenario can.
    EXPECT_EQ(c.keyUsageBits, 0x06u) << "the KeyUsage bitmask must survive this transport verbatim";
    EXPECT_EQ(c.extendedKeyUsageOids,
              (QStringList{QStringLiteral("1.3.6.1.5.5.7.3.4"), QStringLiteral("1.3.6.1.5.5.7.3.2")}))
        << "EKU OIDs must arrive complete and in the agent-supplied order";
    EXPECT_EQ(c.chainSubjectCns, (QStringList{QStringLiteral("Parity Signer"), QStringLiteral("Parity CA")}))
        << "the leaf..root chain must arrive complete and in order";

    // One source of truth: the three members above no longer ALSO ride the
    // untyped pass-through map. `trustStatusWire` still does -- no typed
    // member mirrors it.
    EXPECT_FALSE(c.extra.contains(QStringLiteral("keyUsageBits")));
    EXPECT_FALSE(c.extra.contains(QStringLiteral("extendedKeyUsageOids")));
    EXPECT_FALSE(c.extra.contains(QStringLiteral("chainSubjectCns")));
    // contains() first, deliberately: this scenario scripts trustStatus 0, and
    // toUInt() on a MISSING key also yields 0 -- so the value check alone
    // would pass on a transport that stopped carrying the key at all.
    EXPECT_TRUE(c.extra.contains(QStringLiteral("trustStatusWire")));
    EXPECT_EQ(c.extra.value(QStringLiteral("trustStatusWire")).toUInt(), 0u);
}

// The whole cert-info `fields` dict, one body against both wires.
//
// The two decodes read the dict out of containers that have nothing in common
// -- a QtDBus-demarshalled `a{sa{s(ssv)}}` of QDBusVariant cells on one side,
// a `std::map<std::string, std::map<std::string, Wire::CertField>>` of CBOR
// text on the other -- and both must land it on `extra["fields"]` in ONE
// shape, because the consumer that renders it is written against that shape
// and not against either wire. So the assertion is a WHOLE-MAP comparison
// against one expected value, not a spot-check: a transport that dropped a
// group, flattened the nesting, ordered the triple differently or stringified
// a cell would each still pass a `contains()`-shaped test on its own suite,
// and every one of them is a different rendering on the two wires.
//
// Every group the CDDL enumerates is scripted, for the reason the per-group
// D-Bus cases exist: the decode that shipped before this one special-cased
// four cells by name, and a scenario carrying one group cannot tell a generic
// copy from a lucky special case.
TYPED_TEST(TransportParity, CertificateFieldsDictSurfacesIdenticallyOnBothWires)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    ParityCert pc;
    pc.certId = QStringLiteral("cert-fields-parity");
    pc.signingCapable = true;
    // The four derived cells, scripted through the typed members exactly as
    // every other cert scenario does -- they must appear in the dict TOO, in
    // their own groups, alongside the scripted ones.
    pc.subjectCn = QStringLiteral("Ana Anić");
    pc.issuerCn = QStringLiteral("Republika Srbija CA");
    pc.notBefore = QStringLiteral("2020-01-01T00:00:00Z");
    pc.notAfter = QStringLiteral("2030-12-31T23:59:59Z");
    pc.trustStatus = 4; // Expired -- the "security" group's token rides along
    pc.securityStatus = QStringList{QStringLiteral("expired")};
    pc.extraFields = Fakes::FakeCertFieldGroups{
        {QStringLiteral("subject"),
         {{QStringLiteral("dn"),
           {QStringLiteral("cert.subject.dn"), QStringLiteral("Distinguished Name"),
            QStringLiteral("CN=Ana Anić, O=Republika Srbija")}}}},
        {QStringLiteral("publicKey"),
         {{QStringLiteral("algorithm"),
           {QStringLiteral("cert.publicKey.algorithm"), QStringLiteral("Algorithm"), QStringLiteral("ECDSA")}},
          {QStringLiteral("sizeBits"),
           {QStringLiteral("cert.publicKey.sizeBits"), QStringLiteral("Key Size"), QStringLiteral("256")}},
          {QStringLiteral("curveOid"),
           {QStringLiteral("cert.publicKey.curveOid"), QStringLiteral("Curve"),
            QStringLiteral("1.2.840.10045.3.1.7")}}}},
        {QStringLiteral("cert"),
         {{QStringLiteral("serial"),
           {QStringLiteral("cert.cert.serial"), QStringLiteral("Serial Number"), QStringLiteral("1A:2B:3C:4D")}},
          {QStringLiteral("version"),
           {QStringLiteral("cert.cert.version"), QStringLiteral("Version"), QStringLiteral("v3")}},
          {QStringLiteral("subjectKeyIdentifier"),
           {QStringLiteral("cert.cert.subjectKeyIdentifier"), QStringLiteral("Subject Key Identifier"),
            QStringLiteral("AA:BB:CC")}}}},
        {QStringLiteral("basicConstraints"),
         {{QStringLiteral("isCa"),
           {QStringLiteral("cert.basicConstraints.isCa"), QStringLiteral("CA"), QStringLiteral("false")}}}},
        {QStringLiteral("san"),
         {{QStringLiteral("email0"),
           {QStringLiteral("cert.san.email"), QStringLiteral("Email"), QStringLiteral("ana@example.invalid")}}}},
        {QStringLiteral("ian"),
         {{QStringLiteral("uri0"),
           {QStringLiteral("cert.ian.uri"), QStringLiteral("URI"), QStringLiteral("https://ca.example.invalid/")}}}},
        {QStringLiteral("crlDp"),
         {{QStringLiteral("url0"),
           {QStringLiteral("cert.crlDp.url0"), QStringLiteral("CRL Distribution Point"),
            QStringLiteral("http://crl.example.invalid/a")}}}},
        {QStringLiteral("aia"),
         {{QStringLiteral("ocsp0"),
           {QStringLiteral("cert.aia.ocsp0"), QStringLiteral("OCSP Responder"),
            QStringLiteral("http://ocsp.example.invalid/")}}}},
        {QStringLiteral("certificatePolicies"),
         {{QStringLiteral("policy0"),
           {QStringLiteral("cert.certificatePolicies.policy0"), QStringLiteral("Certificate Policy"),
            QStringLiteral("1.3.6.1.4.1.1.1.1")}}}},
        {QStringLiteral("eku"),
         {{QStringLiteral("usage0"),
           {QStringLiteral("cert.eku.usage0"), QStringLiteral("Extended Key Usage"),
            QStringLiteral("E-mail Protection")}},
          {QStringLiteral("usage1"),
           {QStringLiteral("cert.eku.usage1"), QStringLiteral("Extended Key Usage"),
            QStringLiteral("1.3.6.1.4.1.99999.1")}}}},
        {QStringLiteral("ext"),
         {{QStringLiteral("2.5.29.9"),
           {QStringLiteral("cert.ext.2.5.29.9"), QStringLiteral("X509v3 Subject Directory Attributes (Critical)"),
            QStringLiteral("30820103")}}}},
    };
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

    const auto cell = [](const QString& labelKey, const QString& labelFallback, const QString& value) {
        return QVariant(QVariantList{labelKey, labelFallback, value});
    };
    const QVariantMap expected{
        {QStringLiteral("subject"),
         QVariantMap{
             {QStringLiteral("cn"),
              cell(QStringLiteral("label_subject_cn"), QStringLiteral("Subject CN"), QStringLiteral("Ana Anić"))},
             {QStringLiteral("dn"), cell(QStringLiteral("cert.subject.dn"), QStringLiteral("Distinguished Name"),
                                         QStringLiteral("CN=Ana Anić, O=Republika Srbija"))}}},
        {QStringLiteral("issuer"),
         QVariantMap{{QStringLiteral("cn"), cell(QStringLiteral("label_issuer_cn"), QStringLiteral("Issuer CN"),
                                                 QStringLiteral("Republika Srbija CA"))}}},
        {QStringLiteral("validity"),
         QVariantMap{
             {QStringLiteral("notBefore"), cell(QStringLiteral("label_not_before"), QStringLiteral("Not before"),
                                                QStringLiteral("2020-01-01T00:00:00Z"))},
             {QStringLiteral("notAfter"), cell(QStringLiteral("label_not_after"), QStringLiteral("Not after"),
                                               QStringLiteral("2030-12-31T23:59:59Z"))}}},
        {QStringLiteral("publicKey"),
         QVariantMap{
             {QStringLiteral("algorithm"),
              cell(QStringLiteral("cert.publicKey.algorithm"), QStringLiteral("Algorithm"), QStringLiteral("ECDSA"))},
             {QStringLiteral("sizeBits"),
              cell(QStringLiteral("cert.publicKey.sizeBits"), QStringLiteral("Key Size"), QStringLiteral("256"))},
             {QStringLiteral("curveOid"), cell(QStringLiteral("cert.publicKey.curveOid"), QStringLiteral("Curve"),
                                               QStringLiteral("1.2.840.10045.3.1.7"))}}},
        {QStringLiteral("cert"),
         QVariantMap{{QStringLiteral("serial"), cell(QStringLiteral("cert.cert.serial"),
                                                     QStringLiteral("Serial Number"), QStringLiteral("1A:2B:3C:4D"))},
                     {QStringLiteral("version"),
                      cell(QStringLiteral("cert.cert.version"), QStringLiteral("Version"), QStringLiteral("v3"))},
                     {QStringLiteral("subjectKeyIdentifier"),
                      cell(QStringLiteral("cert.cert.subjectKeyIdentifier"), QStringLiteral("Subject Key Identifier"),
                           QStringLiteral("AA:BB:CC"))}}},
        {QStringLiteral("basicConstraints"),
         QVariantMap{{QStringLiteral("isCa"), cell(QStringLiteral("cert.basicConstraints.isCa"), QStringLiteral("CA"),
                                                   QStringLiteral("false"))}}},
        {QStringLiteral("san"),
         QVariantMap{{QStringLiteral("email0"), cell(QStringLiteral("cert.san.email"), QStringLiteral("Email"),
                                                     QStringLiteral("ana@example.invalid"))}}},
        {QStringLiteral("ian"),
         QVariantMap{{QStringLiteral("uri0"), cell(QStringLiteral("cert.ian.uri"), QStringLiteral("URI"),
                                                   QStringLiteral("https://ca.example.invalid/"))}}},
        {QStringLiteral("crlDp"),
         QVariantMap{
             {QStringLiteral("url0"), cell(QStringLiteral("cert.crlDp.url0"), QStringLiteral("CRL Distribution Point"),
                                           QStringLiteral("http://crl.example.invalid/a"))}}},
        {QStringLiteral("aia"),
         QVariantMap{{QStringLiteral("ocsp0"), cell(QStringLiteral("cert.aia.ocsp0"), QStringLiteral("OCSP Responder"),
                                                    QStringLiteral("http://ocsp.example.invalid/"))}}},
        {QStringLiteral("certificatePolicies"),
         QVariantMap{{QStringLiteral("policy0"),
                      cell(QStringLiteral("cert.certificatePolicies.policy0"), QStringLiteral("Certificate Policy"),
                           QStringLiteral("1.3.6.1.4.1.1.1.1"))}}},
        {QStringLiteral("eku"),
         QVariantMap{
             {QStringLiteral("usage0"), cell(QStringLiteral("cert.eku.usage0"), QStringLiteral("Extended Key Usage"),
                                             QStringLiteral("E-mail Protection"))},
             {QStringLiteral("usage1"), cell(QStringLiteral("cert.eku.usage1"), QStringLiteral("Extended Key Usage"),
                                             QStringLiteral("1.3.6.1.4.1.99999.1"))}}},
        {QStringLiteral("ext"),
         QVariantMap{{QStringLiteral("2.5.29.9"), cell(QStringLiteral("cert.ext.2.5.29.9"),
                                                       QStringLiteral("X509v3 Subject Directory Attributes (Critical)"),
                                                       QStringLiteral("30820103"))}}},
        {QStringLiteral("security"),
         QVariantMap{{QStringLiteral("expired"), cell(QStringLiteral("cert.security.expired"),
                                                      QStringLiteral("expired"), QStringLiteral("expired"))}}},
    };

    ASSERT_TRUE(c.extra.contains(QStringLiteral("fields")))
        << "the fields dict must reach the consumer on BOTH transports, not just the one whose decode was edited";
    EXPECT_EQ(c.extra.value(QStringLiteral("fields")).toMap(), expected)
        << "both wires must surface the SAME grouped shape — group -> field -> [labelKey, labelFallback, value]";

    // The dict is surfaced IN ADDITION to the typed extraction, never instead
    // of it: a consumer reading `subject` must still get the CN, and one
    // reading the dict must still find the same cell inside it.
    EXPECT_EQ(c.subject, QStringLiteral("Ana Anić"));
    EXPECT_EQ(c.issuer, QStringLiteral("Republika Srbija CA"));
    EXPECT_EQ(c.securityStatus, (QStringList{QStringLiteral("expired")}));
}

// The diagnostic failure channel, one body against both wires. When the agent
// cannot parse a certificate's DER at all, the wire carries a "diagnostic"
// group INSTEAD of the certificate vocabulary -- alone, with a single
// parseError cell -- and the cert stays signing-incapable. A client decodes
// it through the same generic dict path as every other group, so a transport
// that special-cased the happy-path groups would pass the scenario above and
// still lose the one group a broken certificate produces.
TYPED_TEST(TransportParity, DiagnosticParseFailureSurfacesIdenticallyOnBothWires)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    ParityCert pc;
    pc.certId = QStringLiteral("cert-diagnostic-parity");
    pc.signingCapable = false;
    pc.extraFields = Fakes::FakeCertFieldGroups{
        {QStringLiteral("diagnostic"),
         {{QStringLiteral("parseError"),
           {QStringLiteral("cert.diagnostic.parseError"), QStringLiteral("Parse error"),
            QStringLiteral("d2i_X509: header too long")}}}},
    };
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
    EXPECT_FALSE(c.signingCapable);

    const auto cell = [](const QString& labelKey, const QString& labelFallback, const QString& value) {
        return QVariant(QVariantList{labelKey, labelFallback, value});
    };
    ASSERT_TRUE(c.extra.contains(QStringLiteral("fields")));
    const QVariantMap fields = c.extra.value(QStringLiteral("fields")).toMap();
    ASSERT_TRUE(fields.contains(QStringLiteral("diagnostic")))
        << "the failure channel must survive both decodes, not just the one whose transport was edited";
    EXPECT_EQ(fields.value(QStringLiteral("diagnostic")).toMap(),
              (QVariantMap{{QStringLiteral("parseError"),
                            cell(QStringLiteral("cert.diagnostic.parseError"), QStringLiteral("Parse error"),
                                 QStringLiteral("d2i_X509: header too long"))}}));
}

// The best-effort warm, one body against both wires. Most of what this verb
// promises is TRUE ON BOTH regardless of whether a frame goes out at all --
// it returns without waiting, it mints nothing the caller can observe or leak,
// it is safe to call repeatedly, and it never disturbs the real read that
// follows -- and those are the assertions below. The single genuine
// divergence, whether the card work reaches the agent, is read from the
// policy's `kWarmOperationsOnTheWire` rather than branched on inline, so a
// transport that quietly changed sides fails here instead of passing on a
// scenario that only ever checked its own wire.
TYPED_TEST(TransportParity, WarmCertificatesMintsNothingAndLeavesTheRealReadIntact)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    ParityCert pc;
    pc.certId = QStringLiteral("cert-parity-warm");
    pc.signingCapable = true;
    cfg.certScript = {pc};
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    ASSERT_EQ(env.operationCount(), 0);

    // Twice, back to back and without returning to the event loop: whatever
    // each transport does with a warm, a second one on top of an in-flight one
    // must never stack card work.
    card->warmCertificates();
    card->warmCertificates();
    (void)waitFor([]() { return false; }, 250); // let anything that was sent arrive

    EXPECT_EQ(env.operationCount(), TypeParam::kWarmOperationsOnTheWire)
        << "this transport did not do what its policy says a warm does";
    EXPECT_TRUE(card->children().isEmpty()) << "a warm minted a consumer-visible operation";
    EXPECT_TRUE(env.client()->isAvailable()) << "a warm disturbed the client's availability";

    // The real read still behaves identically on both wires afterwards -- the
    // property that makes the socket side's no-op cost a consumer nothing.
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs.constFirst().id, QStringLiteral("cert-parity-warm"));
    EXPECT_EQ(env.operationCount(), TypeParam::kWarmOperationsOnTheWire + 1);
}

// The trust-verdict append: the SAME scripted trustStatus/securityStatus
// pair surfaces identically on both transports -- Revoked (5) maps to the
// client's own Revoked case, and the "security" fields-group token rides
// CertificateInfo::securityStatus on both wires (dict-key growth, not a new
// wire member -- see CertSnapshot.h).
TYPED_TEST(TransportParity, CertificateTrustVerdictAndSecurityTokenMatchAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    ParityCert pc;
    pc.certId = QStringLiteral("cert-parity-revoked");
    pc.trustStatus = 5; // Revoked
    pc.securityStatus = QStringList{QStringLiteral("revoked")};
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
    EXPECT_EQ(c.trust, TrustStatus::Revoked);
    EXPECT_EQ(c.securityStatus, (QStringList{QStringLiteral("revoked")}));
}

// ---- sign: tsaUrl + visualSignature now forward identically ----------

TYPED_TEST(TransportParity, SignWithTsaUrlAndVisualSignatureForwardsIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("tsa-url"), QStringLiteral("visual-sign")};
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    const QByteArray document = QByteArrayLiteral("the bytes TransportParityTest signs");
    SignOptions options;
    options.format = SignatureFormat::PAdES;
    options.level = SignatureLevel::BT;
    options.packaging = Packaging::Enveloped;
    options.tsaUrl = QStringLiteral("https://tsa.example/parity");
    options.visualSignature =
        QVariantMap{{QStringLiteral("page"), 0},      {QStringLiteral("x"), 10.0},
                    {QStringLiteral("y"), 20.0},      {QStringLiteral("width"), 150.0},
                    {QStringLiteral("height"), 60.0}, {QStringLiteral("text"), QStringLiteral("Signed by {cn}")}};
    options.extra.insert(QStringLiteral("reason"), QStringLiteral("parity-suite"));

    AgentOperation* op = card->sign(QStringLiteral("cert-for-sign"), makeMemfdDocument(document), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    // fd in: both fakes read the document synchronously.
    EXPECT_EQ(env.lastSignCertId(), QStringLiteral("cert-for-sign"));
    EXPECT_EQ(env.lastSignInputBytes(), document);

    // The shared sign-opts vocabulary is identical on both wires — the
    // historical tsaUrl asymmetry this scenario used to pin is retired: both
    // transports now forward tsaUrl AND the nested visualSignature map.
    const QVariantMap wireOptions = env.lastSignOptions();
    EXPECT_EQ(wireOptions.value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("level")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("packaging")).toString(), QStringLiteral("enveloped"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("reason")).toString(), QStringLiteral("parity-suite"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("tsaUrl")).toString(), options.tsaUrl)
        << "tsaUrl must forward identically on both transports";

    const QVariantMap wireVisual = wireOptions.value(QStringLiteral("visualSignature")).toMap();
    EXPECT_EQ(wireVisual.value(QStringLiteral("page")).toULongLong(), 0ULL);
    EXPECT_EQ(wireVisual.value(QStringLiteral("x")).toDouble(), 10.0);
    EXPECT_EQ(wireVisual.value(QStringLiteral("y")).toDouble(), 20.0);
    EXPECT_EQ(wireVisual.value(QStringLiteral("width")).toDouble(), 150.0);
    EXPECT_EQ(wireVisual.value(QStringLiteral("height")).toDouble(), 60.0);
    EXPECT_EQ(wireVisual.value(QStringLiteral("text")).toString(), QStringLiteral("Signed by {cn}"));

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

// A parity suite exists to assert SAMENESS, so a case asserting a difference
// has to say why it exists and when it stops being needed — otherwise the next
// reader takes the asymmetry as sanctioned and permanent. See
// DBusPolicy/SocketPolicy's kAutoLevelOnTheWire for both.
TYPED_TEST(TransportParity, AutoLevelSpellingDivergesUntilTheDBusAgentAcceptsTheSentinel)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    SignOptions options; // level defaults to Auto
    AgentOperation* op =
        card->sign(QStringLiteral("cert-for-sign"), makeMemfdDocument(QByteArrayLiteral("deferred")), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    const QVariantMap wireOptions = env.lastSignOptions();
    if (TypeParam::kAutoLevelOnTheWire == nullptr) {
        EXPECT_FALSE(wireOptions.contains(QStringLiteral("level")))
            << "an absent key is how this transport spells the deferral";
    } else {
        EXPECT_EQ(wireOptions.value(QStringLiteral("level")).toString(),
                  QString::fromLatin1(TypeParam::kAutoLevelOnTheWire))
            << "this transport's sign-opts requires the field, so the sentinel must be spelled";
    }
    // Everything else about the request is identical, as always.
    EXPECT_EQ(wireOptions.value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    EXPECT_EQ(wireOptions.value(QStringLiteral("packaging")).toString(), QStringLiteral("enveloped"));
}

// ---- feature-gated sign: tsaUrl/visualSignature without their tokens
// refuses identically on both transports, before either dials the wire ------
TYPED_TEST(TransportParity, MissingTsaUrlOrVisualSignFeatureRefusesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "tsa-url" / "visual-sign"
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("tsa-url")));
    EXPECT_FALSE(client->hasFeature(QStringLiteral("visual-sign")));

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    const QByteArray document = QByteArrayLiteral("gated sign document");

    SignOptions tsaOptions;
    tsaOptions.tsaUrl = QStringLiteral("https://tsa.example/gated");
    AgentOperation* tsaOp = card->sign(QStringLiteral("cert-for-sign"), makeMemfdDocument(document), tsaOptions);
    ASSERT_NE(tsaOp, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return tsaOp->isFinished(); }));
    EXPECT_EQ(tsaOp->status(), OperationStatus::Error);
    EXPECT_EQ(tsaOp->errorCode(), ErrorCode::CapabilityMissing);

    SignOptions visualOptions;
    visualOptions.visualSignature =
        QVariantMap{{QStringLiteral("page"), 0},      {QStringLiteral("x"), 0.0},
                    {QStringLiteral("y"), 0.0},       {QStringLiteral("width"), 100.0},
                    {QStringLiteral("height"), 50.0}, {QStringLiteral("text"), QStringLiteral("Signed")}};
    AgentOperation* visualOp = card->sign(QStringLiteral("cert-for-sign"), makeMemfdDocument(document), visualOptions);
    ASSERT_NE(visualOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return visualOp->isFinished(); }));
    EXPECT_EQ(visualOp->status(), OperationStatus::Error);
    EXPECT_EQ(visualOp->errorCode(), ErrorCode::CapabilityMissing);

    // Neither refused sign ever reached either transport's fake.
    EXPECT_EQ(env.operationCount(), 0) << "both refusals must fire before either transport ever dials the wire";
}

// ---- batch signing: happy path, mid-batch halt, feature-gated refusal -----

TYPED_TEST(TransportParity, SignBatchHappyPathForwardsIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("first.pdf"), makeMemfdDocument(QByteArrayLiteral("doc one bytes"))});
    docs.push_back(BatchDocument{QStringLiteral("second.pdf"), makeMemfdDocument(QByteArrayLiteral("doc two bytes"))});

    SignOptions options;
    options.format = SignatureFormat::PAdES;
    options.level = SignatureLevel::BB;

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), options);
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    EXPECT_EQ(env.lastSignBatchCertId(), QStringLiteral("cert-for-batch"));
    EXPECT_EQ(env.lastSignBatchDisplayNames(),
              (QStringList{QStringLiteral("first.pdf"), QStringLiteral("second.pdf")}));
    const QList<QByteArray> receivedDocs = env.lastSignBatchDocumentBytes();
    ASSERT_EQ(receivedDocs.size(), 2);
    EXPECT_EQ(receivedDocs.at(0), QByteArrayLiteral("doc one bytes"));
    EXPECT_EQ(receivedDocs.at(1), QByteArrayLiteral("doc two bytes"));

    // Both fakes were scripted with the SAME signArtifactBytes/signMeta
    // (ParityConfig's defaults) — rows, meta, AND artifact content hashes are
    // asserted byte-for-byte / field-for-field identical across transports.
    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 2U);
    EXPECT_EQ(rows[0].displayName, QStringLiteral("first.pdf"));
    EXPECT_EQ(rows[1].displayName, QStringLiteral("second.pdf"));
    for (const BatchSignRow& row : rows) {
        EXPECT_EQ(row.error, ErrorCode::None);
        ASSERT_TRUE(row.artifact.valid());
        const QByteArray receivedArtifact = readFdAll(row.artifact.get());
        EXPECT_EQ(receivedArtifact, cfg.signArtifactBytes);
        EXPECT_EQ(QCryptographicHash::hash(receivedArtifact, QCryptographicHash::Sha256),
                  QCryptographicHash::hash(cfg.signArtifactBytes, QCryptographicHash::Sha256));
        EXPECT_EQ(row.meta, cfg.signMeta);
    }
}

TYPED_TEST(TransportParity, SignBatchMidBatchHaltProducesIdenticalRowsAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("batch-sign")};
    cfg.batchHaltAtIndex = 1;
    cfg.batchHaltErrorCode = static_cast<quint32>(ErrorCode::CredentialBlocked);
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    for (int i = 0; i < 3; ++i) {
        docs.push_back(BatchDocument{QStringLiteral("doc-%1.pdf").arg(i), makeMemfdDocument(QByteArrayLiteral("b"))});
    }

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok) << "successCount > 0 (row 0 signed) keeps the aggregate Ok";

    std::vector<BatchSignRow> rows = op->takeBatchResults();
    ASSERT_EQ(rows.size(), 3U);
    EXPECT_EQ(rows[0].error, ErrorCode::None);
    ASSERT_TRUE(rows[0].artifact.valid());
    EXPECT_FALSE(readFdAll(rows[0].artifact.get()).isEmpty());
    for (std::size_t i = 1; i < rows.size(); ++i) {
        EXPECT_EQ(rows[i].error, ErrorCode::CredentialBlocked) << "row " << i << " — identical halt code";
        ASSERT_TRUE(rows[i].artifact.valid()) << "row " << i << " — a valid, zero-length descriptor, never invalid";
        EXPECT_TRUE(readFdAll(rows[i].artifact.get()).isEmpty()) << "row " << i;
    }
}

TYPED_TEST(TransportParity, MissingBatchSignFeatureRefusesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "batch-sign"
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("batch-sign")));

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);

    std::vector<BatchDocument> docs;
    docs.push_back(BatchDocument{QStringLiteral("a.pdf"), makeMemfdDocument(QByteArrayLiteral("b"))});

    AgentOperation* op = card->signBatch(QStringLiteral("cert-for-batch"), std::move(docs), SignOptions{});
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    EXPECT_EQ(env.operationCount(), 0) << "the gate must refuse before either transport ever dials the wire";
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

// The wire's one structural ManagePin option, activateKey, actually reaches
// BOTH wires identically -- and only for ActivatePin. lastManagePinOptions()
// is deliberately the SAME accessor name/shape on both Env wrappers
// (FakeAgent's natural a{sv} capture on D-Bus; a synthesized map over
// FakeSocketAgent's typed wire capture on the socket side), so this ONE
// scenario body -- unlike SocketIntegrationTest.cpp's single-transport
// version -- proves the two transports AGREE, not just that each one
// individually forwards the option.
TYPED_TEST(TransportParity, ManagePinActivatePinForwardsActivateKeyIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::PinManagement;
    ParityCredRecord record;
    record.id = QStringLiteral("sign:0x87");
    record.label = QStringLiteral("Signing PIN");
    cfg.credRecords = {record};
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);

    // 1) list, then activate with activateKey=true.
    AgentOperation* listOp = card->listCredentials();
    ASSERT_NE(listOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return listOp->isFinished(); }));
    EXPECT_EQ(listOp->status(), OperationStatus::Ok);

    AgentOperation* activateOp =
        card->managePin(QStringLiteral("sign:0x87"), PinVerb::ActivatePin, ManagePinOptions{true});
    ASSERT_NE(activateOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return activateOp->isFinished(); }));
    EXPECT_EQ(activateOp->status(), OperationStatus::Ok);
    const QVariantMap afterActivate = env.lastManagePinOptions();
    ASSERT_TRUE(afterActivate.contains(QStringLiteral("activateKey")))
        << "activateKey=true must reach the wire identically on both transports";
    EXPECT_TRUE(afterActivate.value(QStringLiteral("activateKey")).toBool());

    // 2) re-list (the mutation above dropped the listing cache), then Change
    // on the SAME id: activateKey must NOT be present on either wire at all --
    // absence, not a present false, is what a Change mutation carries.
    AgentOperation* relistOp = card->listCredentials();
    ASSERT_NE(relistOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return relistOp->isFinished(); }));

    AgentOperation* changeOp = card->managePin(QStringLiteral("sign:0x87"), PinVerb::Change);
    ASSERT_NE(changeOp, nullptr);
    ASSERT_TRUE(waitFor([&]() { return changeOp->isFinished(); }));
    EXPECT_EQ(changeOp->status(), OperationStatus::Ok);
    EXPECT_FALSE(env.lastManagePinOptions().contains(QStringLiteral("activateKey")))
        << "Change must not carry activateKey on either transport";
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
    // Both fakes refuse entry by NAMING UnsupportedOnThisCard in the wire's
    // sync-error vocabulary, so the named-error axis must arrive engaged and
    // identical on both wires — this is the axis a credential surface branches
    // on when several names share one CallError bucket.
    ASSERT_TRUE(op->syncError().has_value()) << "a NAMED entry refusal must carry its name to the consumer";
    EXPECT_EQ(*op->syncError(), SyncError::UnsupportedOnThisCard);
}

// ---- public data: a reply outside the request's contract ----------------------
//
// The failure that LOOKS like the agent answering but is not: each wire is
// handed the same fault in its own terms (D-Bus a reply with no arguments,
// socket a reply carrying the wrong arm), and neither peer named anything. Both
// transports must therefore leave the named-error axis DISENGAGED — reading a
// name here would attribute the client's own decoding fault to the card.
//
// The two other axes are deliberately NOT asserted equal: the transports have
// always classified this case differently (D-Bus reports the ErrorCode
// catch-all, the socket a ProtocolError CallError), and this scenario exists to
// pin the new axis, not to re-map the old ones.
TYPED_TEST(TransportParity, ReplyOutsideTheContractCarriesNoNameOnEitherTransport)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.certDerReplyOutsideContract = true;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_NE(client, nullptr);
    ASSERT_EQ(client->readers().size(), 1);
    const QString readerId = client->readers().constFirst()->id();

    AgentOperation* op = client->certificateDer(readerId, QStringLiteral("cert-1"));
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_FALSE(op->syncError().has_value())
        << "a reply outside the request's contract was diagnosed by the CLIENT — the peer named nothing, so the "
           "named-error axis must stay disengaged on both wires";
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

// ---- wire tolerance: a future ErrorCode surfaces identically -----------------
//
// ErrorCode (ErrorCode.h) is wire-frozen APPEND-ONLY, so a newer agent may
// send a numeric value past this build's last known one; the client decodes
// it through raw (uint32 pass-through) rather than failing the operation
// closed — already ratified on the socket wire (ClientCodec's decodeErrorCode)
// and, on D-Bus, inherent (a plain signal argument has no decode step to
// reject anything). This scenario proves the two transports converge on the
// IDENTICAL raw value end to end, not merely that neither one crashes.
TYPED_TEST(TransportParity, FutureErrorCodeSurfacesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.finalStatus = 2;        // Error
    cfg.finalErrorCode = 10000; // past InvalidDocument=19 -- a future code
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->sign(QStringLiteral("certid"), makeMemfdDocument({}), SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));

    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(static_cast<quint32>(op->errorCode()), 10000u)
        << "a future ErrorCode value must surface identically -- raw, unmodified -- on both transports";
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

// ---- feature discovery: identical on both wires, including an unknown token --
//
// Feature discovery is served on both wires from the SAME
// LibreSCRS::Agent::kAgentFeatures single source of truth (D-Bus
// Manager1.Features, socket HelloAck.features); this scenario scripts an
// identical feature list on both fakes — including one token past this
// client build's known vocabulary — and asserts AgentClient::features()/
// hasFeature() converge on the IDENTICAL outcome regardless of transport.
TYPED_TEST(TransportParity, FeatureTokensMatchAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("a-future-token-this-build-does-not-name")};
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const QStringList features = client->features();
    EXPECT_EQ(features.size(), 2) << "both transports must serve the identical scripted set";
    EXPECT_TRUE(client->hasFeature(QStringLiteral("credentials")));
    EXPECT_TRUE(client->hasFeature(QStringLiteral("a-future-token-this-build-does-not-name")))
        << "an unrecognised extra token must surface identically on both transports, never be dropped";
    EXPECT_FALSE(client->hasFeature(QStringLiteral("nonexistent-token")));
}

// ---- agent version: one string, two very different wires -------------------
//
// The version is the one discovery datum whose two wires do NOT share a
// mechanism: D-Bus reads it as a Manager1.Version PROPERTY on the root
// object, the socket retains it from the HelloAck HANDSHAKE. Only a shared
// scenario can prove the client surfaces them identically — a per-transport
// assertion pins each mechanism but would let the two contracts drift.
TYPED_TEST(TransportParity, AgentVersionMatchesAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.agentVersion = QStringLiteral("4.3.0-parity");
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(client->agentVersion(), QStringLiteral("4.3.0-parity"))
        << "the connected agent's version must reach the public surface verbatim on both wires";
}

// The other half of the contract, and the half a transport is most likely to
// get wrong on its own: a version cached for a connection that is GONE must
// not survive it. D-Bus forgets on the name's unregistration, the socket on
// the connection drop; the client must read empty either way, and re-seed
// from the next connect.
TYPED_TEST(TransportParity, AgentVersionEmptyWhileUnavailableAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.agentVersion = QStringLiteral("4.3.0-parity");
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(client->agentVersion(), QStringLiteral("4.3.0-parity"));

    env.vanishAgent();
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(client->agentVersion().isEmpty()) << "a dead agent's version must never be served as if it were live";

    env.reappearAgent();
    ASSERT_TRUE(waitFor([&]() { return client->isAvailable(); }));
    EXPECT_EQ(client->agentVersion(), QStringLiteral("4.3.0-parity"))
        << "the next connect must re-seed the version, not leave it empty";
}

// Features has the SAME forget-on-loss contract as the version above, reached
// by the same two different mechanisms, and is the more consequential of the
// pair: the client's own optional-surface gating reads features(), so a token
// set left over from a dead agent makes a consumer offer capabilities nothing
// is behind. Kept beside its version twin rather than folded into
// FeatureTokensMatchAcrossTransports, which asserts only the live set.
TYPED_TEST(TransportParity, FeaturesEmptyWhileUnavailableAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    ASSERT_TRUE(client->hasFeature(QStringLiteral("credentials")));

    env.vanishAgent();
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(client->features().isEmpty())
        << "a dead agent's feature tokens must never be served as if they were live";
    EXPECT_FALSE(client->hasFeature(QStringLiteral("credentials")));

    env.reappearAgent();
    ASSERT_TRUE(waitFor([&]() { return client->isAvailable(); }));
    EXPECT_TRUE(client->hasFeature(QStringLiteral("credentials")))
        << "the next connect must re-seed the tokens, not leave them empty";
}

// ---- Config1: one settings surface, two refusal mechanisms -----------------
//
// Config1 is where the two wires diverge MOST while still owing one
// observable outcome. Reading: a typed a(sbb) property array on D-Bus versus
// a CBOR value the grammar types as bare `any` on the socket — so the
// canonical TslSources row is the client's guarantee, and only a shared
// scenario can prove both halves produce it. Writing: D-Bus marshals every
// key and lets the agent name the refusal, while the socket's `set-config`
// grammar cannot even ENCODE a non-settable key, so its transport refuses
// locally. Different mechanism, same enumerator — which is exactly the kind
// of claim a per-transport assertion cannot make.

TYPED_TEST(TransportParity, ConfigSnapshotMatchesAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const QVariantMap config = client->configSnapshot();
    EXPECT_EQ(config.value(QStringLiteral("DefaultLevel")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(config.value(QStringLiteral("DefaultReason")).toString(), QStringLiteral("Approval"));
    EXPECT_EQ(config.value(QStringLiteral("TsaUrls")).toStringList(),
              QStringList{QStringLiteral("https://tsa.example.invalid/tsr")});
    EXPECT_EQ(config.value(QStringLiteral("PluginDir")).toString(), QStringLiteral("/usr/lib/librescrs/plugins"));

    const QVariantList tslSources = config.value(QStringLiteral("TslSources")).toList();
    ASSERT_EQ(tslSources.size(), 1) << "the structured property must survive both decodes";
    const QVariantList row = tslSources.first().toList();
    ASSERT_EQ(row.size(), 3) << "both transports must produce the canonical [url, isLotl, eager] row";
    EXPECT_EQ(row.at(0).toString(), QStringLiteral("https://example.invalid/tl.xml"));
    EXPECT_FALSE(row.at(1).toBool());
    EXPECT_TRUE(row.at(2).toBool());

    const QVariantList cscaSources = config.value(QStringLiteral("CscaSources")).toList();
    ASSERT_EQ(cscaSources.size(), 1) << "the second structured property must survive both decodes too";
    const QVariantList cscaRow = cscaSources.first().toList();
    ASSERT_EQ(cscaRow.size(), 2) << "both transports must produce the canonical [uri, eager] row — TWO "
                                    "cells, not a third copied from the trusted-list row above";
    EXPECT_EQ(cscaRow.at(0).toString(), QStringLiteral("https://example.invalid/csca.ldif"));
    EXPECT_TRUE(cscaRow.at(1).toBool());
}

TYPED_TEST(TransportParity, SetConfigValueRoundTripsAndAnnouncesAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    ASSERT_FALSE(client->configSnapshot().isEmpty());

    QStringList announced;
    QString seenFromSlot;
    QObject::connect(client, &AgentClient::configChanged, client, [&](const QString& key) {
        announced.append(key);
        seenFromSlot = client->configSnapshot().value(key).toString();
    });

    EXPECT_EQ(client->setConfigValue(QStringLiteral("DefaultReason"), QStringLiteral("approval")), std::nullopt);
    ASSERT_TRUE(waitFor([&]() { return !announced.isEmpty(); }));
    EXPECT_EQ(announced.constFirst(), QStringLiteral("DefaultReason"));
    EXPECT_EQ(seenFromSlot, QStringLiteral("approval"))
        << "both transports must refresh the cache BEFORE announcing — the change notification "
           "carries only the key on either wire";
    EXPECT_EQ(client->configSnapshot().value(QStringLiteral("DefaultReason")).toString(), QStringLiteral("approval"));
}

TYPED_TEST(TransportParity, NonSettableConfigKeyRefusesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const std::optional<SyncError> refusal =
        client->setConfigValue(QStringLiteral("PluginDir"), QStringLiteral("/tmp/x"));
    ASSERT_TRUE(refusal.has_value());
    EXPECT_EQ(*refusal, SyncError::ReadOnlyConfig)
        << "an agent-named refusal on one wire and a locally-decided one on the other must be the "
           "same enumerator to a caller";
}

TYPED_TEST(TransportParity, UnknownConfigKeyRefusesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const std::optional<SyncError> refusal = client->setConfigValue(QStringLiteral("NoSuchKey"), QStringLiteral("x"));
    ASSERT_TRUE(refusal.has_value());
    EXPECT_EQ(*refusal, SyncError::UnknownConfigKey);

    const std::optional<SyncError> resetRefusal = client->resetConfigValue(QStringLiteral("NoSuchKey"));
    ASSERT_TRUE(resetRefusal.has_value());
    EXPECT_EQ(*resetRefusal, SyncError::UnknownConfigKey);
}

// `CscaSources` is the SECOND structured Config1 value, and the only other one
// whose cells are not a string or a list of strings. Its trusted-list twin is
// covered above by the snapshot scenario; this one covers the direction that
// scenario cannot — a client WRITE — because a key whose value has no encodable
// form on a wire does not fail there, it degrades: the row list collapses to a
// bare string on the way out and the caller is told the write succeeded.
//
// One scenario for both wires because the two encode it in genuinely different
// places (a typed `a(sb)` struct array marshaled by D-Bus, a CBOR array of
// two-element arrays built by hand on the socket) and both owe the caller the
// same rows back. Two rows, not one: a single row round-trips even through an
// encoder that only ever keeps the last entry.
TYPED_TEST(TransportParity, CscaSourcesRoundTripAsRowsAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    ASSERT_FALSE(client->configSnapshot().isEmpty());

    QStringList announced;
    QObject::connect(client, &AgentClient::configChanged, client, [&](const QString& key) { announced.append(key); });

    const QVariantList sources{cscaSourceRow(QStringLiteral("https://pkd.example.invalid/csca.ldif"), true),
                               cscaSourceRow(QStringLiteral("file:///etc/librescrs/csca-anchors"), false)};
    EXPECT_EQ(client->setConfigValue(QStringLiteral("CscaSources"), sources), std::nullopt);
    ASSERT_TRUE(waitFor([&]() { return announced.contains(QStringLiteral("CscaSources")); }));

    const QVariant stored = client->configSnapshot().value(QStringLiteral("CscaSources"));
    ASSERT_EQ(stored.metaType().id(), QMetaType::QVariantList)
        << "the value must come back as ROWS on both wires; a transport with no arm for this key "
           "degrades it to a string instead, and reports the write as a success. Got: "
        << stored.typeName() << " = " << stored.toString().toStdString();

    const QVariantList rows = stored.toList();
    ASSERT_EQ(rows.size(), 2) << "both rows must survive the encode/decode round trip";

    const QVariantList first = rows.at(0).toList();
    ASSERT_EQ(first.size(), 2) << "the canonical row is [uri, eager] — TWO cells, not the trusted "
                                  "list's three";
    EXPECT_EQ(first.at(0).toString(), QStringLiteral("https://pkd.example.invalid/csca.ldif"));
    EXPECT_TRUE(first.at(1).toBool());

    const QVariantList second = rows.at(1).toList();
    ASSERT_EQ(second.size(), 2);
    EXPECT_EQ(second.at(0).toString(), QStringLiteral("file:///etc/librescrs/csca-anchors"));
    EXPECT_FALSE(second.at(1).toBool()) << "the eager flag must survive as a BOOL, per cell, per row";
}

// ---- Config1.ImportCscaMasterList: the one verb that hands over a FILE -----
//
// Every other call on this seam carries values; this one carries an open file
// description. The distinction is not decorative and it is the reason these
// scenarios exist as parity cases rather than per-transport ones: a client
// that passed a NAME instead would look identical in the reply it gets back,
// and only the sender's own descriptor can tell the two apart (see the first
// scenario's comment).

// The descriptor test. A file descriptor sent over either wire — D-Bus
// UNIX_FDS, socket SCM_RIGHTS — is a SECOND REFERENCE TO ONE OPEN FILE
// DESCRIPTION, not a copy of the file: the receiver's sequential read
// therefore advances the SENDER's file position. A path never could, and
// neither could a client that re-opened the descriptor by name
// (/proc/self/fd/N) before handing it over — that would deliver identical
// bytes while leaving this offset at 0.
//
// So the offset is the assertion that actually distinguishes "passes a
// descriptor" from "passes a name", and the byte comparison alone does not.
// Both fakes read the descriptor with read(2) from its CURRENT position for
// exactly this reason (never pread, which the sign-input capture uses).
TYPED_TEST(TransportParity, CscaMasterListImportPassesADescriptorNotAPathAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    QTemporaryDir dir(QStringLiteral("/var/tmp/laqt-csca-XXXXXX"));
    ASSERT_TRUE(dir.isValid());
    const QByteArray listBytes = QByteArrayLiteral("PARITY-ICAO-MASTER-LIST-BYTES");
    const QString path = dir.path() + QStringLiteral("/master-list.ml");
    {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write(listBytes), listBytes.size());
    }

    const int fd = ::open(path.toLocal8Bit().constData(), O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::lseek(fd, 0, SEEK_CUR), 0) << "the sender starts at the beginning of the file";

    const auto imported = client->importCscaMasterList(fd);
    ASSERT_TRUE(imported.has_value()) << "the scripted agent accepts this list on both wires";

    EXPECT_EQ(env.cscaImportCallCount(), 1);
    EXPECT_EQ(env.lastImportedMasterList(), listBytes) << "the agent must receive the list's bytes verbatim";
    EXPECT_EQ(::lseek(fd, 0, SEEK_CUR), listBytes.size())
        << "the agent's read must have moved THIS descriptor's offset — it shares one open file "
           "description with the one that crossed the wire. An offset still at 0 means the client "
           "handed over a name (or a freshly opened descriptor), which is the failure this "
           "assertion exists to catch; the byte comparison above passes either way.";
    ::close(fd);
}

// The demarshal arm. The reply is the agent's whole anchor-state dict, and a
// client has to be able to SAY what happened: how many anchors it now holds,
// how many countries issued them, when the list was signed — and whether
// rollback refusal is even operating, which is the one a surface must not
// stay silent about (a list with no signing time cannot be checked against a
// later one at all).
TYPED_TEST(TransportParity, CscaAnchorStateFromImportSurfacesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const int fd = ::memfd_create("parity-master-list", MFD_CLOEXEC);
    ASSERT_GE(fd, 0);

    const auto imported = client->importCscaMasterList(fd);
    ASSERT_TRUE(imported.has_value());
    const CscaAnchorState& state = *imported;

    EXPECT_EQ(state.anchors, 212u) << "the anchor count must survive both decodes";
    EXPECT_EQ(state.issuers, 47u);
    EXPECT_EQ(state.signer, QStringLiteral("9c1f5c7b2f4b4d6f8a0e3d5c7b9a1f3e5d7c9b1a3f5e7d9c1b3a5f7e9d1c3b5a"));
    EXPECT_TRUE(state.signerPinned);
    EXPECT_EQ(state.acceptedAt, QDateTime::fromSecsSinceEpoch(1756000000));
    ASSERT_TRUE(state.signedAt.isValid()) << "this list carried a signing time";
    EXPECT_EQ(state.signedAt, QDateTime::fromSecsSinceEpoch(1755000000));
    EXPECT_TRUE(state.replayRefusalActive);
    EXPECT_EQ(state.origin, QStringLiteral("import"));
    ::close(fd);
}

// The other half of that dict, and the half worth a scenario of its own: an
// UNDATED list. CMS makes signingTime optional, so `signedAt` is simply
// absent — never a zero sentinel, because a list signed at the epoch and a
// list with no date must not read alike — and `replayRefusalActive` goes
// FALSE, meaning "is this older than what I have" cannot be answered at all.
TYPED_TEST(TransportParity, UndatedMasterListLeavesReplayRefusalOffAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.cscaAnchorState = Fakes::defaultCscaAnchorState();
    cfg.cscaAnchorState.remove(QString(kCscaAnchorSignedAt));
    cfg.cscaAnchorState.insert(QString(kCscaAnchorReplayRefusalActive), false);
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const int fd = ::memfd_create("parity-master-list", MFD_CLOEXEC);
    ASSERT_GE(fd, 0);

    const auto imported = client->importCscaMasterList(fd);
    ASSERT_TRUE(imported.has_value());
    EXPECT_FALSE(imported->signedAt.isValid())
        << "an absent signing time must stay absent — an epoch-valued QDateTime would make an "
           "undated list indistinguishable from one signed on 1970-01-01";
    EXPECT_FALSE(imported->replayRefusalActive)
        << "the FALSE is the value worth knowing: rollback refusal is not operating";
    EXPECT_EQ(imported->anchors, 212u) << "the rest of the dict is unaffected";
    ::close(fd);
}

// Trust-on-first-import. There is nothing to check a FIRST master list
// against — a master list is what supplies anchors — so the first accepted one
// establishes the publisher and its fingerprint is reported for a person to
// recognise. `signerPinned == false` is how the agent says exactly that, and a
// surface that renders "authenticity verified" over it claims more than was
// measured. The false therefore has to survive both wires as a PRESENT false,
// never as an absence a consumer would read as "not reported".
TYPED_TEST(TransportParity, TrustOnFirstImportReportsAnUnpinnedSignerAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.cscaAnchorState.insert(QString(kCscaAnchorSignerPinned), false);
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const int fd = ::memfd_create("parity-master-list", MFD_CLOEXEC);
    ASSERT_GE(fd, 0);

    const auto imported = client->importCscaMasterList(fd);
    ASSERT_TRUE(imported.has_value());
    EXPECT_FALSE(imported->signerPinned)
        << "the publisher was observed, not established — both wires owe a caller that distinction";
    EXPECT_FALSE(imported->signer.isEmpty()) << "and the fingerprint to show a person is still reported";
    ::close(fd);
}

// The replay refusal, NAMED. Without its own enumerator a caller cannot tell
// "this list is already installed / older than the one you have" from any
// other import failure, and would have to render a raw D-Bus error name (or
// nothing) at the one moment a person can actually act on the answer.
TYPED_TEST(TransportParity, MasterListReplayRefusalIsNamedAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.cscaImportError = SyncError::MasterListReplayed;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const int fd = ::memfd_create("parity-master-list", MFD_CLOEXEC);
    ASSERT_GE(fd, 0);

    const auto imported = client->importCscaMasterList(fd);
    ASSERT_FALSE(imported.has_value()) << "a replayed list installs nothing";
    EXPECT_EQ(imported.error(), SyncError::MasterListReplayed)
        << "both wires must land on the SAME enumerator — a prefixed D-Bus error name on one, a "
           "sync-error token on the other";
    ::close(fd);
}

// An unreachable agent is the retryable class, and it must NOT be reported as
// a refusal the agent named: nothing on either wire said anything about this
// list.
TYPED_TEST(TransportParity, ImportAgainstAnAbsentAgentIsACommunicationErrorAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    env.vanishAgent();
    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));

    const int fd = ::memfd_create("parity-master-list", MFD_CLOEXEC);
    ASSERT_GE(fd, 0);

    const auto imported = client->importCscaMasterList(fd);
    ASSERT_FALSE(imported.has_value());
    EXPECT_EQ(imported.error(), SyncError::CommunicationError);
    EXPECT_EQ(env.cscaImportCallCount(), 0) << "nothing reached either fake";
    ::close(fd);
}

// ---- feature-gated entry: readTokenInfo() without "token-info" refuses
// identically on both transports, before either ever dials the wire --------
//
// Post-fix regression coverage: the "token-info" entry gate now lives in the
// transport-neutral AgentCard::startOperation (see its comment), not a
// socket-only special case. Before the lift, a pre-contract agent's
// ReadTokenInfo dialed the D-Bus wire and got back UnknownMethod, which
// ErrorNameMap/mapDBusErrorName classifies as CallError::InvalidArguments /
// ErrorCode::None — a forked taxonomy from the socket wire's local
// CapabilityMissing refusal. This scenario proves BOTH transports now agree:
// CapabilityMissing, and — via operationCount() — that neither transport's
// fake ever saw the request at all.
TYPED_TEST(TransportParity, MissingTokenInfoFeatureRefusesIdenticallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::Pki;
    cfg.features = {QStringLiteral("credentials")}; // no "token-info"
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("token-info")));

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readTokenInfo();
    ASSERT_NE(op, nullptr) << "a refused entry mints a failed operation, never nullptr";
    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    EXPECT_EQ(op->callError(), CallError::None)
        << "must classify through the wire taxonomy, never a forked CallError, on either transport";
    EXPECT_EQ(env.operationCount(), 0) << "the refusal must fire before either transport ever dials the wire";
}

// ---- Card-type + ATR — identical insertion snapshot AND identical
// post-read authoritative update, regardless of transport --------------------
TYPED_TEST(TransportParity, CardTypeAndAtrMatchAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.cardType = QStringLiteral("SRB-eID"); // the scripted single-candidate case
    cfg.atrHex = QStringLiteral("3B7F96000080318065B085040132900085");
    Env env(cfg);

    AgentCard* card = env.card();
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->cardType(), QStringLiteral("SRB-eID"))
        << "insertion must carry the scripted single-candidate cardType identically on both transports";
    EXPECT_EQ(card->atrHex(), QStringLiteral("3B7F96000080318065B085040132900085"))
        << "atrHex must be known from insertion identically on both transports";

    // No QSignalSpy here (this target does not link Qt::Test): a plain
    // connect-and-count is equivalent and avoids the extra link dependency.
    int cardTypeChangedCount = 0;
    QObject::connect(card, &AgentCard::cardTypeChanged, [&cardTypeChangedCount]() { ++cardTypeChangedCount; });
    env.triggerCardTypeChanged(QStringLiteral("SRB-Vehicle"));

    ASSERT_TRUE(waitFor([&]() { return card->cardType() == QStringLiteral("SRB-Vehicle"); }))
        << "the post-read authoritative update must flip cardType identically on both transports";
    EXPECT_GE(cardTypeChangedCount, 1);
}

// ---- Card-independent visual-signature layout preview ------------------
//
// Manager1.LayoutVisualSignature / GetAppearanceFont are synchronous, no-card,
// no-Operation calls — AgentClient::layoutVisualSignature()/appearanceFont()
// dial neither transport's Operation machinery at all. Both fakes are
// scripted from the SAME ParityConfig fields (layoutFontSize/layoutLineHeight/
// layoutLines/layoutClipped/appearanceFontBytes), so a client-observed result
// must agree field-for-field / byte-for-byte regardless of transport.

TYPED_TEST(TransportParity, LayoutVisualSignatureAndAppearanceFontMatchAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.features = {QStringLiteral("credentials"), QStringLiteral("layout-preview")};
    cfg.layoutFontSize = 8.5;
    cfg.layoutLineHeight = 10.2;
    cfg.layoutLines = {QStringLiteral("Потписао"), QStringLiteral("Немања")}; // Serbian Cyrillic UTF-8
    cfg.layoutClipped = false;
    QByteArray fontBytes = QByteArrayLiteral("\x00\x01\x02"
                                             "FAKE-TTF-BYTES");
    for (int i = 0; i < 64; ++i) {
        fontBytes.append(static_cast<char>(i));
    }
    cfg.appearanceFontBytes = fontBytes;
    const QByteArray expectedFontHash = QCryptographicHash::hash(fontBytes, QCryptographicHash::Sha256);
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    ASSERT_TRUE(client->hasFeature(QStringLiteral("layout-preview")));

    const std::optional<LayoutResult> layout =
        client->layoutVisualSignature(QStringLiteral("Потписао\nНемања"), QRectF(0, 0, 150, 60));
    ASSERT_TRUE(layout.has_value());
    EXPECT_DOUBLE_EQ(layout->fontSize, 8.5);
    EXPECT_DOUBLE_EQ(layout->lineHeight, 10.2);
    EXPECT_EQ(layout->lines, (QStringList{QStringLiteral("Потписао"), QStringLiteral("Немања")}));
    EXPECT_FALSE(layout->clipped);

    FdHandle font = client->appearanceFont();
    ASSERT_TRUE(font.valid());
    const QByteArray received = readFdAll(font.get());
    EXPECT_EQ(received, fontBytes);
    EXPECT_EQ(QCryptographicHash::hash(received, QCryptographicHash::Sha256), expectedFontHash)
        << "the received font FdHandle's content hash must match the agent-side bytes exactly, identically on "
           "both transports";

    // A second call is served from the per-connection cache, not a second
    // wire round trip — layoutCallCount() only counts LayoutVisual requests
    // (independent from appearanceFont()'s own separate GetAppearanceFont
    // count), so this proves caching without disturbing that assertion.
    FdHandle fontAgain = client->appearanceFont();
    ASSERT_TRUE(fontAgain.valid());
    EXPECT_EQ(env.appearanceFontCallCount(), 1) << "appearanceFont() must be cached per connection, not re-dialed";
}

// A box too small to fit even the floor font size is still a VALID call —
// `clipped` becomes true, and that flag must arrive client-side identically
// on both transports (its whole reason to ride the wire — see the CDDL
// `layout` arm's own comment).
TYPED_TEST(TransportParity, LayoutTinyBoxClippedArrivesAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.features = {QStringLiteral("layout-preview")};
    cfg.layoutClipped = true;
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());

    const std::optional<LayoutResult> layout =
        client->layoutVisualSignature(QStringLiteral("Hello World"), QRectF(0, 0, 4, 50));
    ASSERT_TRUE(layout.has_value());
    EXPECT_TRUE(layout->clipped) << "clipped==true must arrive client-side identically on both transports";
}

// Feature-gated local refusal: an agent that does not advertise
// "layout-preview" is refused WITHOUT either transport ever dialing the wire
// — mirrors MissingTokenInfoFeatureRefusesIdenticallyAcrossTransports above,
// via the layoutCallCount()/appearanceFontCallCount() probes instead of
// operationCount() (neither call mints an Operation).
TYPED_TEST(TransportParity, MissingLayoutPreviewFeatureRefusesLocallyAcrossTransports)
{
    using Env = typename TypeParam::Env;
    ParityConfig cfg;
    cfg.features = {QStringLiteral("credentials")}; // no "layout-preview"
    Env env(cfg);

    AgentClient* client = env.client();
    ASSERT_TRUE(client->isAvailable());
    EXPECT_FALSE(client->hasFeature(QStringLiteral("layout-preview")));

    const std::optional<LayoutResult> layout =
        client->layoutVisualSignature(QStringLiteral("Signed by"), QRectF(0, 0, 150, 60));
    EXPECT_FALSE(layout.has_value());
    const FdHandle font = client->appearanceFont();
    EXPECT_FALSE(font.valid());
    EXPECT_EQ(env.layoutCallCount(), 0) << "the gate must refuse before either transport ever dials the wire";
    EXPECT_EQ(env.appearanceFontCallCount(), 0) << "the gate must refuse before either transport ever dials the wire";
}
