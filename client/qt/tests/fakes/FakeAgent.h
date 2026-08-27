// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "dbus/Marshal.h" // reuse the client's own wire-shape mirrors + AgentInterfaceProps

#include "FakeCertFields.h" // the scripted cert `fields` dict, in one shape both fakes accept
#include "FakeConfig.h"     // the Config1 property set both fakes serve, in one shape

#include <QByteArray>
#include <QDBusAbstractAdaptor>
#include <QDBusConnection>
#include <QDBusContext>
#include <QDBusObjectPath>
#include <QDBusUnixFileDescriptor>
#include <QMap>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>
#include <memory>
#include <vector>

/// @file
/// @brief A real `org.librescrs.Agent` peer on a private session bus, for
///        exercising `LibreAgent::ClientQt` end-to-end. Mirrors the agent's
///        wire surface (ObjectManager + Reader1 + Card1 + a scripted
///        Operation1 with a typed Sign1/Identity1 result), but is driven
///        entirely by test scripting hooks — no PC/SC, no real card.
///
/// Run the host process under `dbus-run-session` so the bus is isolated.

namespace LibreSCRS::AgentClient::Fakes {

// a{sa{sv}} and a{oa{sa{sv}}} — the ObjectManager wire shapes. Reuse the
// client's own interface-props type (and its registered metatype) verbatim.
using FakeInterfaceProps = LibreSCRS::AgentClient::AgentInterfaceProps;
using FakeManagedObjects = QMap<QDBusObjectPath, FakeInterfaceProps>;

class FakeAgent;

/// @brief One scripted progressive field group: the ordered payload of ONE
///        Operation.Identity1.Group(groupKey, fields) signal. Distinct from
///        the final `buildIdentityFields()` map (keyed, unordered on the
///        wire) precisely because streaming order is the thing this signal
///        exists to carry — a plain QMap iterates key-sorted, not in
///        insertion order, so scripting an explicit ORDERED list is the only
///        way to pin "these 3 groups arrive in THIS order".
struct FakeIdentityGroup
{
    QString key;
    LibreSCRS::AgentClient::IdentityFieldGroupWire fields;
};

/// @brief A custom `org.freedesktop.DBus.Properties` adaptor whose `GetAll`
///        deliberately WEDGES by default — it marks the call a delayed reply
///        and never answers. Exercises a hung agent: the client's capped GetAll
///        must time out instead of stalling forever. Attached to the SAME
///        object that hosts the real Reader1/Card1 adaptor (shadowing its
///        auto-exported Properties interface) so a proxy discovered the
///        normal way can still be pointed at a wedged property refresh.
///        `scriptGetAllReply()` turns the wedge into a SLOW agent instead: the
///        call is answered after a scripted delay with a scripted props map,
///        for the async-refresh responsiveness and stale-reply-ordering tests.
///        MUST be parented to a `ContextObject`: the QDBusContext used to
///        wedge/delay lives on the registered object, never on the adaptor
///        itself (an adaptor's own context is not populated for plain method
///        calls).
class WedgedPropertiesAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.DBus.Properties")
public:
    explicit WedgedPropertiesAdaptor(QObject* parent) : QDBusAbstractAdaptor(parent) {}

    /// @brief Stop wedging: answer each GetAll after @p delayMs with @p props
    ///        (0 = reply on the next server event-loop turn).
    void scriptGetAllReply(int delayMs, const QVariantMap& props);

    /// @brief How many GetAll calls arrived so far (wedged and scripted alike),
    ///        so a test can assert a recovery re-fetch was actually issued.
    [[nodiscard]] int getAllCallCount() const;

public Q_SLOTS:
    QVariantMap GetAll(const QString& iface);

Q_SIGNALS:
    void PropertiesChanged(const QString& iface, const QVariantMap& changed, const QStringList& invalidated);

private:
    int m_replyDelayMs = -1;     ///< < 0 = wedge forever (default)
    QVariantMap m_scriptedProps; ///< the a{sv} payload a scripted reply carries
    int m_getAllCalls = 0;       ///< arrived GetAll calls (answered or wedged)
};

/// @brief ObjectManager adaptor on the root object.
class ObjectManagerAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.DBus.ObjectManager")
public:
    ObjectManagerAdaptor(QObject* parent, FakeAgent* agent);

public Q_SLOTS:
    FakeManagedObjects GetManagedObjects();

Q_SIGNALS:
    void InterfacesAdded(const QDBusObjectPath& objectPath, const FakeInterfaceProps& interfacesAndProperties);
    void InterfacesRemoved(const QDBusObjectPath& objectPath, const QStringList& interfaces);

private:
    FakeAgent* m_agent;
};

/// @brief Manager1 adaptor (root path): Version + Features. Faithful to the
///        real agent's root-hosted Manager1 interface. FakeAgent::Config::
///        exportManager1 = false omits this adaptor entirely — models an
///        agent predating the interface, so a client's Properties.GetAll for
///        Manager1 fails closed on the root object and MUST degrade to an
///        empty `features()` there, never an error.
class ManagerAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Manager1")
    Q_PROPERTY(QString Version READ version)
    Q_PROPERTY(QStringList Features READ features)
public:
    ManagerAdaptor(QObject* parent, QString version, QStringList features, FakeAgent* agent);
    [[nodiscard]] QString version() const;
    [[nodiscard]] QStringList features() const;

public Q_SLOTS:
    /// Card-independent, synchronous layout preview. Qt multi-out
    /// convention: the return value is the FIRST D-Bus out-arg (fontSize);
    /// lineHeight/lines/clipped ride the trailing non-const-reference
    /// parameters, in D-Bus out-arg order.
    double LayoutVisualSignature(const QString& text, double x, double y, double width, double height,
                                 double& lineHeight, QStringList& lines, bool& clipped);
    /// The embedded appearance font, sealed into a memfd per call (mirrors
    /// makeSealedArtifact's posture for Sign/Photo — the fd is dup'd fresh
    /// per delivery, never handed out shared).
    QDBusUnixFileDescriptor GetAppearanceFont();

    // Call counters — prove a client-side feature-gate refusal never dials
    // the wire at all (there is no Operation/op-count to check, unlike a
    // card method's refused entry).
    [[nodiscard]] int layoutCallCount() const
    {
        return m_layoutCalls;
    }
    [[nodiscard]] int appearanceFontCallCount() const
    {
        return m_appearanceFontCalls;
    }

private:
    QString m_version;
    QStringList m_features;
    FakeAgent* m_agent;
    int m_layoutCalls = 0;
    int m_appearanceFontCalls = 0;
};

/// @brief Config1 adaptor (root path): the nine agent-owned settings, all
///        read-only as PROPERTIES, mutated through SetValue/Reset so each
///        change is gated per key — faithful to
///        `org.librescrs.Agent.Config1`, including its four documented
///        refusals:
///          - `UnknownConfigKey`   no such key;
///          - `ReadOnlyConfig`     a file-only / agent-internal key
///                                 (TslCacheDir / AiaCacheDir / PluginDir /
///                                 LastTsaUrl);
///          - `NotAuthorized`      polkit denied;
///          - `InvalidConfigValue` wrong variant type for the key.
///
///        The first two are the agent's own STRUCTURAL policy and are
///        enforced here for real, because the client's socket half refuses
///        exactly those two locally and the parity corpus asserts both wires
///        land on the same refusal. The last two are authorization/validation
///        verdicts a client can only observe, so they are scripted
///        (`Config::configMutationError`) rather than modelled.
///
///        The error reply is minted through the registered root object's
///        QDBusContext (a `ContextObject`), mirroring `Pkcs11Adaptor` — an
///        adaptor's own context is not populated for plain method calls.
class Config1Adaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Config1")
    Q_PROPERTY(QString DefaultLevel READ defaultLevel)
    Q_PROPERTY(QStringList TsaUrls READ tsaUrls)
    Q_PROPERTY(QString LastTsaUrl READ lastTsaUrl)
    Q_PROPERTY(LibreSCRS::AgentClient::TslSourcesWire TslSources READ tslSources)
    Q_PROPERTY(QString TslCacheDir READ tslCacheDir)
    Q_PROPERTY(QString AiaCacheDir READ aiaCacheDir)
    Q_PROPERTY(QString DefaultReason READ defaultReason)
    Q_PROPERTY(QString DefaultLocation READ defaultLocation)
    Q_PROPERTY(QString PluginDir READ pluginDir)
public:
    Config1Adaptor(QObject* parent, FakeAgent* agent);

    [[nodiscard]] QString defaultLevel() const;
    [[nodiscard]] QStringList tsaUrls() const;
    [[nodiscard]] QString lastTsaUrl() const;
    [[nodiscard]] LibreSCRS::AgentClient::TslSourcesWire tslSources() const;
    [[nodiscard]] QString tslCacheDir() const;
    [[nodiscard]] QString aiaCacheDir() const;
    [[nodiscard]] QString defaultReason() const;
    [[nodiscard]] QString defaultLocation() const;
    [[nodiscard]] QString pluginDir() const;

public Q_SLOTS:
    void SetValue(const QString& key, const QDBusVariant& value);
    void Reset(const QString& key);

Q_SIGNALS:
    void Changed(const QString& key);

private:
    /// @brief Send the agent's per-key refusal for the active call, mirroring
    ///        `CardAdaptor::sendMethodEntryError`. Returns true when a refusal
    ///        was sent (the caller then changes nothing).
    bool refuse(const QString& shortName, const QString& message);

    FakeAgent* m_agent;
};

/// @brief Reader1 adaptor (Name / HasCard / Card properties).
class ReaderAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Reader1")
    Q_PROPERTY(QString Name READ name)
    Q_PROPERTY(bool HasCard READ hasCard)
    Q_PROPERTY(QDBusObjectPath Card READ card)
public:
    ReaderAdaptor(QObject* parent, QString name, bool hasCard, QDBusObjectPath card);
    [[nodiscard]] QString name() const;
    [[nodiscard]] bool hasCard() const;
    [[nodiscard]] QDBusObjectPath card() const;
    void setHasCard(bool v);
    void setCard(QDBusObjectPath v);

private:
    QString m_name;
    bool m_hasCard;
    QDBusObjectPath m_card;
};

/// @brief The QObject registered at a root/card/reader path. Inherits
///        QDBusContext so a sibling adaptor's method slots can mint a
///        method-entry error reply (the agent's UnsupportedOnThisCard etc.)
///        WITHOUT creating an Operation, or host a `WedgedPropertiesAdaptor`
///        — the context lives on the REGISTERED object, not on the adaptor
///        itself. Shared by the root, every card, and every reader object (a
///        reader never sends an entry error today, but hosting the context
///        unconditionally lets a `WedgedPropertiesAdaptor` attach to either).
class ContextObject : public QObject, public QDBusContext
{
    Q_OBJECT
public:
    explicit ContextObject(QObject* parent = nullptr) : QObject(parent) {}
};

/// @brief Card1 adaptor; ReadIdentity / Sign mint a scripted Operation1. On the
///        failMethodEntry path it errors at method entry (no Operation), driving
///        the client's CapabilityMissing entry-refusal path.
class CardAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Card1")
    Q_PROPERTY(uint Capabilities READ capabilities)
    Q_PROPERTY(QDBusObjectPath Reader READ reader)
    Q_PROPERTY(QString PreReadAuthMethod READ preReadAuthMethod)
    Q_PROPERTY(QString CardType READ cardType)
    Q_PROPERTY(QString Atr READ atr)
public:
    CardAdaptor(QObject* parent, FakeAgent* agent, uint capabilities, QDBusObjectPath reader, QString preReadAuth,
                QString cardType = {}, QString atrHex = {});
    [[nodiscard]] uint capabilities() const;
    [[nodiscard]] QDBusObjectPath reader() const;
    [[nodiscard]] QString preReadAuthMethod() const;
    [[nodiscard]] QString cardType() const;
    [[nodiscard]] QString atr() const;
    void setCapabilities(uint v);
    void setPreReadAuthMethod(QString v);
    void setCardType(QString v);

public Q_SLOTS:
    QDBusObjectPath ReadIdentity();
    QDBusObjectPath GetPhoto();
    QDBusObjectPath ReadCertificates();
    /// @brief Lightweight token-info read. Result rides the SAME Identity1
    ///        result path as ReadIdentity (FakeOperation::Kind::TokenInfo
    ///        selects a DIFFERENT scripted field map — the "token" group,
    ///        not "personal"). Gated the same way ReadCertificates is meant
    ///        to be (real agent: PKI capability bit) — see
    ///        `lacksPkiCapability()`, which THIS method enforces for real
    ///        (unlike ReadCertificates above, which only models the generic
    ///        `failMethodEntry` refusal today).
    QDBusObjectPath ReadTokenInfo();
    QDBusObjectPath Sign(const QString& certId, const QDBusUnixFileDescriptor& inputFd, const QVariantMap& options);
    /// @brief Card1.SignBatch(a(sh) documents, s certId, a{sv} options) -> o.
    ///        Reads each document's fd synchronously (same reasoning as
    ///        Sign() above), captures the verbatim in-args, and mints a
    ///        Kind::BatchSign operation carrying the per-document display
    ///        names (echoed back on the matching result rows).
    QDBusObjectPath SignBatch(const LibreSCRS::AgentClient::BatchDocumentsWire& documents, const QString& certId,
                              const QVariantMap& options);

private:
    /// @brief Send the agent's method-entry error (no Operation minted) for the
    ///        active call, returning a sentinel path the client discards.
    QDBusObjectPath sendMethodEntryError();
    /// @brief The real agent's capability entry gate for ReadTokenInfo: true
    ///        when THIS card's LIVE Capabilities lack bit 0 (Pki) —
    ///        UnsupportedOnThisCard, no Operation minted. Token info is
    ///        PKI-adjacent (pkcs15), so it shares ReadCertificates' gate bit.
    [[nodiscard]] bool lacksPkiCapability() const;

    FakeAgent* m_agent;
    uint m_capabilities;
    QDBusObjectPath m_reader;
    QString m_preReadAuth;
    QString m_cardType;
    QString m_atrHex;
};

/// @brief Credentials1 adaptor; parented to the same `ContextObject` as
///        `CardAdaptor` (so its method-entry error reply is minted through the
///        registered object's `QDBusContext`, mirroring
///        `CardAdaptor::sendMethodEntryError` — an adaptor's own context is not
///        populated for plain method calls). `ManagePin`/`ActivateSigningKey`/
///        `ListCredentials` each mint a scripted `FakeOperation::Kind::Credentials`
///        operation; on `Config::credEntryError` the two MUTATIONS
///        (`ManagePin`/`ActivateSigningKey`) instead send the scripted error name
///        at method entry (no Operation minted). `ListCredentials` stays exempt
///        from the scripted error, so a client's recovery / mandatory re-list
///        still succeeds.
///
///        The fake ENFORCES the real agent's entry contract:
///        - capability gate: without Card1 bit 3 (PinManagement) all three
///          methods throw UnsupportedOnThisCard (no Operation);
///        - request vocabulary: `ManagePin`'s verb must be one of
///          change | unblock | activate_pin, and its options map is the CLOSED
///          key set {activateKey: bool}, legal only with activate_pin — any
///          other verb, key, type or combination is refused InvalidRequest, so
///          a client wire-vocabulary regression fails the suite. A vocabulary
///          refusal never reaches the card and does not drop the listing;
///        - list-before-mutate: `ManagePin` without a current listing — never
///          listed, or invalidated by a previous mutation — is refused
///          UnknownCredential, as is a pinId absent from the CURRENT listing
///          snapshot (ids resolve only against what was last listed); both
///          mutations drop the listing cache, so a client that skips the
///          mandatory re-list fails loudly.
class CredentialsAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Credentials1")
public:
    /// @p cardAdaptor is the sibling Card1 adaptor of the SAME card object: the
    /// capability entry gate reads that card's LIVE Capabilities (each card is
    /// gated on its own bits, exactly like the real agent).
    CredentialsAdaptor(QObject* parent, FakeAgent* agent, CardAdaptor* cardAdaptor);

public Q_SLOTS:
    QDBusObjectPath ManagePin(const QString& pinId, const QString& verb, const QVariantMap& options);
    QDBusObjectPath ActivateSigningKey();
    QDBusObjectPath ListCredentials();

private:
    /// @brief Send @p errorName at method entry (no Operation minted), mirroring
    ///        `CardAdaptor::sendMethodEntryError`.
    QDBusObjectPath sendEntryError(const QString& errorName);
    /// @brief The real agent's capability entry gate: true when THIS card's
    ///        LIVE Capabilities lack bit 3 (PinManagement) — all three methods
    ///        then throw UnsupportedOnThisCard.
    [[nodiscard]] bool lacksPinManagement() const;

    FakeAgent* m_agent;
    CardAdaptor* m_cardAdaptor;
};

/// @brief Pkcs11_1 adaptor, hosted on the manager (root) path. Only `CertDer`
///        is modelled (the one client surface exercised here): returns the
///        scripted DER bytes, or a `…Error.KeyNotFound` D-Bus error when the
///        config requests it. The error reply is minted through the registered
///        root object's QDBusContext (a `ContextObject`), mirroring
///        CardAdaptor — an adaptor's own QDBusContext is not populated for
///        plain method calls.
class Pkcs11Adaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Pkcs11_1")
public:
    Pkcs11Adaptor(QObject* parent, FakeAgent* agent);

public Q_SLOTS:
    QByteArray CertDer(const QDBusObjectPath& reader, const QString& certId);

private:
    FakeAgent* m_agent;
};

/// @brief One scripted certificate the FakeAgent's Certificates1.Result emits.
///        Carries the full real-wire field-set so the cert Result can be
///        hand-marshalled into the raw (sba{sa{s(ssv)}}uasasu) struct.
struct FakeCert
{
    QString certId;
    bool signingCapable = false;
    QString subjectCn;
    QString issuerCn = {};                 ///< issuer/cn field group (display only)
    QString notBefore = {};                ///< validity/notBefore field group (display only)
    QString notAfter = {};                 ///< validity/notAfter field group (display only)
    uint keyUsageBits = 0;                 ///< u keyUsageBits
    QStringList extendedKeyUsageOids = {}; ///< as EKU OIDs
    QStringList chainSubjectCns = {};      ///< as ordered leaf..root CN chain
    uint trustStatus = 255;                ///< u trustStatus (255 = Unknown; 5 = Revoked, 6 = OfflineUnverified)
    /// Tokens riding the "security" fields-group (dict-key growth), mirroring
    /// trustStatus -- e.g. {"revoked"} for trustStatus=5, {"offline-unverified"}
    /// for trustStatus=6. Empty by default (matches the pre-Inc-6 wire, where
    /// no cert carried a "security" group at all).
    QStringList securityStatus = {};
    /// Any OTHER field group the real agent emits -- the group vocabulary is
    /// defined by the wire contract (cert-info's `fields` map in
    /// wire/librescrs-agent.cddl), not re-listed here. The five cells the
    /// members above stand for are derived from those members, so scripting
    /// the SAME cell here as well is pointless rather than harmful -- the
    /// derived value wins. Twin of FakeSocketCert::extraFields.
    Fakes::FakeCertFieldGroups extraFields = {};
};
using FakeCertList = QList<FakeCert>;

/// @brief A scripted Operation1 + its typed result interface. Emits its typed
///        Result then Finished after `delayMs` (0 = synchronous before the
///        method even returns, to exercise the lost-Finished race). Holds the
///        last Sign artifact for `GetResult()` recovery.
class FakeOperation : public QObject, protected QDBusContext
{
    Q_OBJECT
public:
    // Credentials covers ListCredentials AND the ManagePin/ActivateSigningKey
    // mutations: the op's typed Operation.Credentials1 Result carries the
    // scripted (credResult, credRecords) payload. TokenInfo rides the SAME
    // Identity1 result path as Identity (ReadTokenInfo mints NO new result
    // interface) but buildIdentityFields() serves a DIFFERENT scripted field
    // map for it — the "token" group.
    enum class Kind { Sign, Identity, Certificates, Photo, Credentials, TokenInfo, BatchSign };

    FakeOperation(QObject* parent, QDBusConnection connection, QString path, Kind kind, int delayMs, uint finalStatus,
                  uint finalErrorCode, bool suppressResult, FakeCertList certScript = {}, bool rawCertResult = false,
                  QByteArray photoBytes = {}, bool photoEmptyMap = false, bool announceConsentPhase = false,
                  bool lostSignalRecoverable = false, QVariantMap credResult = {},
                  LibreSCRS::AgentClient::CredentialRecordsWire credRecords = {},
                  QByteArray signArtifactBytes = QByteArrayLiteral("FAKE-SIGNED-ARTIFACT"), QVariantMap signMeta = {},
                  bool tokenInfoEmpty = false, QList<FakeIdentityGroup> identityGroupScript = {},
                  QStringList batchDisplayNames = {}, int batchHaltAtIndex = -1, uint batchHaltErrorCode = 0,
                  bool marksListingCurrent = false);
    ~FakeOperation() override;

    [[nodiscard]] QString path() const;
    void start();

    /// @brief Send the frozen NoResult D-Bus error for the active GetResult call
    ///        (mirrors the real Sign1 contract; sets setDelayedReply so the
    ///        adaptor's return value is discarded).
    void replyNoResult();

private:
    friend class FakeOperationAdaptor;
    friend class FakeSignAdaptor;
    friend class FakeSignBatchAdaptor;
    friend class FakeIdentityAdaptor;
    friend class FakeCertificatesAdaptor;
    friend class FakePhotoAdaptor;
    friend class FakeCredentialsAdaptor;
    void fire();
    /// @brief Build the deterministic Identity1 field map ("personal:given_name"
    ///        = "Ana") the Result signal AND Identity1.GetResult both serve, so
    ///        the recovery pull re-serves exactly what a live signal would.
    [[nodiscard]] LibreSCRS::AgentClient::IdentityFieldsWire buildIdentityFields() const;
    /// @brief Build the CertListWire from m_certScript, shared by the
    ///        Certificates1.Result emit and Certificates1.GetResult recovery.
    [[nodiscard]] LibreSCRS::AgentClient::CertListWire buildCertificateList() const;
    /// @brief Seal m_photoBytes into m_keptPhotoFd (idempotent). Called on the
    ///        Ok-result RETAIN path — whether or not the Result signal fires —
    ///        so Photo1.GetResult can re-dup a sealed memfd of the same bytes.
    void retainPhotoFd();
    /// @brief Emit an Operation1 Properties.PropertiesChanged carrying Phase=@p phase
    ///        (so the client's AgentOperation raises phaseChanged) — models the agent
    ///        announcing e.g. AwaitingConsent while a human is at the prompter.
    void emitPhase(uint phase);
    /// @brief Emit a Photo1.Result. Normally a one-entry `a{sh}` photo map (key
    ///        "personal:photo", value a sealed memfd holding m_photoBytes); when
    ///        m_photoEmptyMap is set, emits a genuinely EMPTY map (no entries) to
    ///        exercise the consumer's empty-map guard rather than the empty-fd one.
    void emitPhotoResult();
    /// @brief Hand-marshal the cert script into the raw a(sba{sa{s(ssv)}}uasasu)
    ///        struct and send it as a Certificates1.Result signal, bypassing the
    ///        client's operator<< so the client's operator>> is tested against a
    ///        payload it did NOT itself produce.
    void emitRawCertResult();
    /// @brief The Sign1 meta map `fire()` and `FakeSignAdaptor::GetResult()`
    ///        both serve: `m_signMeta` verbatim when scripted, else the
    ///        historical fixed script (format=pades level=b-b tsaUsed=false
    ///        chainComplete=false) — preserved so every caller that does not
    ///        pass `signMeta` keeps today's exact values.
    [[nodiscard]] QVariantMap effectiveSignMeta() const;
    /// @brief Seal one memfd per scripted batch document (idempotent),
    ///        mirroring `retainPhotoFd()`'s retain-once posture: a row at or
    ///        past `m_batchHaltAtIndex` seals ZERO bytes (the frozen failed-
    ///        row convention), every earlier row seals `m_signArtifactBytes`.
    void retainBatchFds();
    /// @brief Build the `a(sha{sv}u)` rows `fire()`'s Result signal AND
    ///        `FakeSignBatchAdaptor::GetResult()` both serve, from the
    ///        already-retained per-row fds (`retainBatchFds()` must have run
    ///        first). Each row's fd is handed out via `QDBusUnixFileDescriptor`'s
    ///        own internal dup (mirrors `FakeSignAdaptor::GetResult()`'s
    ///        posture, not `fire()`'s Sign-artifact belt-and-suspenders
    ///        pre-dup) — `m_keptBatchFds` stays open for a later call.
    [[nodiscard]] LibreSCRS::AgentClient::SignBatchRowsWire buildBatchRows() const;

    QDBusConnection m_connection;
    QString m_path;
    Kind m_kind;
    int m_delayMs;
    uint m_finalStatus;
    uint m_finalErrorCode;
    bool m_suppressResult; ///< finish Ok WITHOUT emitting the typed Result AND with nothing to recover (total loss)
    bool m_completed = false;
    /// A ListCredentials operation: the agent's listing cache is populated when
    /// THIS completes, not when the method that minted it returned.
    bool m_marksListingCurrent = false;
    bool m_lostSignalRecoverable = false; ///< finish Ok, SUPPRESS the Result signal, but RETAIN the payload so
                                          ///< GetResult recovers it (the deterministic lost-signal race)
    bool m_resultRetained = false;        ///< an Ok result was retained -> GetResult serves it (else NoResult)
    int m_keptArtifactFd = -1;            // for Sign GetResult recovery (owned)
    FakeCertList m_certScript;            // for Certificates1.Result
    bool m_rawCertResult = false;         // emit cert Result via a hand-marshalled raw signal
    QByteArray m_photoBytes;              // bytes the Photo1.Result sealed memfd carries
    bool m_photoEmptyMap = false;         // emit an EMPTY a{sh} (no entries) instead of one "personal:photo" entry
    bool m_announceConsentPhase = false;  // emit Phase=AwaitingConsent after a short delay, before finishing
    int m_keptPhotoFd = -1;               // sealed photo memfd, kept alive past the signal send (owned)
    QVariantMap m_credResult;             // a{sv} mutation result the Operation.Credentials1.Result carries
    LibreSCRS::AgentClient::CredentialRecordsWire m_credRecords; // aa{sv} records (empty for a mutation)
    QByteArray m_signArtifactBytes; // Sign1 Result/GetResult artifact bytes (default: "FAKE-SIGNED-ARTIFACT")
    QVariantMap m_signMeta;         // Sign1 Result/GetResult meta map (empty -> effectiveSignMeta()'s default)
    bool m_tokenInfoEmpty = false;  // Kind::TokenInfo: serve a present-but-EMPTY "token" group (SUCCESS, 0 fields)
    // Progressive-delivery script (Kind::Identity only; ignored otherwise).
    // Empty (default) streams nothing -- every pre-existing test's exact
    // buildIdentityFields() output is unaffected. Every scripted entry fires
    // live, in order, from fire(), strictly before the Result signal.
    QList<FakeIdentityGroup> m_identityGroupScript;
    // Kind::BatchSign scripting: the per-document display names captured off
    // the LIVE SignBatch() request (echoed back verbatim, mirroring the real
    // agent — NOT a Config field like every other script here), plus the
    // halt point/code the test author DOES pre-script via Config.
    QStringList m_batchDisplayNames;
    int m_batchHaltAtIndex = -1;
    uint m_batchHaltErrorCode = 0;
    std::vector<int> m_keptBatchFds; // one owned, sealed memfd per row (for GetResult recovery)
    std::unique_ptr<class FakeOperationAdaptor> m_opAdaptor;
    std::unique_ptr<QObject> m_resultAdaptor;
};

/// @brief Top-level fake agent. Constructs the tree on a caller-supplied
///        connection (a private `dbus-run-session` server connection) under
///        a caller-supplied service name; test hooks mutate state + script ops.
class FakeAgent : public QObject
{
    Q_OBJECT
public:
    struct Config
    {
        QString service;
        /// Reader1.Name of the initial reader (reader/0). Overridable so tests
        /// can model realistic PC/SC name shapes (serial groups, enumeration
        /// indices, dual-interface siblings) for bound-reader matching.
        QString readerName = QStringLiteral("Fake");
        /// Reader1.Name of the second reader (reader/1) the arrival helpers
        /// (`emitReaderArrivesEmpty`, `registerSecondReaderSilently`) register.
        QString reader2Name = QStringLiteral("Fake2");
        uint capabilities = 0;
        bool hasCard = true;
        QString preReadAuth = QStringLiteral("None");
        // Card1.CardType / Card1.Atr the initial card carries (Card1.Reader).
        // Empty (default) models the ambiguous/not-yet-known case; atrHex is
        // realistically always non-empty in production (an ATR is always
        // known at insertion) but stays scriptable-empty here too for the
        // "agent predating this surface" absence case.
        QString cardType;
        QString atrHex;
        int operationDelayMs = 5; ///< delay before an op fires its result/finished
        uint finalStatus = 0;     ///< 0 Ok / 1 Cancelled / 2 Error
        /// Terminal status for the ListCredentials operation ALONE, scripted apart
        /// from `finalStatus` above — which usually scripts the MUTATION a test is
        /// after (a wrong PIN finishes Error). The agent caches a snapshot only for
        /// a list that succeeded, so a listing dragged into a mutation's Error would
        /// leave every id unresolvable. Set to 2 to model a listing that itself failed.
        uint listingFinalStatus = 0;         ///< 0 Ok / 1 Cancelled / 2 Error
        uint finalErrorCode = 0;             ///< Finished errorCode when status==Error
        bool raceResultBeforeReturn = false; ///< fire op synchronously (delay ignored) before method returns
        bool suppressResult = false;         ///< finish Ok WITHOUT emitting the typed Result AND unrecoverable
                                     ///< (GetResult -> NoResult): the "GetResult also unavailable" negative case
        bool lostSignalRecoverable = false; ///< finish Ok, SUPPRESS the Result signal, but RETAIN the payload so
                                            ///< GetResult recovers it — the DETERMINISTIC lost-signal race (all kinds)
        FakeCertList certScript;            ///< certs ReadCertificates emits on its Certificates1.Result
        bool failMethodEntry =
            false; ///< ReadIdentity/GetPhoto/ReadCertificates/Sign send a D-Bus error at entry (no Operation minted)
        /// Card1.ReadCertificates accepts the call and then NEVER replies —
        /// no Operation minted, no error sent, the caller's pending call left
        /// to time out on its own budget. The wedged-agent model for the
        /// entry-call path specifically (`wedgeGetManagedObjects` below does
        /// the same for discovery, and `wedgeCardProperties` for the property
        /// path). This is what distinguishes a call that WAITS for its entry
        /// reply from one that does not: the former stalls for the full call
        /// budget, the latter returns at once.
        bool wedgeCertificatesEntry = false;
        /// ReadTokenInfo's Identity1 result carries a present-but-EMPTY
        /// "token" group instead of the scripted label/serial_number/
        /// manufacturer fields — the unsupported/best-effort-miss plugin
        /// case, a SUCCESS with zero fields (never an error).
        bool tokenInfoEmpty = false;
        bool rawCertResult = false; ///< emit the cert Result as a hand-marshalled raw signal (bypasses operator<<)
        QByteArray photoBytes;      ///< bytes the GetPhoto Photo1.Result sealed memfd carries ("personal:photo")
        bool photoEmptyMap =
            false; ///< Photo op emits a genuinely EMPTY a{sh} (no entries) — exercises the empty-map guard
        bool photoSuppressResult = false; ///< Photo op finishes Ok WITHOUT emitting any Result (lost-Result race)
        QByteArray certDerBytes;          ///< DER bytes Pkcs11_1.CertDer returns on success
        bool certDerKeyNotFound = false;  ///< CertDer sends …Error.KeyNotFound instead of returning bytes
        /// CertDer answers a well-formed REPLY carrying no arguments at all —
        /// a reply outside this method's contract, which the peer named
        /// nothing about. Models the exchange failing on the client's side of
        /// the decode rather than the agent refusing; the socket fake's
        /// certDerUnexpectedArm is the same fault on the other wire.
        bool certDerEmptyReply = false;
        bool wedgeGetManagedObjects =
            false; ///< ObjectManager.GetManagedObjects never replies (models the discovery-path hang)
        bool announceConsentPhase =
            false; ///< the op emits an Operation1 Phase=AwaitingConsent (a human at the prompter) before finishing
        bool credEntryError = false; ///< the id-bearing ManagePin/ActivateSigningKey send a D-Bus error at entry
                                     ///< (no Operation minted); ListCredentials is id-less and stays exempt
        QString credEntryErrorName =
            QStringLiteral("org.librescrs.Agent.Error.UnknownCredential"); ///< the error name credEntryError sends
        QVariantMap credResult; ///< a{sv} mutation result the minted Operation.Credentials1.Result carries (and
                                ///< GetResult re-serves) — delivered for EVERY completed attempt, Ok or Error
        LibreSCRS::AgentClient::CredentialRecordsWire
            credRecords; ///< aa{sv} records a ListCredentials op returns; empty for a mutation (a legitimate result)
        /// Sign1 Result/GetResult artifact bytes. Default preserves the
        /// historical "FAKE-SIGNED-ARTIFACT" literal every pre-existing suite
        /// asserts on; scriptable so a cross-transport test can request
        /// IDENTICAL bytes from both fakes for a byte-for-byte content-hash
        /// comparison.
        QByteArray signArtifactBytes = QByteArrayLiteral("FAKE-SIGNED-ARTIFACT");
        /// Sign1 Result/GetResult meta map. Empty (default) preserves the
        /// historical fixed script (format=pades level=b-b tsaUsed=false
        /// chainComplete=false); scriptable for the same cross-transport
        /// reason as signArtifactBytes above.
        QVariantMap signMeta;
        /// SignBatch: from THIS 0-based row index onward (inclusive), every
        /// row's artifact is a ZERO-LENGTH sealed memfd and its errorCode is
        /// batchHaltErrorCode — the SAME per-row halt-code convention the
        /// real agent's Operation.SignBatch1.Result freezes (a wrong/blocked
        /// signing credential halts the remaining documents). -1 (default)
        /// means no halt: every row succeeds with signArtifactBytes/signMeta,
        /// mirroring a normal Sign per document. batchHaltAtIndex==0 with a
        /// single-document batch models an all-failed batch.
        int batchHaltAtIndex = -1;
        uint batchHaltErrorCode = 0;
        /// Attach a `WedgedPropertiesAdaptor` to the card object at construction
        /// time, shadowing its auto-exported Properties interface (GetAll never
        /// replies until scripted via `scriptCardGetAll`). Requires hasCard=true.
        bool wedgeCardProperties = false;
        /// Ditto for the (always-present) reader object.
        bool wedgeReaderProperties = false;
        /// Manager1.Version the fake serves. Unused by any client today (kept
        /// for interface fidelity with the real agent's root-hosted Manager1).
        QString agentVersion = QStringLiteral("0.0-fake-dbus");
        /// Manager1.Features the fake serves when exportManager1 is true —
        /// mirrors FakeSocketAgent::Config::features's default/shape (drop
        /// "credentials" to script an agent predating the credential request
        /// family on THIS wire too).
        QStringList features = {QStringLiteral("credentials")};
        /// Whether the fake exports Manager1 AT ALL (default true). false
        /// models an agent predating this interface entirely: a client's
        /// Properties.GetAll("...Manager1") on the root object fails closed,
        /// and features() must degrade to an empty list, never an error.
        bool exportManager1 = true;
        /// The Config1 property set this fake serves, keyed by the nine wire
        /// spellings and valued in the canonical client-side shape (see
        /// defaultAgentConfig()). Also the RESET target: the fake snapshots
        /// this map at construction and Reset(key) restores that entry, which
        /// is exactly the real store's "reset to the built-in default".
        QVariantMap config = defaultAgentConfig();
        /// Refuse every Config1 MUTATION with this agent-namespace short
        /// name instead of applying it — the authorization/validation half of
        /// the interface's refusal vocabulary ("NotAuthorized" for a polkit
        /// denial, "InvalidConfigValue" for a value the agent rejects), which
        /// a client can only observe. Empty (default) applies the real
        /// structural policy instead (unknown key / read-only key). Mirrors
        /// FakeSocketAgent::Config::configMutationError.
        QString configMutationError;
        /// Manager1.LayoutVisualSignature's scripted reply. Defaults
        /// model a plausible two-line layout; a cross-transport parity test
        /// scripts these to the SAME values on both fakes for an exact
        /// comparison, and a tiny-box test scripts layoutClipped=true (the
        /// field's whole reason to ride the wire).
        double layoutFontSize = 9.5;
        double layoutLineHeight = 11.4;
        QStringList layoutLines = {QStringLiteral("Signed by"), QStringLiteral("John Doe")};
        bool layoutClipped = false;
        /// Manager1.GetAppearanceFont's scripted bytes, sealed into a memfd
        /// per call. Default is a small deterministic stand-in (NOT a real
        /// TTF) — a content-hash-comparison test scripts real bytes
        /// explicitly.
        QByteArray appearanceFontBytes = QByteArrayLiteral("FAKE-LIBERATION-SANS-TTF");
        /// Ordered per-group sequence a ReadIdentity op streams via
        /// Operation.Identity1.Group BEFORE its Result (see FakeIdentityGroup's
        /// own doc comment for why this is an explicit ordered list rather
        /// than a QMap). Empty (default) streams nothing — every
        /// pre-existing test is unaffected. When non-empty, buildIdentityFields()
        /// also switches from the historical fixed "personal:given_name"
        /// script to the UNION of this list, so Result/GetResult always
        /// matches what streamed.
        QList<FakeIdentityGroup> identityGroupScript;
    };

    FakeAgent(QDBusConnection connection, Config config, QObject* parent = nullptr);
    ~FakeAgent() override;

    [[nodiscard]] QDBusConnection connection() const;
    [[nodiscard]] QString service() const;
    [[nodiscard]] QString rootPath() const;
    [[nodiscard]] QString readerPath() const;
    [[nodiscard]] QString cardPath() const;

    /// @brief Script the card's wedged Properties.GetAll (Config::wedgeCardProperties
    ///        must be set) to answer after @p delayMs with @p props instead of
    ///        wedging forever (a SLOW agent, not a hung one).
    void scriptCardGetAll(int delayMs, const QVariantMap& props);
    /// @brief How many GetAll calls reached the card's wedge so far (answered or
    ///        wedged), so a test can assert a recovery re-fetch was issued.
    [[nodiscard]] int cardGetAllCallCount() const;
    /// @brief Ditto for the reader's wedge (Config::wedgeReaderProperties).
    void scriptReaderGetAll(int delayMs, const QVariantMap& props);
    [[nodiscard]] int readerGetAllCallCount() const;

    /// @brief Emit a Card1 Properties.PropertiesChanged carrying @p changed
    ///        directly-applied values and/or @p invalidated stale-property
    ///        names — the general form behind the capability-specific helpers
    ///        below, for tests that need to move a DIFFERENT property (e.g.
    ///        PreReadAuthMethod) or combine changed+invalidated in one signal.
    void emitCardPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated = {});
    /// @brief Ditto for Reader1.
    void emitReaderPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated = {});

    [[nodiscard]] FakeManagedObjects managedObjects() const;
    [[nodiscard]] Config& config();

    /// @brief The live Config1 value behind @p key (empty QVariant when the
    ///        key is absent), so a test can assert what the agent ACTUALLY
    ///        stored rather than only what the client read back.
    [[nodiscard]] QVariant configValue(const QString& key) const;
    /// @brief Apply a Config1 mutation the way the interface does: store the
    ///        value (or, for @p reset, restore the construction-time default)
    ///        and emit Changed(key). Called by Config1Adaptor after its
    ///        refusal checks pass.
    void applyConfigValue(const QString& key, const QVariant& value);
    void resetConfigValue(const QString& key);
    /// @brief Emit Config1.Changed(key) without changing anything — the
    ///        agent-internal mutation path (the real agent fires Changed for
    ///        LastTsaUrl after a timestamped sign, which no client wrote).
    void emitConfigChanged(const QString& key);

    /// @brief How many Manager1.LayoutVisualSignature/GetAppearanceFont calls
    ///        reached this fake — proves a client-side "layout-preview"
    ///        feature-gate refusal never dialed the wire at all (there is no
    ///        Operation/op-count to check for these two card-independent
    ///        calls, unlike a refused card method's entry).
    [[nodiscard]] int layoutCallCount() const;
    [[nodiscard]] int appearanceFontCallCount() const;

    /// @brief Total Operation1 objects minted so far (ReadIdentity/GetPhoto/
    ///        ReadCertificates/Sign). The lazy-card-I/O probe: classification +
    ///        discovery mint ZERO ops, so a non-zero count means a content read.
    [[nodiscard]] int operationCount() const;

    /// @brief Mint a scripted operation object, returning its path. A
    ///        Credentials MUTATION passes @p withCredRecords = false: the real
    ///        agent's mutation Result carries only the a{sv} outcome — records
    ///        ride ListCredentials results alone. @p batchDisplayNames is
    ///        BatchSign-only: the per-document names captured off the LIVE
    ///        SignBatch() request (see FakeOperation's own doc comment).
    QDBusObjectPath mintOperation(FakeOperation::Kind kind, bool withCredRecords = true,
                                  QStringList batchDisplayNames = {});

    /// @brief Capture the verbatim Sign() in-args (CardAdaptor::Sign dups +
    ///        reads inputFd synchronously, before the client closes its fd).
    void captureSign(const QString& certId, const QByteArray& inputBytes, const QVariantMap& options);

    /// @brief Last Sign() certId / options / input-document bytes, as the fake
    ///        actually received them on the wire.
    [[nodiscard]] QString lastSignCertId() const;
    [[nodiscard]] QVariantMap lastSignOptions() const;
    [[nodiscard]] QByteArray lastSignInputBytes() const;

    /// @brief Capture the verbatim SignBatch() in-args (CardAdaptor::SignBatch
    ///        dups + reads every document fd synchronously, before the client
    ///        closes its copies).
    void captureSignBatch(const QString& certId, const QStringList& displayNames,
                          const QList<QByteArray>& documentBytes, const QVariantMap& options);

    /// @brief Last SignBatch() certId / options / per-document display names
    ///        and input bytes (index-aligned), as the fake actually received
    ///        them on the wire.
    [[nodiscard]] QString lastSignBatchCertId() const;
    [[nodiscard]] QVariantMap lastSignBatchOptions() const;
    [[nodiscard]] QStringList lastSignBatchDisplayNames() const;
    [[nodiscard]] QList<QByteArray> lastSignBatchDocumentBytes() const;

    /// @brief Record + read the (reader, certId) the last Pkcs11_1.CertDer call
    ///        carried, so a test can assert the client addressed the right card.
    void captureCertDer(const QString& reader, const QString& certId);
    [[nodiscard]] QString lastCertDerReader() const;
    [[nodiscard]] QString lastCertDerCertId() const;

    /// @brief Capture the verbatim Credentials1.ManagePin in-args, exactly as
    ///        `CredentialsAdaptor::ManagePin` received them off the wire —
    ///        BEFORE any refusal branch, so a refused request is captured too
    ///        (mirrors `captureSign()`'s own "capture what actually crossed
    ///        the wire" discipline, and `FakeSocketAgent`'s identical
    ///        capture-first placement for the same request).
    void captureManagePin(const QString& pinId, const QString& verb, const QVariantMap& options);

    /// @brief Last ManagePin() pinId / verb / options, as the fake actually
    ///        received them on the wire. `lastManagePinOptions()` is the D-Bus
    ///        analogue of `FakeSocketAgent::lastManagePinOptions()` — the two
    ///        exist so a transport-parity scenario can assert the SAME
    ///        request-content check against both fakes without branching.
    [[nodiscard]] QString lastManagePinId() const;
    [[nodiscard]] QString lastManagePinVerb() const;
    [[nodiscard]] QVariantMap lastManagePinOptions() const;

    /// @brief Insert/remove the card live (emits InterfacesAdded/Removed plus
    ///        a Reader1 HasCard PropertiesChanged, mirroring the real agent).
    void setCardPresent(bool present);

    /// @brief Model the agent's deferred-publish window (or a dropped
    ///        `InterfacesAdded`): register the `Card1` object so it appears in
    ///        `GetManagedObjects`, flip the owning Reader1 to HasCard=true /
    ///        Card=<cardPath> and emit that Reader1 `PropertiesChanged` — but do
    ///        NOT emit the `Card1` `InterfacesAdded`. A client thus sees the
    ///        reader claim a card it cannot resolve until it re-runs discovery.
    ///        Precondition: no card is present yet (construct with
    ///        `Config::hasCard = false`).
    void exportCardSilently();

    /// @brief The inverse of exportCardSilently: unregister the `Card1` object so
    ///        `GetManagedObjects` stops returning it and flip the owning `Reader1`
    ///        to HasCard=false / Card="/", but emit NEITHER `InterfacesRemoved` NOR
    ///        the `Reader1` `PropertiesChanged`. Models a DROPPED removal signal —
    ///        the client still tracks a card the agent no longer exports, so only a
    ///        discovery re-run (reconcile) can drop it.
    void dropCardSilently();

    /// @brief Register a SECOND reader (present, empty) so `GetManagedObjects`
    ///        returns it, but DON'T emit its `InterfacesAdded` — the client's
    ///        live roster misses it (the hot-plugged-reader signal drop) until a
    ///        manual discovery re-run picks it up.
    void registerSecondReaderSilently();

    /// @brief Emit a Reader1 PropertiesChanged flipping HasCard *and* Card
    ///        together (both full values in the `changed` map), mirroring the
    ///        real agent's presence model. Reads the current Card path off the
    ///        reader adaptor, so callers must set it first.
    void emitReaderHasCardChanged(bool hasCard);

    /// @brief Change the card's Capabilities and emit a Properties.PropertiesChanged
    ///        carrying the FULL new value in the `changed` map (mirrors the
    ///        agent, which never relies on `invalidated`). Lets a test assert the
    ///        client applies `changed` without a Get round-trip.
    void emitCardCapabilitiesChanged(uint capabilities);

    /// @brief Change the card's CardType and emit a Properties.PropertiesChanged
    ///        carrying the FULL new value — the post-read authoritative update
    ///        (IdentityReadFlow resolving CardData::cardType), mirroring
    ///        emitCardCapabilitiesChanged's pattern.
    void emitCardTypeChanged(const QString& cardType);

    /// @brief Change the card's Capabilities and emit a PropertiesChanged that
    ///        marks the property `invalidated` (empty `changed`), forcing the
    ///        client onto its single-GetAll fallback path.
    void invalidateCardCapabilities(uint capabilities);

    /// @brief Change the card's Capabilities WITHOUT any signal — models a
    ///        client-vs-agent capability desync, so the Credentials1 entry gate
    ///        can refuse a client whose cached caps still advertise the bit.
    void setCardCapabilitiesSilently(uint capabilities);

    /// @brief How many Operation1.Cancel calls reached minted operations so far
    ///        — the observable seam for "an abandoned op was cancelled
    ///        agent-side" (a re-target must dismiss the orphaned read's prompt).
    [[nodiscard]] int cancelledOperationCount() const;
    void noteOperationCancelled();

    /// @brief Whether a ListCredentials has been issued on the card and no
    ///        mutation has invalidated it since (the agent's per-session listing
    ///        cache). ManagePin is refused UnknownCredential while false.
    [[nodiscard]] bool hasCurrentListing() const;
    /// @brief A ListCredentials was issued: mark the listing current and
    ///        snapshot the ids it returned (from the scripted records), the set
    ///        ManagePin resolves pinIds against.
    void noteListingIssued();
    /// @brief Drop the listing cache (a mutation reached the card, or a card
    ///        removal/insertion started a new session): the flag AND the id
    ///        snapshot are cleared together.
    void invalidateListing();
    /// @brief True when @p pinId is part of the CURRENT listing snapshot.
    [[nodiscard]] bool isListedId(const QString& pinId) const;

    /// @brief Re-emit ObjectManager.InterfacesAdded for the EXISTING card path
    ///        carrying changed Capabilities, so a test can assert the client
    ///        UPDATES the already-tracked card instead of dropping the new props.
    void reAddCardWithCapabilities(uint capabilities);

    /// @brief Faithful "a reader arrives already holding a card" sequence on a
    ///        SECOND reader/card path, mirroring the real agent's presence-model
    ///        ordering, split into three steps so the client can process (and
    ///        register its per-path match rules for) each before the next:
    ///          step (a) emitReaderArrivesEmpty: Reader1 InterfacesAdded for a NEW
    ///                   reader path with HasCard=false / Card="/";
    ///          step (b) emitArrivedReaderCardAdded: Card1 InterfacesAdded;
    ///          step (c) emitArrivedReaderHasCard: Reader1 PropertiesChanged
    ///                   flipping HasCard=true AND Card=<cardPath> together.
    ///        A reader never arrives with HasCard already true. Returns the new
    ///        card path (valid after step (b)).
    void emitReaderArrivesEmpty();
    QString emitArrivedReaderCardAdded(uint capabilities, const QString& preReadAuth = QStringLiteral("None"));
    void emitArrivedReaderHasCard();

private:
    void exportTree();

    QDBusConnection m_connection;
    Config m_config;
    QString m_rootPath = QStringLiteral("/org/librescrs/Agent");
    QString m_readerPath = QStringLiteral("/org/librescrs/Agent/reader/0");
    QString m_cardPath = QStringLiteral("/org/librescrs/Agent/card/0");
    int m_opCounter = 0;

    /// The agent's per-session listing cache marker: set by ListCredentials,
    /// cleared by any mutation (and by card removal/insertion). ManagePin is
    /// refused UnknownCredential while false — list-before-mutate is enforced.
    bool m_hasCurrentListing = false;
    /// The ids the CURRENT listing returned (snapshotted from the scripted
    /// records at list time); ManagePin refuses any pinId outside this set.
    QStringList m_currentListingIds;
    /// Operation1.Cancel calls received by minted ops (see cancelledOperationCount).
    int m_cancelledOps = 0;

    QObject* m_rootObject = nullptr;
    ContextObject* m_readerObject = nullptr;
    ContextObject* m_cardObject = nullptr;
    WedgedPropertiesAdaptor* m_cardPropsWedge = nullptr;
    WedgedPropertiesAdaptor* m_readerPropsWedge = nullptr;
    ObjectManagerAdaptor* m_objectManager = nullptr;
    ManagerAdaptor* m_managerAdaptor = nullptr; // null when Config::exportManager1 is false
    Config1Adaptor* m_configAdaptor = nullptr;
    /// Config::config as constructed — Reset(key)'s restore target.
    QVariantMap m_configDefaults;
    ReaderAdaptor* m_readerAdaptor = nullptr;
    CardAdaptor* m_cardAdaptor = nullptr;
    Pkcs11Adaptor* m_pkcs11Adaptor = nullptr;
    QList<FakeOperation*> m_operations;

    // Second reader/card, materialised on demand by emitReaderArrivesThenCard.
    QString m_reader2Path = QStringLiteral("/org/librescrs/Agent/reader/1");
    QString m_card2Path = QStringLiteral("/org/librescrs/Agent/card/1");
    QObject* m_reader2Object = nullptr;
    QObject* m_card2Object = nullptr;
    ReaderAdaptor* m_reader2Adaptor = nullptr;
    CardAdaptor* m_card2Adaptor = nullptr;

    QString m_lastSignCertId;
    QVariantMap m_lastSignOptions;
    QByteArray m_lastSignInputBytes;

    QString m_lastSignBatchCertId;
    QVariantMap m_lastSignBatchOptions;
    QStringList m_lastSignBatchDisplayNames;
    QList<QByteArray> m_lastSignBatchDocumentBytes;

    QString m_lastCertDerReader;
    QString m_lastCertDerCertId;

    QString m_lastManagePinId;
    QString m_lastManagePinVerb;
    QVariantMap m_lastManagePinOptions;
};

} // namespace LibreSCRS::AgentClient::Fakes

// FakeInterfaceProps == LibreSCRS::AgentClient::AgentInterfaceProps, already
// declared a metatype by Marshal.h/ensureDBusMetatypes(); only the
// managed-objects map is new here.
Q_DECLARE_METATYPE(LibreSCRS::AgentClient::Fakes::FakeManagedObjects)
