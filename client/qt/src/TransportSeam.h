// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The pure-virtual seam between the public
// AgentClient/AgentReader/AgentCard/AgentOperation classes and a concrete
// transport. The D-Bus transport (src/dbus/DBusTransport) implements it now;
// the socket transport (a later task) implements the SAME interface, and the
// transport-parity suite parametrizes over both via ClientTestAccess.
//
// Design rule: this seam carries ONLY what the public classes actually need —
// availability watch, registry snapshot + live add/remove, per-object property
// tracking, operation start/subscribe/recover/cancel with fd passing, and the
// DER public-data fetch — expressed exclusively in public value types
// (QString ids, QVariant maps, FdHandle) plus the std-only wire enums. No
// QtDBus, no wire-internal types: everything transport-specific is scrubbed
// by the transport BEFORE it crosses this boundary.
//
// Timeout contract: implementations bound EVERY call using the public
// ClientTimeouts.h budgets — discovery/probe calls at kHandshakeTimeoutMs,
// method-entry and recovery calls at kDefaultCallTimeoutMs — so a wedged
// agent can never hang a caller (the lifted client's capped-call discipline).
//
// Threading contract: single-threaded. Every listener callback is delivered
// on the thread the seam lives in, either synchronously from within a seam
// call or from the thread's event loop — never from a foreign thread.
#include <LibreSCRS/AgentClient/CallError.h>
#include <LibreSCRS/AgentClient/CredentialTypes.h>
#include <LibreSCRS/AgentClient/ErrorCode.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/OperationPhase.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/SyncError.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QByteArray>
#include <QList>
#include <QRectF>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVariantMap>

#include <expected>
#include <optional>
#include <vector>

namespace LibreSCRS::AgentClient {

/// How a seam call failed. Exactly one axis is set per failure:
///   - callError: the call produced NO wire-level answer (agent unreachable,
///     timeout, transport break) or was rejected before an operation started
///     for a reason outside the wire error taxonomy (bad arguments, access
///     denied).
///   - errorCode: the agent ANSWERED with a wire-taxonomy refusal (missing
///     capability, rate limit, unknown card, ...).
/// wireName/message carry the transport's raw spelling for diagnostics only —
/// they never reach the public API as a contract (the scrub that replaced the
/// lifted client's error-name strings).
///
/// syncError is a THIRD axis, orthogonal to both of the above rather than
/// alternative to either: it is engaged whenever the failure was named in the
/// wire's `sync-error` vocabulary, and it says WHICH name — the distinction the
/// callError/errorCode classifications deliberately collapse (several names
/// share one bucket). It is a typed enumerator, not a string, so it can cross
/// into the public API where `wireName` must not.
///
/// @warning Do NOT derive it from `wireName`. That field holds whatever
///          spelling the transport had: the D-Bus branch stores the FULL
///          freedesktop name for a bus-daemon error, and the socket branch
///          stores a synthetic `code:N` for the numeric arm. `syncError` is set
///          at the one classification site that actually sees a sync-error
///          token, and stays disengaged everywhere else.
struct SeamError
{
    CallError callError = CallError::None;
    ErrorCode errorCode = ErrorCode::None;
    /// The wire's own name for this failure, when it had one. Disengaged when
    /// no sync-error token was involved at all — a bus-daemon/transport-level
    /// failure, a numeric-taxonomy answer, or a local refusal this client
    /// decided without borrowing the wire vocabulary.
    std::optional<SyncError> syncError;
    QString wireName;
    QString message;

    [[nodiscard]] bool isError() const
    {
        return callError != CallError::None || errorCode != ErrorCode::None;
    }
};

/// One discovered registry object: its opaque id plus the property map in the
/// canonical vocabulary (the agent contract's property names — readers:
/// "Name" / "HasCard" / "Card"; cards: "Capabilities" / "PreReadAuthMethod" /
/// "Reader" / "CardType" / "Atr"), with every object reference already
/// flattened to an opaque QString id. CardType/Atr may be absent against an
/// agent predating this surface (the client's applyProps degrades absence to
/// its cached/default empty value, never an error).
struct RegistryObject
{
    QString id;
    QVariantMap properties;
};

/// A full discovery snapshot, split by object kind.
struct RegistrySnapshot
{
    QList<RegistryObject> readers;
    QList<RegistryObject> cards;
};

/// Which registry object a property subscription addresses.
enum class ObjectKind : unsigned char { Reader, Card };

/// Which typed result an operation binds (== the minting method family).
enum class OperationKind : unsigned char { Identity, Photo, Certificates, Sign, Credentials, BatchSign };

/// One card-method invocation, already encoded to the wire vocabulary by the
/// caller (enum options -> token strings via the internal TokenMap): the seam
/// and the transports never see the public enums, so the token mapping is
/// pinned in exactly one place. Move-only (the Sign document fd).
struct OperationRequest
{
    enum class Method : unsigned char {
        ReadIdentity,
        GetPhoto,
        ReadCertificates,
        ReadTokenInfo,
        Sign,
        SignBatch,
        ListCredentials,
        ManagePin,
        ActivateSigningKey,
    };

    Method method = Method::ReadIdentity;
    QString certId;                       ///< Sign/SignBatch only.
    FdHandle document;                    ///< Sign only — the document to sign, passed by fd.
    std::vector<BatchDocument> documents; ///< SignBatch only — one entry per document, passed by fd.
    QString pinId;                        ///< ManagePin only.
    QString verb;                         ///< ManagePin only — the wire verb token.
    QVariantMap options;                  ///< Sign/SignBatch/ManagePin — wire-keyed option map.
};

/// Outcome of a method-entry call: the minted operation's id, or the entry
/// failure (empty id).
struct StartOutcome
{
    QString operationId;
    SeamError error;
};

/// The polled terminal triple of an operation (the lost-Finished recovery
/// read). `completed == false` means the operation is still running.
struct TerminalSnapshot
{
    bool completed = false;
    OperationStatus status = OperationStatus::Error;
    ErrorCode errorCode = ErrorCode::None;
};

/// One typed operation payload, already scrubbed to public value types by the
/// transport. `kind` selects which member is meaningful. Move-only (fds).
struct OperationPayload
{
    OperationKind kind = OperationKind::Identity;
    QList<FieldGroup> identity;
    QList<CertificateInfo> certificates;
    std::vector<PhotoItem> photos;
    FdHandle signedArtifact;
    QVariantMap signMeta;
    std::vector<BatchSignRow> batchRows; ///< SignBatch only.
    PinResult pinResult;
    CredentialList credentials;
};

/// Outcome of the asynchronous DER fetch.
struct DerOutcome
{
    QByteArray der;
    SeamError error;
};

/// Implemented by AgentClient: agent liveness + registry add/remove + the
/// agent-wide settings change. A live object-added notification for one
/// discovery event delivers the CARD before the READER (the lifted ordering —
/// a reader's card reference must resolve immediately).
///
/// Config lands here rather than on a listener of its own because it is
/// addressed the same way liveness is: to the CLIENT, not to any reader or
/// card. One listener, one registration, one lifetime rule.
class RegistryListener
{
public:
    virtual ~RegistryListener() = default;
    virtual void onServiceRegistered() = 0;
    virtual void onServiceUnregistered() = 0;
    virtual void onReaderAdded(const QString& readerId, const QVariantMap& properties) = 0;
    virtual void onCardAdded(const QString& cardId, const QVariantMap& properties) = 0;
    virtual void onReaderRemoved(const QString& readerId) = 0;
    virtual void onCardRemoved(const QString& cardId) = 0;
    /// One Config1 key changed. The transport has ALREADY re-read the value
    /// into its snapshot cache when this arrives (see `configSnapshot()`), so
    /// a consumer reached from here reads the new value, never the old one.
    virtual void onConfigChanged(const QString& key) = 0;
};

/// Implemented by AgentReader/AgentCard: live property updates for one
/// subscribed object. `onPropertiesChanged` delivers the transport's changed
/// subset (+ the keys it declared stale without values); `onPropertiesFetched`
/// answers ONE requestProperties() call, identified by its token (nullopt =
/// the fetch failed/timed out — keep cached values).
class PropertyListener
{
public:
    virtual ~PropertyListener() = default;
    virtual void onPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated) = 0;
    virtual void onPropertiesFetched(quint64 token, const std::optional<QVariantMap>& properties) = 0;
};

/// Implemented by AgentOperation: one operation's live signals, scrubbed.
class OperationListener
{
public:
    virtual ~OperationListener() = default;
    virtual void onPhaseChanged(OperationPhase phase, double progress) = 0;
    virtual void onFinished(OperationStatus status, ErrorCode errorCode, const QString& msgKey,
                            const QString& msgFallback) = 0;
    virtual void onResult(OperationPayload payload) = 0;
    /// Progressive delivery: fired zero or more times, in order, strictly
    /// BEFORE onResult/onFinished for the SAME operation -- a hint only, never
    /// a substitute for onResult's own eventual complete payload. Only ever
    /// dispatched for an Identity-kind operation (a transport wires this from
    /// the D-Bus Operation.Identity1.Group signal / the socket
    /// "OpIdentityGroup" event, both Identity1-specific); every other kind
    /// simply never calls it. No recovery pull exists for a group missed
    /// before this listener subscribed -- see AgentOperation::identityResult()'s
    /// doc comment for the accumulation contract this implies.
    virtual void onGroupReady(const FieldGroup& group) = 0;
};

/// The transport seam proper. One instance per AgentClient, owned by it.
///
/// Lifetime rules the implementations rely on: listeners outlive their
/// subscription (the subscriber unsubscribes from its dtor BEFORE dying), and
/// after unsubscribe*/listener teardown NO further callback for that listener
/// may be delivered — including the reply of a requestProperties() still in
/// flight.
class TransportSeam
{
public:
    virtual ~TransportSeam() = default;

    TransportSeam(const TransportSeam&) = delete;
    TransportSeam& operator=(const TransportSeam&) = delete;

    // ---- availability -----------------------------------------------------
    /// Register the single registry listener (nullptr to clear).
    virtual void setRegistryListener(RegistryListener* listener) = 0;
    /// Bounded liveness probe: is the agent reachable right now?
    [[nodiscard]] virtual bool probeAvailability() = 0;
    /// Bounded install probe: is an agent present on this system (reachable
    /// now, or startable on demand)?
    [[nodiscard]] virtual bool agentInstalled() = 0;

    // ---- registry ----------------------------------------------------------
    /// Bounded discovery snapshot; nullopt when discovery failed (wedged or
    /// absent agent) so the caller can RECONCILE instead of rebuilding.
    [[nodiscard]] virtual std::optional<RegistrySnapshot> fetchRegistry() = 0;

    // ---- feature discovery ---------------------------------------------------
    /// The optional request/property families the agent advertises — the
    /// single-sourced `LibreSCRS::Agent::kAgentFeatures` vocabulary
    /// (FeatureTokens.h), served verbatim as D-Bus `Manager1.Features` (a
    /// `const` property) or socket `HelloAck.features`. Refreshed once per
    /// connect (D-Bus: the first probe/registration after the service
    /// becomes reachable; socket: the handshake) and cached until the agent
    /// is lost. An agent predating this surface (no `Manager1.Features`
    /// property at all, or — pre-Hello-vocabulary — nothing) answers
    /// gracefully with an EMPTY list here, never an error: absence is a
    /// normal, expected state, not a fault.
    [[nodiscard]] virtual QStringList features() const = 0;

    /// The connected agent's version string, captured on the SAME
    /// once-per-connect exchange that primes `features()` above — served as
    /// D-Bus `Manager1.Version` (a property read folded into the Features
    /// fetch) or socket `HelloAck.agentVer` (retained from the handshake) —
    /// and forgotten when the agent is lost, so a dead connection's version
    /// is never handed out for a live one. Identical graceful-degrade
    /// posture to `features()`: an unreachable agent, or one predating the
    /// surface, answers with an EMPTY string, never an error.
    [[nodiscard]] virtual QString agentVersion() const = 0;

    // ---- agent configuration (Config1) ---------------------------------------
    /// The agent's Config1 property set in the canonical client vocabulary
    /// (see `AgentClient::configSnapshot()` for the key/value contract this
    /// forwards verbatim, including the two fixed-width source rows every
    /// implementation must produce out of its own wire shape: TslSources'
    /// `[url, isLotl, eager]` and CscaSources' `[uri, eager]`).
    ///
    /// NOT const, unlike `features()`/`agentVersion()` above, and for the
    /// same reason `appearanceFont()` is not: this one is fetched LAZILY, on
    /// first use, so a consumer that never reads settings never pays a
    /// round-trip for them — the discovery-path pair are primed eagerly
    /// because availability handling needs them regardless. Cached
    /// afterwards, refreshed before each `onConfigChanged` announcement, and
    /// forgotten when the agent is lost: an unreachable agent answers EMPTY,
    /// never an error, exactly like the two above.
    [[nodiscard]] virtual QVariantMap configSnapshot() = 0;
    /// Write one setting; disengaged on success, else the NAMED refusal.
    /// A failure the client never got an answer to — unreachable agent,
    /// capped-call timeout, no reply — is `SyncError::CommunicationError`,
    /// so a caller can tell "the agent refused" from "the write never
    /// arrived" without a second axis.
    ///
    /// WHERE the refusal is decided is an implementation's own business: a
    /// transport whose grammar cannot even express the request refuses
    /// locally, one that can sends it and reports the agent's name. What is
    /// NOT negotiable is the enumerator — the same key must produce the same
    /// answer on every transport (the parity corpus asserts exactly this).
    [[nodiscard]] virtual std::optional<SyncError> setConfig(const QString& key, const QVariant& value) = 0;
    /// Restore one setting to the agent's built-in default; same contract.
    [[nodiscard]] virtual std::optional<SyncError> resetConfig(const QString& key) = 0;

    /// Install country-signing trust anchors from a signed ICAO master list
    /// (`Config1.ImportCscaMasterList` / socket `ImportCscaMasterList`);
    /// the accepted anchor state on success, else the NAMED refusal.
    ///
    /// @p masterListFd is BORROWED, never owned: an implementation duplicates
    /// it for the wire (D-Bus UNIX_FDS / socket SCM_RIGHTS) and never closes
    /// the caller's descriptor. It is a descriptor and not a path on purpose —
    /// the agent is a separate, possibly sandboxed process, so a name it would
    /// have to re-open is a name it may not be able to open, and would be a
    /// second resolution of a file the caller already resolved. One consequence
    /// is worth knowing before writing a test: the descriptor that crosses the
    /// wire shares ONE open file description with the caller's, so the agent's
    /// read advances the CALLER's file position.
    ///
    /// A failure the client never got an answer to — unreachable agent,
    /// capped-call timeout, no reply — is `SyncError::CommunicationError`,
    /// exactly like `setConfig` above.
    [[nodiscard]] virtual std::expected<CscaAnchorState, SyncError> importCscaMasterList(int masterListFd) = 0;

    // ---- Visual-signature layout preview ---------------------------------
    /// Bounded synchronous layout call (Manager1.LayoutVisualSignature /
    /// socket "LayoutVisual") — card-independent, pure CPU: no card, no
    /// Operation. nullopt on any call failure (agent unreachable, timeout,
    /// protocol error) OR an entry rejection (invalid geometry). The
    /// "layout-preview" feature gate is enforced by the CALLER
    /// (AgentClient), not here — a transport never refuses locally.
    [[nodiscard]] virtual std::optional<LayoutResult> layoutVisualSignature(const QString& text, QRectF box) = 0;
    /// The embedded appearance font (Liberation Sans Regular TTF), cached per
    /// connection (Manager1.GetAppearanceFont / socket "GetAppearanceFont").
    /// Fetched at most once per connect; invalidated on reconnect. An invalid
    /// `FdHandle` (see `FdHandle::valid()`) means the fetch failed or has not
    /// succeeded yet — never an error return, mirroring `features()`'s own
    /// graceful-degrade posture.
    [[nodiscard]] virtual FdHandle appearanceFont() = 0;

    // ---- per-object property tracking ---------------------------------------
    virtual void subscribeProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener) = 0;
    virtual void unsubscribeProperties(const QString& objectId, PropertyListener* listener) = 0;
    /// Asynchronous full-property fetch (the invalidated-property fallback).
    /// Returns a nonzero token; the reply arrives via onPropertiesFetched on
    /// the listener IF it is still subscribed for @p objectId when the reply
    /// lands (a dead subscription silently drops the reply).
    virtual quint64 requestProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener) = 0;

    // ---- operations ---------------------------------------------------------
    /// Bounded synchronous method-entry call. Method entry replies immediately
    /// in the agent design — it mints the operation and returns its id; the
    /// long card work happens on that operation and arrives via its signals.
    [[nodiscard]] virtual StartOutcome startOperation(const QString& cardId, OperationRequest request) = 0;
    /// Install the operation's signal subscriptions (terminal + progress +
    /// typed result), in an order that guarantees a result arriving after this
    /// call cannot be missed.
    virtual void subscribeOperation(const QString& operationId, OperationKind kind, OperationListener* listener) = 0;
    virtual void unsubscribeOperation(const QString& operationId, OperationListener* listener) = 0;
    /// Bounded synchronous read of the terminal triple (lost-Finished
    /// recovery); nullopt when the read failed (the live signal drives us).
    [[nodiscard]] virtual std::optional<TerminalSnapshot> fetchOperationState(const QString& operationId) = 0;
    /// Bounded synchronous re-pull of the retained typed payload
    /// (lost-Result recovery); nullopt when the agent has none (grace window
    /// elapsed, no-result, or an agent without the recovery method).
    [[nodiscard]] virtual std::optional<OperationPayload> fetchOperationResult(const QString& operationId,
                                                                               OperationKind kind) = 0;
    /// Fire-and-forget cancellation request. Never blocks.
    virtual void cancelOperation(const QString& operationId) = 0;

    // ---- best-effort cache warm --------------------------------------------
    /// Best-effort certificate pre-read for @p cardId: ask the agent to do the
    /// card I/O NOW, so a later real read finds it warm.
    ///
    /// Returns IMMEDIATELY, and that is the whole reason this verb exists
    /// beside `startOperation`. `startOperation`'s contract is to hand the
    /// minted operation back synchronously, so it is allowed one bounded
    /// block; a warm has no consumer for the operation at all, so it must not
    /// wait for the entry reply — a slow or wedged agent would otherwise stall
    /// the caller's thread, which for the GUI consumers of this library is the
    /// thread painting the shell.
    ///
    /// Nothing consumer-visible is minted: no operation id is returned, no
    /// operation object is created, and there is deliberately nothing to
    /// subscribe to, poll or cancel. Every failure — unreachable agent, entry
    /// refusal, a card that has no certificates to read — is silently dropped.
    /// A warm that did not happen simply leaves the next real read to pay its
    /// own cold cost, so "best effort" is the whole contract.
    ///
    /// Debounce: a warm issued while one is still in flight for the SAME
    /// @p cardId is a no-op. Implementations own that guard, because only the
    /// transport knows when its own entry call completed — the callers this
    /// replaces used to hold a pending-call handle for exactly this purpose
    /// and a void-returning API takes that handle away from them.
    ///
    /// A transport MAY implement this as a no-op when its wire cannot express
    /// a fire-and-forget method entry without stranding agent-side state that
    /// nothing will ever release. That is a documented, tested choice, not an
    /// omission: see the socket transport's implementation, which is the one
    /// such case today and carries the reasoning.
    virtual void warmCertificates(const QString& cardId) = 0;

    // ---- public-data primitive ----------------------------------------------
    /// Asynchronous DER fetch (the agent's no-consent public-data call),
    /// reader-addressed. @p listener receives exactly one
    /// onCertificateDer(token, outcome) IF still registered when the reply
    /// lands; returns a nonzero token. Implementations MUST track the
    /// registration by this token, never by listener identity alone: a
    /// cancelled operation's Private and a freshly minted one can share the
    /// same heap address, and an identity-keyed registry would let the
    /// cancelled operation's late/stale reply silently unregister — and thus
    /// permanently drop — the new operation's delivery.
    class DerListener
    {
    public:
        virtual ~DerListener() = default;
        virtual void onCertificateDer(quint64 token, DerOutcome outcome) = 0;
    };
    virtual quint64 requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener) = 0;
    /// Cancel path: drop @p token's registration. Keyed by @p token (NOT by
    /// @p listener identity) for the same reason requestCertificateDer's
    /// delivery is — @p listener is passed through only for an
    /// implementation's own defense-in-depth sanity check.
    virtual void cancelCertificateDer(quint64 token, DerListener* listener) = 0;

protected:
    TransportSeam() = default;
};

} // namespace LibreSCRS::AgentClient
