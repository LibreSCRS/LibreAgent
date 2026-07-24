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
#include <LibreSCRS/AgentClient/Types.h>

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariantMap>

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
struct SeamError
{
    CallError callError = CallError::None;
    ErrorCode errorCode = ErrorCode::None;
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
/// "Reader"), with every object reference already flattened to an opaque
/// QString id.
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
enum class OperationKind : unsigned char { Identity, Photo, Certificates, Sign, Credentials };

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
        Sign,
        ListCredentials,
        ManagePin,
        ActivateSigningKey,
    };

    Method method = Method::ReadIdentity;
    QString certId;      ///< Sign only.
    FdHandle document;   ///< Sign only — the document to sign, passed by fd.
    QString pinId;       ///< ManagePin only.
    QString verb;        ///< ManagePin only — the wire verb token.
    QVariantMap options; ///< Sign/ManagePin — wire-keyed option map.
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
    PinResult pinResult;
    CredentialList credentials;
};

/// Outcome of the asynchronous DER fetch.
struct DerOutcome
{
    QByteArray der;
    SeamError error;
};

/// Implemented by AgentClient: agent liveness + registry add/remove. A live
/// object-added notification for one discovery event delivers the CARD before
/// the READER (the lifted ordering — a reader's card reference must resolve
/// immediately).
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
