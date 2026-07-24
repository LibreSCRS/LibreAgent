// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The AF_UNIX + canonical-CBOR implementation of
// TransportSeam (the macOS transport, written portably and testable on any
// POSIX host): connect + Hello/HelloAck handshake, uint32-LE body-len +
// uint32-LE fd-count framing (Wire's Framing/FrameReassembler), request/reply
// correlation by the envelope's `req` id, SCM_RIGHTS fd passing in both
// directions (documents out, artifacts/photos in), and the wire's
// events-as-frames model mapped onto the seam's listener callbacks. Every
// wire type is scrubbed at this boundary exactly like the D-Bus transport
// scrubs QtDBus types: handles cross as opaque QString ids, fd indices as
// owning FdHandles, err-info as SeamError (the sync-error names re-use the
// D-Bus ErrorNameMap's short-name half — the two wires share that
// vocabulary).
//
// Dispatch discipline (the seam's single-threaded contract): the event pump
// is a QSocketNotifier on this object's thread. Bounded synchronous seam
// calls (handshake, GetState, method entry, GetSignResult) wait on the
// socket with a plain deadline poll — deliberately NOT a nested QEventLoop,
// mirroring the D-Bus transport's capped-Block choice for method entry: no
// foreign event may re-enter a consumer mid-call. Frames that arrive during
// such a wait (unsolicited events, replies to other requests) are never
// dispatched inline; they are queued and drained on the next event-loop
// turn, so every listener callback is delivered either from the thread's
// event loop or as the direct return value of the seam call that awaited it.
//
// Failure policy (documented here, exercised by the socket suites):
//   - connect refused / peer EOF / ECONNRESET / send failure -> the
//     connection is dropped and the in-flight call fails
//     CallError::AgentUnavailable; the registry listener sees
//     onServiceUnregistered (the availability push) on a LATER event-loop
//     turn, never from inside the failing call itself (a send can fail at
//     sync depth 0, from directly inside a consumer's seam call).
//   - a frame whose body decodes to neither a reply nor an event (malformed
//     or non-canonical CBOR), or a framing-level violation (oversize,
//     fd-count mismatch) -> FAIL CLOSED: the connection is dropped
//     (an agent emitting non-canonical bytes is outside the contract; the
//     CDDL's tolerance covers unknown map keys and unknown arms, never
//     malformed encoding) and an awaiting call fails
//     CallError::ProtocolError.
//   - an UNKNOWN reply arm / event (UnknownReply/UnknownEvent) is the
//     CDDL-sanctioned forward-compatibility escape: tolerated, the
//     connection survives; a call awaiting that reply fails
//     CallError::ProtocolError for itself alone.
//   - AgentQuiesced -> availability semantics: the agent quiesced card
//     access (sleep/lock/user-switch), so the seam reports
//     onServiceUnregistered (terminalizing in-flight operations exactly like
//     an agent death) while the connection stays open; the next
//     probeAvailability() issues a bounded GetState round-trip and reports
//     available again only once the agent answers (there is no resume event
//     on the wire).
//   - the HelloAck feature-token gate is enforced HERE: credential requests
//     (ListCredentials/ManagePin/ActivateSigningKey) against an agent that
//     did not advertise "credentials" are refused locally (mapped like the
//     agent's own NotSupported refusal) instead of being sent — an agent
//     predating that request family fails the unknown frame closed and drops
//     the whole connection, so the gate is mandatory, not advisory.
#include "../DerListenerRegistry.h"
#include "../TransportSeam.h"

#include <LibreSCRS/Agent/wire/ClientCodec.h>
#include <LibreSCRS/Agent/wire/FrameReassembler.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <QHash>
#include <QObject>
#include <QString>
#include <QStringList>

#include <deque>
#include <memory>
#include <optional>
#include <vector>

class QSocketNotifier;
class QTimer;

namespace LibreSCRS::AgentClient {

class SocketTransport : public QObject, public TransportSeam
{
    Q_OBJECT
public:
    /// Production: resolveAgentSocketPath() (env override, then the platform
    /// default). The connection is established lazily by the first
    /// probeAvailability() — the AgentClient ctor's probe — never eagerly.
    SocketTransport();
    /// Tests: an explicit socket path (the fake agent's temp path).
    explicit SocketTransport(QString socketPath);
    ~SocketTransport() override;

    // TransportSeam
    void setRegistryListener(RegistryListener* listener) override;
    [[nodiscard]] bool probeAvailability() override;
    [[nodiscard]] bool agentInstalled() override;
    [[nodiscard]] std::optional<RegistrySnapshot> fetchRegistry() override;
    void subscribeProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener) override;
    void unsubscribeProperties(const QString& objectId, PropertyListener* listener) override;
    quint64 requestProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener) override;
    [[nodiscard]] StartOutcome startOperation(const QString& cardId, OperationRequest request) override;
    void subscribeOperation(const QString& operationId, OperationKind kind, OperationListener* listener) override;
    void unsubscribeOperation(const QString& operationId, OperationListener* listener) override;
    [[nodiscard]] std::optional<TerminalSnapshot> fetchOperationState(const QString& operationId) override;
    [[nodiscard]] std::optional<OperationPayload> fetchOperationResult(const QString& operationId,
                                                                       OperationKind kind) override;
    void cancelOperation(const QString& operationId) override;
    quint64 requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener) override;
    void cancelCertificateDer(quint64 token, DerListener* listener) override;

    // ---- HelloAck capture (the socket wire's availability surface) ---------
    /// True while a handshaken connection is up (the socket analogue of the
    /// D-Bus name having an owner).
    [[nodiscard]] bool isConnected() const;
    /// The agent version the HelloAck carried (empty before the first
    /// successful handshake).
    [[nodiscard]] QString agentVersion() const;
    /// The optional request families the agent advertised.
    [[nodiscard]] QStringList agentFeatures() const;
    /// Feature-token membership test (the credentials gate reads this).
    [[nodiscard]] bool hasFeature(QLatin1StringView token) const;

private:
    // One live per-object property subscription (values only — the socket
    // wire carries full values in PropertyChanged, never an invalidation).
    struct PropertyWatch
    {
        QString objectId;
        ObjectKind kind = ObjectKind::Reader;
    };
    // One live operation subscription, keyed both ways (listener for
    // unsubscribe, numeric op id for event routing).
    struct OperationWatch
    {
        quint64 op = 0;
        OperationKind kind = OperationKind::Identity;
        OperationListener* listener = nullptr;
    };
    // An asynchronous GetState issued for requestProperties(): the reply is
    // reduced to the one object's property map.
    struct PendingProps
    {
        quint64 token = 0;
        QString objectId;
        ObjectKind kind = ObjectKind::Reader;
        PropertyListener* listener = nullptr;
        QTimer* timer = nullptr;
    };
    // An asynchronous GetCertDer: the reply resolves the DerListenerRegistry
    // token.
    struct PendingDer
    {
        quint64 token = 0;
        QTimer* timer = nullptr;
    };
    // The outcome of one bounded synchronous request/reply exchange.
    struct SyncResult
    {
        CallError failure = CallError::None; // None == a reply arrived
        LibreSCRS::Agent::Wire::ReplyVariant reply;
        std::vector<LibreSCRS::Agent::Wire::UniqueFd> fds;
    };
    // A frame (or connection-loss notice) whose dispatch was displaced onto
    // the next event-loop turn. A ConnectionLost item carries the DEAD
    // connection's generation stamp plus its in-flight async requests
    // (snapshotted at drop time): answering those with failure outcomes is
    // unconditional — no connection can ever answer them — while the
    // availability push is generation-guarded, so a reconnect completed
    // before the drain does not have its FRESH registry cleared by the stale
    // notice.
    struct DeferredItem
    {
        enum class Kind : unsigned char { Event, Reply, ConnectionLost };
        Kind kind = Kind::Event;
        LibreSCRS::Agent::Wire::DecodedEvent event{};
        LibreSCRS::Agent::Wire::DecodedReply reply{};
        std::vector<LibreSCRS::Agent::Wire::UniqueFd> fds;
        quint64 generation = 0; // ConnectionLost only
        QHash<quint64, PendingProps> lostProps;
        QHash<quint64, PendingDer> lostDer;
    };

    [[nodiscard]] bool connectAndHandshake();
    /// Tear down the connection. In-flight async requests are answered
    /// (failure outcomes) and the registry listener is told the agent is gone
    /// — ALWAYS deferred onto the event loop (queued), never delivered inline
    /// from the dropping call's stack: a drop can be discovered inside a
    /// consumer's own seam call (a failing send at sync depth 0 included),
    /// and an inline onServiceUnregistered would let the consumer tear down
    /// the registry — freeing the very object the call is running on.
    void dropConnection();
    void onReadable();
    /// Classify one inbound frame and either consume it (the awaited sync
    /// reply), queue it (mid-wait), or dispatch it (event-loop context).
    /// Returns false on a malformed/non-canonical body (fail closed).
    [[nodiscard]] bool absorbFrame(LibreSCRS::Agent::Wire::Frame&& frame, quint64 awaitedId, SyncResult* awaited);
    void scheduleDrain();
    void drainDeferred();
    void dispatchEvent(LibreSCRS::Agent::Wire::DecodedEvent&& event,
                       std::vector<LibreSCRS::Agent::Wire::UniqueFd>& fds);
    void dispatchAsyncReply(LibreSCRS::Agent::Wire::DecodedReply&& reply);
    void deliverConnectionLost(DeferredItem& item);
    /// Send one request and wait (deadline poll, no event loop) for its
    /// correlated reply.
    [[nodiscard]] SyncResult callSync(const LibreSCRS::Agent::Wire::RequestVariant& request, int timeoutMs,
                                      std::span<const int> passFds = {});
    [[nodiscard]] OperationListener* operationListenerFor(quint64 op, OperationKind* kindOut = nullptr) const;

    QString m_socketPath;
    LibreSCRS::Agent::Wire::UniqueFd m_fd;
    std::unique_ptr<QSocketNotifier> m_notifier;
    // Recreated per connection (the class is deliberately non-copyable and
    // non-movable — its buffers are connection state).
    std::unique_ptr<LibreSCRS::Agent::Wire::FrameReassembler> m_reassembler;
    bool m_established = false; // handshake completed on the current connection
    bool m_quiesced = false;    // an AgentQuiesced arrived; cleared by a successful re-probe
    QString m_agentVersion;
    QStringList m_features;

    RegistryListener* m_registry = nullptr;
    QHash<PropertyListener*, PropertyWatch> m_propertyWatches;
    QHash<OperationListener*, OperationWatch> m_operationWatches;
    DerListenerRegistry m_derListeners;
    QHash<quint64, PendingProps> m_pendingProps; // keyed by wire request id
    QHash<quint64, PendingDer> m_pendingDer;     // keyed by wire request id

    std::deque<DeferredItem> m_deferred;
    // Bumped on every completed handshake; deferred ConnectionLost notices
    // are stamped with it so a stale notice cannot be announced against a
    // connection established after the drop (see DeferredItem).
    quint64 m_generation = 0;
    int m_syncDepth = 0; // > 0 while a synchronous wait owns the socket
    bool m_draining = false;
    bool m_drainQueued = false;
    quint64 m_nextRequestId = 0;
    quint64 m_nextPropsToken = 0; // requestProperties only — DER tokens live in m_derListeners
};

} // namespace LibreSCRS::AgentClient
