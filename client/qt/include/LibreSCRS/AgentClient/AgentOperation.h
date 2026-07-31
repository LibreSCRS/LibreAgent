// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/CallError.h>
#include <LibreSCRS/AgentClient/CredentialTypes.h>
#include <LibreSCRS/AgentClient/ErrorCode.h>
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/OperationPhase.h>
#include <LibreSCRS/AgentClient/SignOptions.h>
#include <LibreSCRS/AgentClient/SyncError.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <memory>
#include <optional>
#include <vector>

/// @file
/// @brief Drives one agent operation and its typed result, handling the
///        Finished/Result race and the late-subscriber result recovery
///        contract behind a transport-neutral surface.

namespace LibreSCRS::AgentClient {

class AgentCard;
class AgentClient;
class TransportSeam;
struct SeamError;

/// @brief One in-flight (or finished) agent operation, minted by an
///        `AgentCard` method or by `AgentClient::certificateDer()`.
///
/// Lifecycle: the minting call returns immediately; progress arrives via
/// `phaseChanged` and the terminal outcome via `finished()`. After `finished()`
/// the polled state (`status()` / `errorCode()` / `callError()`) and the typed
/// result getter matching the minting method are valid. The operation is
/// QObject-parented to the object that minted it, so it never outlives its
/// card/client; consumers that finish with it early may delete it sooner.
///
/// The lifted behavior this preserves: results are settled BEFORE `finished()`
/// fires (a lost/raced one-shot result signal is recovered from the agent's
/// retained payload where the contract provides one, and an unrecoverable
/// lost result surfaces as a loud CommunicationError instead of masquerading
/// as a silent empty success).
///
/// @par Threading and connection-timing
/// All signals are delivered on the thread the minting `AgentCard`/`AgentClient`
/// lives on (the single-threaded transport contract; see `TransportSeam`) —
/// never from a foreign thread, so a direct connection on that thread never
/// races the polled state. `finished()` is guaranteed exactly once even when
/// the terminal outcome is already known at minting time (an entry-refused
/// call, or a hot operation that completed before this object finished
/// constructing): that early terminal is QUEUED to the event loop rather
/// than emitted from inside the constructor, specifically so a consumer that
/// connects to `finished()` right after receiving the minted pointer — never
/// having had a chance to connect earlier — still observes it. Once emitted
/// on the live/async path, it is synchronous and never re-queued.
class LIBRESCRS_AGENTCLIENT_EXPORT AgentOperation : public QObject
{
    Q_OBJECT
public:
    ~AgentOperation() override;

    AgentOperation(const AgentOperation&) = delete;
    AgentOperation& operator=(const AgentOperation&) = delete;

    /// @brief Request cancellation. Fire-and-forget: the terminal outcome
    ///        still arrives via `finished()` (normally with a Cancelled
    ///        status), never synchronously here.
    void cancel();

    /// @brief True once the terminal outcome was observed (or recovered).
    [[nodiscard]] bool isFinished() const;
    /// @brief Terminal status; valid after `finished()` (Error before). A
    ///        terminal status value this build does not recognise (a future
    ///        agent's outcome; OperationStatus is wire-frozen append-only) is
    ///        treated as Error rather than surfaced as an unnamed enumerator.
    [[nodiscard]] OperationStatus status() const;
    /// @brief Last observed phase (Created until the agent reports
    ///        progress). Holds its last known-good value if the agent
    ///        reports a phase this build does not recognise (OperationPhase
    ///        is wire-frozen append-only) — `progress()` still advances on
    ///        such a report, only the phase itself does not regress to the
    ///        unrecognised value.
    [[nodiscard]] OperationPhase phase() const;
    /// @brief Last observed progress in [0.0, 1.0] (0.0 until reported).
    [[nodiscard]] double progress() const;

    /// @brief The agent's wire-frozen error taxonomy value for a failed
    ///        operation; None on success or when the failure never produced a
    ///        wire-level answer (see `callError()`).
    [[nodiscard]] ErrorCode errorCode() const;
    /// @brief The client-side call classification when the operation failed
    ///        WITHOUT a wire-level answer (agent unreachable, timeout,
    ///        transport break, request rejected at entry); None otherwise.
    [[nodiscard]] CallError callError() const;
    /// @brief The refusal's own name in the wire's `sync-error` vocabulary,
    ///        when the failure had one; disengaged otherwise.
    ///
    /// Third axis, orthogonal to `errorCode()` and `callError()` — it never
    /// changes what either of those reports, it says which of the several names
    /// sharing one of their buckets this actually was. Two engaged values can
    /// carry the same `callError()`: `UnknownCredential` and `InvalidRequest`
    /// both report `CallError::InvalidArguments`, and a consumer whose recovery
    /// differs between them (re-list the stale ids versus surface a persistent
    /// card condition) can only tell them apart here.
    ///
    /// @par When it is engaged
    /// A method-entry refusal or a public-data fetch that the peer answered
    /// with a named error, on either transport. Also the small set of refusals
    /// this client decides locally in that SAME vocabulary so both transports
    /// converge on one outcome (an operation the agent does not advertise
    /// support for reports `NotSupported` without any wire exchange) — the
    /// value names the refusal, not its author.
    ///
    /// @par When it is disengaged
    /// Everything else, and the absence is informative rather than a gap:
    /// a transport-level failure (no agent, timeout, broken connection), a
    /// local refusal this client made without borrowing the vocabulary
    /// (caller-side argument validation), a terminal outcome of an operation
    /// that DID start — those report the numeric `errorCode()` taxonomy
    /// instead — and, of course, success. In particular an unreachable agent
    /// is `callError() == CallError::AgentUnavailable` with NO sync error:
    /// unavailability is a client-side observation and has never been a wire
    /// token.
    ///
    /// Disengaged too — and this is the case worth stating on its own, because
    /// the failure LOOKS like the agent answering — when the exchange itself is
    /// outside the wire contract: a reply that is not a reply, a reply with an
    /// empty body, a reply arm that does not answer this request. The client
    /// diagnosed those; the peer named nothing. They still report
    /// `ErrorCode::CommunicationError` or `CallError::ProtocolError` on the
    /// other two axes, so nothing about them is silent — but reading an engaged
    /// name there would attribute a local framing fault to the card, which is a
    /// different failure with a different recovery.
    ///
    /// The discriminator throughout is therefore WHO NAMED IT, not what went
    /// wrong: engaged means a name from this vocabulary was genuinely in play.
    ///
    /// @warning An engaged `SyncError::CommunicationError` does NOT prove the
    ///          peer named that error. `sync-error` is a text-token vocabulary
    ///          with no room to carry an unrecognised token forward, so a name
    ///          from a newer agent degrades to that value at decode time on
    ///          both transports (see `decodeSyncError()`'s own warning). Treat
    ///          it as "named, but not usefully" — never as a positive
    ///          identification.
    [[nodiscard]] std::optional<SyncError> syncError() const;
    /// @brief Agent-authored i18n message key for the terminal outcome, or
    ///        empty (recovered terminals carry no message — map `errorCode()`).
    [[nodiscard]] QString messageKey() const;
    /// @brief Agent-authored English fallback message, or empty.
    [[nodiscard]] QString messageFallback() const;

    /// @brief Identity payload of a `readIdentity()` operation; each Field
    ///        carries its wire metadata in `Field::extra` (see IdentityRows.h
    ///        for the canonical keys). Empty otherwise.
    ///
    /// @par Accumulation contract
    /// `identityResult()` is valid, complete, and authoritative once `finished()`
    /// has fired — regardless of how many (if any) `groupReady()` signals
    /// arrived first. Progressive groups delivered via `groupReady()` are
    /// hints only, for a consumer that wants to render incrementally; they
    /// are never accumulated into this getter and a group missed before a
    /// consumer connected has no separate recovery (unlike the terminal
    /// result itself, which the late-subscriber recovery pull always
    /// converges on — see the class documentation above). An agent that does
    /// not serve progressive delivery emits no `groupReady()` at all, and
    /// `identityResult()` is unaffected either way.
    [[nodiscard]] QList<FieldGroup> identityResult() const;
    /// @brief Certificate payload of a `readCertificates()` operation.
    [[nodiscard]] QList<CertificateInfo> certificatesResult() const;
    /// @brief Photo payload of a `getPhoto()` operation — move-only sealed-fd
    ///        items the caller must read and close promptly (the agent retains
    ///        no copy). First call takes ownership; later calls return empty.
    [[nodiscard]] std::vector<PhotoItem> takePhotos();
    /// @brief Signed artifact of a `sign()` operation — a move-only sealed fd
    ///        the caller must stream out and close promptly. First call takes
    ///        ownership; later calls return an invalid handle.
    [[nodiscard]] FdHandle takeSignedArtifact();
    /// @brief Signature metadata of a `sign()` operation (format/level/...).
    [[nodiscard]] QVariantMap signMeta() const;
    /// @brief Rows of a `signBatch()` operation — move-only, index-aligned
    ///        with the request's documents (see `BatchSignRow`'s own doc
    ///        comment for the failed-row representation: a valid, open,
    ///        possibly-zero-length `artifact` plus a non-`None` `error`).
    ///        First call takes ownership; later calls return an empty vector.
    [[nodiscard]] std::vector<BatchSignRow> takeBatchResults();
    /// @brief Mutation result of a `managePin()` / `activateSigningKey()`
    ///        attempt. Delivered for EVERY completed attempt — including the
    ///        soft-fail outcomes that finish Error — so `PinResult::outcome`
    ///        is meaningful even when `status()` is Error.
    [[nodiscard]] PinResult pinResult() const;
    /// @brief Records of a `listCredentials()` operation. Empty for a
    ///        mutation — an empty list is a legitimate result, not a missing
    ///        one.
    [[nodiscard]] CredentialList credentialsResult() const;
    /// @brief Raw DER of an `AgentClient::certificateDer()` operation.
    [[nodiscard]] QByteArray certificateDerResult() const;

Q_SIGNALS:
    /// @brief Progress report: the agent moved into @p phase, with @p progress
    ///        in [0.0, 1.0]. Zero or more emissions between minting and
    ///        `finished()`; not every operation kind visits every phase, and
    ///        an operation that fails fast may emit none at all.
    void phaseChanged(LibreSCRS::AgentClient::OperationPhase phase, double progress);
    /// @brief Progressive identity-field delivery: one field group became
    ///        available. Zero or more emissions, in order, strictly before
    ///        `finished()` — see `identityResult()`'s accumulation contract
    ///        for how this relates to the eventual complete result. Only
    ///        ever fires for a `readIdentity()` operation (mirrors LibreCelik's
    ///        existing `cardGroupReady`); every other operation kind emits it
    ///        never.
    void groupReady(const LibreSCRS::AgentClient::FieldGroup& group);
    /// @brief The single terminal notification; fires exactly once, ever,
    ///        for this operation. `status()` / `errorCode()` / `callError()`
    ///        / `messageKey()` / `messageFallback()` and the typed result
    ///        getter matching the minting method are ALL settled before this
    ///        signal is emitted — a slot connected directly may read them
    ///        synchronously inside the slot with no further synchronization.
    ///        See the class documentation for the connection-timing
    ///        guarantee on an operation that was already terminal when
    ///        minted, and for the lost-result recovery this fires after.
    void finished();

private:
    friend class AgentCard;   // mints card operations; entry-refusal terminals
    friend class AgentClient; // mints DER operations; agent-vanish/card-removed sweeps

    /// Internal operation kind — which typed result this operation binds.
    enum class Kind : unsigned char { Identity, Photo, Certificates, Sign, Credentials, CertificateDer, BatchSign };

    /// Transport-backed ctor: subscribes to the operation's signals and runs
    /// the lost-Finished recovery before returning.
    AgentOperation(TransportSeam* transport, const QString& operationId, Kind kind, QObject* parent);
    /// Local ctor (no agent-side operation object): an entry-refused call or a
    /// client-driven fetch (certificateDer). Starts unfinished and untracked.
    AgentOperation(Kind kind, QObject* parent);

    /// @brief Force a terminal outcome WITHOUT touching the transport, firing
    ///        `finished` once if it has not already fired. The AgentClient
    ///        calls this on every live operation when the agent vanishes or
    ///        the card is removed mid-flight — no terminal signal will ever
    ///        arrive, so without this sweep the consumer would hang forever.
    ///        Idempotent (a no-op once finished).
    void terminate(OperationStatus terminalStatus, ErrorCode code, CallError call, const QString& msgKey,
                   const QString& msgFallback);
    /// @brief Apply an entry-refusal / local-call failure as the terminal
    ///        outcome, QUEUING the `finished` emit so a consumer connecting
    ///        right after the minting call still receives it.
    void failEntry(const SeamError& error);
    /// @brief Issue the asynchronous DER fetch this operation reports on.
    void startCertificateDer(TransportSeam* transport, const QString& readerId, const QString& certId);

    /// @brief Resolve a terminal (status, errorCode) into the public
    ///        `finished()`. On a terminal with no result yet seen: recovers
    ///        the typed payload via the transport's recovery pull, or — when
    ///        the pull yields nothing usable — surfaces a loud
    ///        CommunicationError so a lost/late result never masquerades as a
    ///        silent empty success.
    void finalizeTerminal(OperationStatus terminalStatus, ErrorCode code, const QString& msgKey,
                          const QString& msgFallback);
    /// @brief The single writer of the terminal state. @p sync is the named
    ///        wire error `syncError()` will report — disengaged on every route
    ///        that had no wire name to carry (a terminal on an operation that
    ///        already started, the agent-loss/card-removal sweeps, a successful
    ///        public-data fetch), engaged only where a classified `SeamError`
    ///        brought one in.
    void emitFinishedOnce(OperationStatus terminalStatus, ErrorCode code, CallError call, std::optional<SyncError> sync,
                          const QString& msgKey, const QString& msgFallback);
    void recoverIfAlreadyFinished();

    struct Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
