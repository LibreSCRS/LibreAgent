// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// A scripted in-process agent peer on a temp AF_UNIX listening socket, for
// exercising the socket transport end-to-end: it speaks the real wire —
// requests decoded by the Wire server-role parseRequest, replies/events
// built by the Wire server-role encoders (makeReply/makeErrorReply/
// makeSignRecoveryReply/toCbor), so every byte it emits is canonical by
// construction — but is driven entirely by test scripting hooks, mirroring
// the D-Bus FakeAgent's scripting surface where the two wires overlap (one
// scenario description can drive both fakes).
//
// Threading: a plain QObject driven by QSocketNotifiers on whatever thread
// it lives on. The socket transport under test waits for replies with a
// blocking deadline poll (its documented anti-reentrancy discipline), so the
// suites host this fake on a worker thread with its own event loop — the
// same two-thread arrangement the D-Bus suites' Harness uses for the same
// reason — and marshal every scripting call onto that thread.

#include <LibreSCRS/Agent/wire/FrameReassembler.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <memory>
#include <optional>
#include <span>
#include <vector>

class QSocketNotifier;

namespace LibreSCRS::AgentClient::Fakes {

/// One scripted certificate a ReadCertificates operation returns.
struct FakeSocketCert
{
    QString certId;
    bool signingCapable = false;
    QString subjectCn;
    QString issuerCn;
    QString notBefore;
    QString notAfter;
    quint32 keyUsageBits = 0;
    QStringList extendedKeyUsageOids;
    QStringList chainSubjectCns;
    quint32 trustStatus = 255;
};

/// One scripted credential record a ListCredentials operation returns.
struct FakeSocketCredRecord
{
    QString id;
    QString label;
    QString kind = QStringLiteral("user");
    QString state = QStringLiteral("operational");
    bool canChange = true;
    std::optional<int> retriesLeft;
};

class FakeSocketAgent : public QObject
{
    Q_OBJECT
public:
    struct Config
    {
        QString socketPath; ///< REQUIRED — the temp path to bind.
        QString agentVersion = QStringLiteral("0.0-fake");
        /// HelloAck feature tokens; drop "credentials" to script an agent
        /// predating the credential request family.
        QStringList features = {QStringLiteral("credentials")};
        QString readerName = QStringLiteral("Fake");
        quint32 capabilities = 0;
        bool hasCard = true;
        QString preReadAuth = QStringLiteral("None"); ///< None | BacMrz | PaceCan
        int operationDelayMs = 5;                     ///< delay before an op fires its result/finished events
        quint32 finalStatus = 0;                      ///< 0 Ok / 1 Cancelled / 2 Error
        quint32 finalErrorCode = 0;
        bool raceResultBeforeReturn = false; ///< fire the op's events synchronously, right after op-started
        bool suppressResult = false;         ///< finish Ok WITHOUT the result event AND with nothing to recover
        bool signRecoverable = false;        ///< Sign: SUPPRESS the result event but serve GetSignResult (the
                                             ///< deterministic lost-result recovery window)
        bool failMethodEntry = false;        ///< card methods answer an err-info at entry (no op minted)
        LibreSCRS::Agent::Wire::SyncError entryError = LibreSCRS::Agent::Wire::SyncError::UnsupportedOnThisCard;
        bool credEntryError = false; ///< the id-bearing mutations answer the scripted err at entry
        LibreSCRS::Agent::Wire::SyncError credEntryErrorName = LibreSCRS::Agent::Wire::SyncError::UnknownCredential;
        bool wedgeGetState = false; ///< GetState never answers (models a wedged discovery)
        /// Answer GetState with the real reply IMMEDIATELY FOLLOWED by a
        /// non-canonical frame, written as ONE batch (a single send) so the
        /// client's one pump absorbs both frames together.
        bool nonCanonicalAfterStateReply = false;
        QByteArray photoBytes; ///< bytes the GetPhoto result memfd carries ("personal:photo")
        QByteArray signArtifactBytes = QByteArrayLiteral("FAKE-SOCKET-ARTIFACT");
        QByteArray certDerBytes;         ///< GetCertDer success bytes
        bool certDerKeyNotFound = false; ///< GetCertDer answers err KeyNotFound instead
        QList<FakeSocketCert> certScript;
        LibreSCRS::Agent::Wire::CredentialOutcome credOutcome = LibreSCRS::Agent::Wire::CredentialOutcome::Ok;
        bool credBlocked = false;
        std::optional<int> credRetriesLeft;
        QList<FakeSocketCredRecord> credRecords;
    };

    explicit FakeSocketAgent(Config config, QObject* parent = nullptr);
    ~FakeSocketAgent() override;

    [[nodiscard]] bool listening() const;
    [[nodiscard]] QString socketPath() const;
    [[nodiscard]] Config& config();

    /// Stop accepting AND unbind (unlink) the socket path — the agent is gone
    /// from this system until relisten().
    void stopListening();
    /// Re-bind + listen on the same path after stopListening().
    void relisten();
    /// Close every accepted connection (the agent process dying mid-session).
    void closeAllConnections();
    [[nodiscard]] int connectionCount() const;

    // ---- live scripting (event emission) ------------------------------------
    /// Insert/remove the card: CardAdded/CardRemoved plus the owning reader's
    /// PropertyChanged, mirroring the presence model's ordering.
    void setCardPresent(bool present);
    /// Change the card's capabilities and broadcast the PropertyChanged
    /// carrying the full new value.
    void emitCardCapabilitiesChanged(quint32 capabilities);
    void sendAgentQuiesced(quint32 reason);
    /// Broadcast one frame whose body is well-formed-length but NON-CANONICAL
    /// CBOR (a non-shortest-form integer) — must fail the client closed.
    void sendNonCanonicalFrame();

    // ---- captures -----------------------------------------------------------
    [[nodiscard]] int operationCount() const;
    [[nodiscard]] int cancelledOperationCount() const;
    [[nodiscard]] int getStateCount() const;
    [[nodiscard]] int listCredentialsCount() const;
    [[nodiscard]] int getSignResultCount() const;
    [[nodiscard]] QString lastSignCertId() const;
    [[nodiscard]] QByteArray lastSignInputBytes() const;
    [[nodiscard]] QVariantMap lastSignOptions() const;
    [[nodiscard]] QString lastCertDerReader() const;
    [[nodiscard]] QString lastCertDerCertId() const;

private:
    struct Connection
    {
        LibreSCRS::Agent::Wire::UniqueFd fd;
        std::unique_ptr<QSocketNotifier> notifier;
        std::unique_ptr<LibreSCRS::Agent::Wire::FrameReassembler> reassembler;
    };
    enum class OpKind : unsigned char { Identity, Photo, Certificates, Sign, Credentials };
    struct Op
    {
        quint64 id = 0;
        OpKind kind = OpKind::Identity;
        Connection* connection = nullptr;
        bool fired = false;
        bool withRecords = false;      ///< Credentials: listing (true) vs mutation (false)
        bool retainedArtifact = false; ///< Sign: GetSignResult may still serve the artifact
    };

    void onAcceptable();
    void onConnectionReadable(Connection* connection);
    void closeConnection(Connection* connection);
    [[nodiscard]] bool isLive(Connection* connection) const;
    void handleRequest(Connection* connection, LibreSCRS::Agent::Wire::RequestEnvelope&& envelope,
                       std::vector<LibreSCRS::Agent::Wire::UniqueFd>& fds);
    void sendCbor(Connection* connection, const LibreSCRS::Agent::Wire::CborValue& value,
                  std::span<const int> passFds = {});
    /// Write pre-framed bytes verbatim (several frames as ONE send batch).
    void sendRawBatch(Connection* connection, std::span<const std::uint8_t> bytes);
    void broadcastCbor(const LibreSCRS::Agent::Wire::CborValue& value);
    void sendEntryError(Connection* connection, quint64 req, LibreSCRS::Agent::Wire::SyncError error);
    /// Mint + schedule a scripted op; answers op-started on @p connection.
    void mintOperation(Connection* connection, quint64 req, OpKind kind, bool withRecords);
    void fireOperation(quint64 opId);
    [[nodiscard]] Op* findOperation(quint64 opId);
    [[nodiscard]] LibreSCRS::Agent::Wire::StateReply buildState() const;
    [[nodiscard]] LibreSCRS::Agent::Wire::CardState buildCardState() const;
    [[nodiscard]] LibreSCRS::Agent::Wire::ReaderState buildReaderState() const;
    [[nodiscard]] std::vector<LibreSCRS::Agent::Wire::CertInfo> buildCertList() const;
    [[nodiscard]] LibreSCRS::Agent::Wire::CredentialsResult buildCredentialsResult(bool withRecords) const;
    [[nodiscard]] LibreSCRS::Agent::Wire::SignMeta signMeta() const;

    Config m_config;
    LibreSCRS::Agent::Wire::UniqueFd m_listenFd;
    std::unique_ptr<QSocketNotifier> m_listenNotifier;
    std::vector<std::unique_ptr<Connection>> m_connections;
    std::vector<std::unique_ptr<Op>> m_operations;
    quint64 m_nextOpId = 0;
    int m_cancelledOps = 0;
    int m_getStateCalls = 0;
    int m_listCredentialsCalls = 0;
    int m_getSignResultCalls = 0;
    bool m_hasListing = false;
    QStringList m_listedIds;
    QString m_lastSignCertId;
    QByteArray m_lastSignInputBytes;
    QVariantMap m_lastSignOptions;
    QString m_lastCertDerReader;
    QString m_lastCertDerCertId;
};

} // namespace LibreSCRS::AgentClient::Fakes
