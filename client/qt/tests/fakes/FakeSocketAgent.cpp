// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "FakeSocketAgent.h"

#include "ConfigKeys.h"         // the Config1 key vocabulary + the canonical TslSources row shape
#include "dbus/AgentDBus.h"     // the shared object/interface name spellings (constants only)
#include "socket/MemfdSource.h" // memfd document/artifact source + readFdAll (Linux test helper)

#include <LibreSCRS/Agent/wire/Framing.h>

#include <QFile>
#include <QSocketNotifier>
#include <QTimer>
#include <QVariant>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

namespace LibreSCRS::AgentClient::Fakes {

namespace Wire = LibreSCRS::Agent::Wire;

namespace {

constexpr const char* kReaderHandle = "reader/0";
constexpr const char* kCardHandle = "card/0";

Wire::PreReadAuth preAuthFromToken(const QString& token)
{
    if (token == QLatin1String("Mrz")) {
        return Wire::PreReadAuth::Mrz;
    }
    if (token == QLatin1String("Can")) {
        return Wire::PreReadAuth::Can;
    }
    return Wire::PreReadAuth::None;
}

/// One scripted config value -> the CBOR the `config` reply arm carries.
/// `TslSources` is the interesting one: the socket grammar types every config
/// value as bare `any` (unlike D-Bus's declared `a(sbb)`), so this fake can —
/// and, under Config::tslSourcesAsMaps, does — serve the SAME rows in two
/// lawful encodings, which is what makes the client's normalization a real
/// claim rather than a pass-through.
Wire::CborValue configValueToCbor(const QString& key, const QVariant& value, bool tslSourcesAsMaps)
{
    if (key == kConfigTslSources) {
        Wire::CborValue::Array rows;
        for (const QVariant& row : value.toList()) {
            const QVariantList cells = row.toList();
            if (cells.size() != 3) {
                continue;
            }
            const std::string url = cells.at(0).toString().toStdString();
            const bool isLotl = cells.at(1).toBool();
            const bool eager = cells.at(2).toBool();
            if (tslSourcesAsMaps) {
                Wire::CborValue::Map entry;
                entry.emplace("url", Wire::CborValue(url));
                entry.emplace("lotl", Wire::CborValue(isLotl));
                entry.emplace("eager", Wire::CborValue(eager));
                rows.push_back(Wire::CborValue(std::move(entry)));
                continue;
            }
            rows.push_back(Wire::CborValue(
                Wire::CborValue::Array{Wire::CborValue(url), Wire::CborValue(isLotl), Wire::CborValue(eager)}));
        }
        return Wire::CborValue(std::move(rows));
    }
    if (value.metaType().id() == QMetaType::QStringList) {
        Wire::CborValue::Array items;
        for (const QString& item : value.toStringList()) {
            items.push_back(Wire::CborValue(item.toStdString()));
        }
        return Wire::CborValue(std::move(items));
    }
    return Wire::CborValue(value.toString().toStdString());
}

/// The inverse, for SetConfig: the wire's `any` value back into the canonical
/// client-side shape this fake stores and later re-serves.
QVariant cborConfigValueToVariant(const QString& key, const Wire::CborValue& value)
{
    if (key == kConfigTslSources) {
        QVariantList rows;
        if (const auto* array = value.asArray()) {
            for (const Wire::CborValue& row : *array) {
                const auto* cells = row.asArray();
                if (cells == nullptr || cells->size() != 3) {
                    continue;
                }
                const std::string* url = (*cells)[0].asText();
                rows.append(tslSourceRow(url != nullptr ? QString::fromStdString(*url) : QString(),
                                         (*cells)[1].asBool().value_or(false), (*cells)[2].asBool().value_or(false)));
            }
        }
        return rows;
    }
    if (const auto* array = value.asArray()) {
        QStringList items;
        for (const Wire::CborValue& item : *array) {
            if (const std::string* text = item.asText()) {
                items.append(QString::fromStdString(*text));
            }
        }
        return items;
    }
    const std::string* text = value.asText();
    return text != nullptr ? QString::fromStdString(*text) : QString();
}

void setNonBlockingCloexec(int fd)
{
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Wire::SignOpts -> the seam's wire-keyed option QVariantMap. Shared by Sign
// and SignBatch (the two entry points carry the IDENTICAL sign-opts
// vocabulary), so the two request handlers below never drift apart.
QVariantMap signOptsToMap(const Wire::SignOpts& opts)
{
    QVariantMap options;
    options.insert(QStringLiteral("format"), QString::fromStdString(opts.format));
    options.insert(QStringLiteral("level"), QString::fromStdString(opts.level));
    options.insert(QStringLiteral("packaging"), QString::fromStdString(opts.packaging));
    if (opts.allowExpired) {
        options.insert(QStringLiteral("allowExpired"), *opts.allowExpired);
    }
    if (opts.displayName) {
        options.insert(QStringLiteral("displayName"), QString::fromStdString(*opts.displayName));
    }
    if (opts.reason) {
        options.insert(QStringLiteral("reason"), QString::fromStdString(*opts.reason));
    }
    if (opts.location) {
        options.insert(QStringLiteral("location"), QString::fromStdString(*opts.location));
    }
    if (opts.tsaUrl) {
        options.insert(QStringLiteral("tsaUrl"), QString::fromStdString(*opts.tsaUrl));
    }
    if (opts.visualSignature) {
        const auto& v = *opts.visualSignature;
        QVariantMap visual;
        visual.insert(QStringLiteral("page"), static_cast<qulonglong>(v.page));
        visual.insert(QStringLiteral("x"), v.x);
        visual.insert(QStringLiteral("y"), v.y);
        visual.insert(QStringLiteral("width"), v.width);
        visual.insert(QStringLiteral("height"), v.height);
        visual.insert(QStringLiteral("text"), QString::fromStdString(v.text));
        options.insert(QStringLiteral("visualSignature"), visual);
    }
    return options;
}

} // namespace

FakeSocketAgent::FakeSocketAgent(Config config, QObject* parent)
    : QObject(parent), m_config(std::move(config)), m_configDefaults(m_config.config)
{
    relisten();
}

FakeSocketAgent::~FakeSocketAgent()
{
    stopListening();
}

bool FakeSocketAgent::listening() const
{
    return m_listenFd.valid();
}

QString FakeSocketAgent::socketPath() const
{
    return m_config.socketPath;
}

FakeSocketAgent::Config& FakeSocketAgent::config()
{
    return m_config;
}

void FakeSocketAgent::stopListening()
{
    m_listenNotifier.reset();
    m_listenFd.reset();
    if (!m_config.socketPath.isEmpty()) {
        ::unlink(QFile::encodeName(m_config.socketPath).constData());
    }
}

void FakeSocketAgent::relisten()
{
    stopListening();
    const QByteArray encoded = QFile::encodeName(m_config.socketPath);
    sockaddr_un address{};
    if (encoded.isEmpty() || static_cast<std::size_t>(encoded.size()) + 1 > sizeof(address.sun_path)) {
        return;
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, encoded.constData(), static_cast<std::size_t>(encoded.size()));

    Wire::UniqueFd fd(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (!fd.valid()) {
        return;
    }
    setNonBlockingCloexec(fd.get());
    ::unlink(encoded.constData());
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(fd.get(), 4) != 0) {
        return;
    }
    m_listenFd = std::move(fd);
    m_listenNotifier = std::make_unique<QSocketNotifier>(m_listenFd.get(), QSocketNotifier::Read);
    connect(m_listenNotifier.get(), &QSocketNotifier::activated, this, [this]() { onAcceptable(); });
}

void FakeSocketAgent::closeAllConnections()
{
    for (const auto& op : m_operations) {
        op->connection = nullptr;
    }
    m_connections.clear();
}

int FakeSocketAgent::connectionCount() const
{
    return static_cast<int>(m_connections.size());
}

void FakeSocketAgent::onAcceptable()
{
    while (true) {
        const int fd = ::accept(m_listenFd.get(), nullptr, nullptr);
        if (fd < 0) {
            return; // EAGAIN — drained
        }
        setNonBlockingCloexec(fd);
        auto connection = std::make_unique<Connection>();
        connection->fd = Wire::UniqueFd(fd);
        connection->reassembler = std::make_unique<Wire::FrameReassembler>();
        connection->notifier = std::make_unique<QSocketNotifier>(fd, QSocketNotifier::Read);
        Connection* raw = connection.get();
        connect(connection->notifier.get(), &QSocketNotifier::activated, this,
                [this, raw]() { onConnectionReadable(raw); });
        m_connections.push_back(std::move(connection));
    }
}

bool FakeSocketAgent::isLive(Connection* connection) const
{
    if (connection == nullptr) {
        return false;
    }
    for (const auto& candidate : m_connections) {
        if (candidate.get() == connection) {
            return true;
        }
    }
    return false;
}

void FakeSocketAgent::closeConnection(Connection* connection)
{
    for (const auto& op : m_operations) {
        if (op->connection == connection) {
            op->connection = nullptr;
        }
    }
    for (auto it = m_connections.begin(); it != m_connections.end(); ++it) {
        if (it->get() == connection) {
            // May run from inside this notifier's own activated handler —
            // never delete a signal's sender mid-emission.
            if (connection->notifier != nullptr) {
                connection->notifier->setEnabled(false);
                connection->notifier.release()->deleteLater();
            }
            m_connections.erase(it);
            return;
        }
    }
}

void FakeSocketAgent::onConnectionReadable(Connection* connection)
{
    if (!isLive(connection)) {
        return;
    }
    Wire::PumpResult pumped = connection->reassembler->pump(connection->fd.get());
    for (Wire::Frame& frame : pumped.frames) {
        if (!isLive(connection)) {
            return; // a handler closed it mid-batch
        }
        auto envelope = Wire::parseRequest(frame.body);
        if (!envelope) {
            closeConnection(connection); // the agent fails malformed requests closed
            return;
        }
        handleRequest(connection, std::move(*envelope), frame.fds);
    }
    if (pumped.status != Wire::PumpStatus::Ok && isLive(connection)) {
        closeConnection(connection);
    }
}

void FakeSocketAgent::sendCbor(Connection* connection, const Wire::CborValue& value, std::span<const int> passFds)
{
    if (!isLive(connection)) {
        return;
    }
    const std::vector<std::uint8_t> body = value.encode();
    if (!Wire::sendFrame(connection->fd.get(), body, passFds)) {
        closeConnection(connection);
    }
}

void FakeSocketAgent::sendRawBatch(Connection* connection, std::span<const std::uint8_t> bytes)
{
    if (!isLive(connection)) {
        return;
    }
#ifdef MSG_NOSIGNAL
    constexpr int kFlags = MSG_NOSIGNAL;
#else
    constexpr int kFlags = 0;
#endif
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const ssize_t w = ::send(connection->fd.get(), bytes.data() + sent, bytes.size() - sent, kFlags);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            closeConnection(connection);
            return;
        }
        sent += static_cast<std::size_t>(w);
    }
}

void FakeSocketAgent::broadcastCbor(const Wire::CborValue& value)
{
    // Snapshot: a failed send closes (erases) the connection mid-loop.
    std::vector<Connection*> targets;
    targets.reserve(m_connections.size());
    for (const auto& connection : m_connections) {
        targets.push_back(connection.get());
    }
    for (Connection* connection : targets) {
        sendCbor(connection, value);
    }
}

void FakeSocketAgent::sendEntryError(Connection* connection, quint64 req, Wire::SyncError error)
{
    Wire::ErrInfo info;
    info.code = error;
    info.msgFallback = std::string("scripted method-entry refusal");
    sendCbor(connection, Wire::makeErrorReply(req, info));
}

// ---- state ------------------------------------------------------------------------

Wire::ReaderState FakeSocketAgent::buildReaderState() const
{
    Wire::ReaderState reader;
    reader.handle = kReaderHandle;
    reader.name = m_config.readerName.toStdString();
    reader.hasCard = m_config.hasCard;
    if (m_config.hasCard) {
        reader.card = std::string(kCardHandle);
    }
    return reader;
}

Wire::CardState FakeSocketAgent::buildCardState() const
{
    Wire::CardState card;
    card.handle = kCardHandle;
    card.reader = kReaderHandle;
    card.caps = m_config.capabilities;
    card.preAuth = preAuthFromToken(m_config.preReadAuth);
    // Optional keys: encoded only when scripted non-empty, mirroring the real
    // agent's empty-until-known / always-known-from-insertion semantics.
    if (!m_config.cardType.isEmpty()) {
        card.cardType = m_config.cardType.toStdString();
    }
    if (!m_config.atrHex.isEmpty()) {
        card.atr = m_config.atrHex.toStdString();
    }
    return card;
}

Wire::StateReply FakeSocketAgent::buildState() const
{
    Wire::StateReply state;
    state.readers.push_back(buildReaderState());
    if (m_config.hasCard) {
        state.cards.push_back(buildCardState());
    }
    return state;
}

Wire::SignMeta FakeSocketAgent::signMeta() const
{
    if (m_config.signMetaOverride) {
        return *m_config.signMetaOverride;
    }
    // Fixed meta script, mirroring the D-Bus fake's fixed Sign meta.
    return Wire::SignMeta{"pades", "b-lta", true, true};
}

std::vector<Wire::CertInfo> FakeSocketAgent::buildCertList() const
{
    std::vector<Wire::CertInfo> certs;
    certs.reserve(static_cast<std::size_t>(m_config.certScript.size()));
    for (const FakeSocketCert& scripted : m_config.certScript) {
        Wire::CertInfo cert;
        cert.certId = scripted.certId.toStdString();
        cert.signingCapable = scripted.signingCapable;
        // The scripted groups go in FIRST, so the four derived cells below
        // overlay rather than are overlaid -- the D-Bus fake's operator<<
        // orders the same two writes the same way.
        for (auto g = scripted.extraFields.constBegin(); g != scripted.extraFields.constEnd(); ++g) {
            for (auto f = g->constBegin(); f != g->constEnd(); ++f) {
                cert.fields[g.key().toStdString()][f.key().toStdString()] =
                    Wire::CertField{f->labelKey.toStdString(), f->labelFallback.toStdString(), f->value.toStdString()};
            }
        }
        if (!scripted.subjectCn.isEmpty()) {
            cert.fields["subject"]["cn"] =
                Wire::CertField{"label_subject_cn", "Subject CN", scripted.subjectCn.toStdString()};
        }
        if (!scripted.issuerCn.isEmpty()) {
            cert.fields["issuer"]["cn"] =
                Wire::CertField{"label_issuer_cn", "Issuer CN", scripted.issuerCn.toStdString()};
        }
        if (!scripted.notBefore.isEmpty()) {
            cert.fields["validity"]["notBefore"] =
                Wire::CertField{"label_not_before", "Not before", scripted.notBefore.toStdString()};
        }
        if (!scripted.notAfter.isEmpty()) {
            cert.fields["validity"]["notAfter"] =
                Wire::CertField{"label_not_after", "Not after", scripted.notAfter.toStdString()};
        }
        cert.keyUsageBits = scripted.keyUsageBits;
        for (const QString& oid : scripted.extendedKeyUsageOids) {
            cert.ekus.push_back(oid.toStdString());
        }
        if (scripted.chainSubjectCns.isEmpty()) {
            cert.chainSubjectCns.push_back(scripted.subjectCn.toStdString());
        } else {
            for (const QString& cn : scripted.chainSubjectCns) {
                cert.chainSubjectCns.push_back(cn.toStdString());
            }
        }
        cert.trustStatus = scripted.trustStatus;
        for (const QString& token : scripted.securityStatus) {
            cert.fields["security"][token.toStdString()] =
                Wire::CertField{"cert.security." + token.toStdString(), token.toStdString(), token.toStdString()};
        }
        certs.push_back(std::move(cert));
    }
    return certs;
}

Wire::CredentialsResult FakeSocketAgent::buildCredentialsResult(bool withRecords) const
{
    Wire::CredentialsResult result;
    result.result.outcome = m_config.credOutcome;
    result.result.blocked = m_config.credBlocked;
    result.result.retriesLeft = m_config.credRetriesLeft;
    if (withRecords) {
        for (const FakeSocketCredRecord& scripted : m_config.credRecords) {
            Wire::CredentialRecord record;
            record.id = scripted.id.toStdString();
            record.label = scripted.label.toStdString();
            record.kind = scripted.kind.toStdString();
            record.state = scripted.state.toStdString();
            record.retriesLeft = scripted.retriesLeft;
            record.canChange = scripted.canChange;
            record.unblockStyle = "unknown";
            record.recovery = "unknown";
            result.records.push_back(std::move(record));
        }
    }
    return result;
}

// ---- operations --------------------------------------------------------------------

FakeSocketAgent::Op* FakeSocketAgent::findOperation(quint64 opId)
{
    for (const auto& op : m_operations) {
        if (op->id == opId) {
            return op.get();
        }
    }
    return nullptr;
}

int FakeSocketAgent::operationCount() const
{
    return static_cast<int>(m_operations.size());
}

int FakeSocketAgent::cancelledOperationCount() const
{
    return m_cancelledOps;
}

int FakeSocketAgent::getStateCount() const
{
    return m_getStateCalls;
}

int FakeSocketAgent::layoutCallCount() const
{
    return m_layoutCalls;
}

int FakeSocketAgent::appearanceFontCallCount() const
{
    return m_appearanceFontCalls;
}

int FakeSocketAgent::listCredentialsCount() const
{
    return m_listCredentialsCalls;
}

int FakeSocketAgent::getSignResultCount() const
{
    return m_getSignResultCalls;
}

int FakeSocketAgent::getConfigCount() const
{
    return m_getConfigCalls;
}

int FakeSocketAgent::configMutationCount() const
{
    return m_configMutationCalls;
}

QVariant FakeSocketAgent::configValue(const QString& key) const
{
    return m_config.config.value(key);
}

QString FakeSocketAgent::lastSignCertId() const
{
    return m_lastSignCertId;
}

QByteArray FakeSocketAgent::lastSignInputBytes() const
{
    return m_lastSignInputBytes;
}

QVariantMap FakeSocketAgent::lastSignOptions() const
{
    return m_lastSignOptions;
}

QString FakeSocketAgent::lastSignBatchCertId() const
{
    return m_lastSignBatchCertId;
}

QVariantMap FakeSocketAgent::lastSignBatchOptions() const
{
    return m_lastSignBatchOptions;
}

QStringList FakeSocketAgent::lastSignBatchDisplayNames() const
{
    return m_lastSignBatchDisplayNames;
}

QList<QByteArray> FakeSocketAgent::lastSignBatchDocumentBytes() const
{
    return m_lastSignBatchDocumentBytes;
}

QString FakeSocketAgent::lastCertDerReader() const
{
    return m_lastCertDerReader;
}

QString FakeSocketAgent::lastCertDerCertId() const
{
    return m_lastCertDerCertId;
}

std::optional<bool> FakeSocketAgent::lastManagePinActivateKey() const
{
    return m_lastManagePinActivateKey;
}

QVariantMap FakeSocketAgent::lastManagePinOptions() const
{
    QVariantMap out;
    if (m_lastManagePinActivateKey.has_value()) {
        out.insert(QStringLiteral("activateKey"), *m_lastManagePinActivateKey);
    }
    return out;
}

void FakeSocketAgent::mintOperation(Connection* connection, quint64 req, OpKind kind, bool withRecords,
                                    QStringList batchDisplayNames)
{
    auto op = std::make_unique<Op>();
    op->id = ++m_nextOpId;
    op->kind = kind;
    op->connection = connection;
    op->withRecords = withRecords;
    op->batchDisplayNames = std::move(batchDisplayNames);
    const quint64 opId = op->id;
    m_operations.push_back(std::move(op));

    // The op-started reply is enqueued BEFORE any of the op's events — the
    // unicast-FIFO ordering the wire contract guarantees.
    sendCbor(connection, Wire::makeReply(req, Wire::OpStarted{opId}));
    if (m_config.raceResultBeforeReturn) {
        fireOperation(opId); // events written before the client even parses the reply
        return;
    }
    QTimer::singleShot(m_config.operationDelayMs, this, [this, opId]() { fireOperation(opId); });
}

void FakeSocketAgent::fireOperation(quint64 opId)
{
    Op* op = findOperation(opId);
    if (op == nullptr || op->fired || !isLive(op->connection)) {
        return;
    }
    op->fired = true;

    Wire::OpProgress progress;
    progress.op = op->id;
    progress.phase = Wire::OperationPhase::Reading;
    progress.progress = 0.5;
    sendCbor(op->connection, Wire::toCbor(progress));

    const bool ok = m_config.finalStatus == 0;
    const bool suppressResult = m_config.suppressResult || (op->kind == OpKind::Sign && m_config.signRecoverable);
    // Progressive delivery: every scripted group streams, in order, strictly
    // before the op-result-ready below for the SAME op — same gating as that
    // Result (a successful, non-suppressed read), since an unscripted default
    // (identityGroupScript empty) must stream nothing regardless.
    if (op->kind == OpKind::Identity && ok && !suppressResult && !m_config.identityGroupScript.isEmpty() &&
        isLive(op->connection)) {
        for (const FakeSocketIdentityGroup& g : m_config.identityGroupScript) {
            Wire::OpIdentityGroup ev;
            ev.op = op->id;
            ev.groupKey = g.key.toStdString();
            ev.fields = g.fields;
            sendCbor(op->connection, Wire::toCbor(ev));
        }
    }
    // A read result only exists on Ok; the credentials result is delivered
    // for EVERY completed attempt (its payload carries the outcome); the
    // SignBatch result is delivered whenever >=1 document was attempted --
    // reached here, that is ALWAYS true (an op is only minted with a
    // non-empty document list), regardless of the aggregate status.
    const bool emitResult = (ok || op->kind == OpKind::Credentials || op->kind == OpKind::SignBatch) && !suppressResult;
    if (emitResult && isLive(op->connection)) {
        Wire::OpResultReady ready;
        ready.op = op->id;
        switch (op->kind) {
        case OpKind::Identity: {
            Wire::IdentityResult identity;
            if (!m_config.identityGroupScript.isEmpty()) {
                // The eventual result is the UNION of every scripted group —
                // the same invariant the D-Bus fake's buildIdentityFields()
                // enforces for its own script.
                for (const FakeSocketIdentityGroup& g : m_config.identityGroupScript) {
                    identity.fields[g.key.toStdString()] = g.fields;
                }
            } else {
                identity.fields["personal"]["given_name"] =
                    Wire::IdentityField{"label_given_name", "Given name", "text", std::string("Ana")};
                identity.fields["personal"]["family_name"] =
                    Wire::IdentityField{"label_family_name", "Family name", "text", std::string("Horvat")};
            }
            ready.result = std::move(identity);
            sendCbor(op->connection, Wire::toCbor(ready));
            break;
        }
        case OpKind::TokenInfo: {
            // "token" group -- label/serial_number/manufacturer, matching
            // Card1.ReadTokenInfo's wire result (rides the SAME
            // Identity1-shaped op-result-ready arm as Identity; only the
            // group content differs). tokenInfoEmpty scripts the
            // unsupported-plugin case: a present-but-EMPTY group, a SUCCESS
            // with zero fields, never an error. An empty inner field map is
            // modeled as the "token" key being ABSENT from the outer
            // IdentityResult.fields map (mirrors the real agent's own
            // CardReadSnapshot -> wire mapping, which never inserts a group
            // whose fields ended up empty).
            Wire::IdentityResult tokenInfo;
            if (!m_config.tokenInfoEmpty) {
                tokenInfo.fields["token"]["label"] =
                    Wire::IdentityField{"field.label", "Label", "text", std::string("Fake Token")};
                tokenInfo.fields["token"]["serial_number"] =
                    Wire::IdentityField{"field.serial_number", "Serial Number", "text", std::string("0123456789")};
                tokenInfo.fields["token"]["manufacturer"] =
                    Wire::IdentityField{"field.manufacturer", "Manufacturer", "text", std::string("LibreSCRS Fake")};
            }
            ready.result = std::move(tokenInfo);
            sendCbor(op->connection, Wire::toCbor(ready));
            break;
        }
        case OpKind::Photo: {
            FdHandle photoFd = makeMemfdDocument(m_config.photoBytes);
            Wire::PhotoResult photos;
            photos.photos.push_back(Wire::PhotoItem{"personal:photo", 0});
            ready.result = std::move(photos);
            const int raw = photoFd.get();
            sendCbor(op->connection, Wire::toCbor(ready), std::span<const int>(&raw, 1));
            break;
        }
        case OpKind::Certificates: {
            ready.result = Wire::CertListResult{buildCertList()};
            sendCbor(op->connection, Wire::toCbor(ready));
            break;
        }
        case OpKind::Sign: {
            FdHandle artifactFd = makeMemfdDocument(m_config.signArtifactBytes);
            ready.result = Wire::SignResult{0, signMeta()};
            const int raw = artifactFd.get();
            sendCbor(op->connection, Wire::toCbor(ready), std::span<const int>(&raw, 1));
            break;
        }
        case OpKind::SignBatch: {
            // One memfd per document, in order (fd-index == row position):
            // a row at or past batchHaltAtIndex seals ZERO bytes -- the
            // frozen failed-row convention -- and carries the halt code;
            // every earlier row signs successfully with signArtifactBytes/
            // signMeta.
            std::vector<FdHandle> rowFds;
            std::vector<int> rawFds;
            rowFds.reserve(static_cast<std::size_t>(op->batchDisplayNames.size()));
            rawFds.reserve(static_cast<std::size_t>(op->batchDisplayNames.size()));
            Wire::SignBatchResult batchResult;
            batchResult.rows.reserve(static_cast<std::size_t>(op->batchDisplayNames.size()));
            for (int i = 0; i < op->batchDisplayNames.size(); ++i) {
                const bool halted = m_config.batchHaltAtIndex >= 0 && i >= m_config.batchHaltAtIndex;
                FdHandle fd = makeMemfdDocument(halted ? QByteArray() : m_config.signArtifactBytes);
                rawFds.push_back(fd.get());
                Wire::SignBatchRow row;
                row.displayName = op->batchDisplayNames.at(i).toStdString();
                row.artifact = static_cast<std::uint64_t>(i);
                row.meta = halted ? Wire::SignMeta{} : signMeta();
                row.code = halted ? static_cast<Wire::ErrorCode>(m_config.batchHaltErrorCode) : Wire::ErrorCode::None;
                batchResult.rows.push_back(std::move(row));
                rowFds.push_back(std::move(fd));
            }
            ready.result = std::move(batchResult);
            sendCbor(op->connection, Wire::toCbor(ready), std::span<const int>(rawFds));
            break;
        }
        case OpKind::Credentials: {
            ready.result = buildCredentialsResult(op->withRecords);
            sendCbor(op->connection, Wire::toCbor(ready));
            break;
        }
        }
    }
    if (op->kind == OpKind::Sign && m_config.signRecoverable && ok) {
        op->retainedArtifact = true; // GetSignResult re-serves it within the grace window
    }

    if (!isLive(op->connection)) {
        return;
    }
    Wire::OpFinished finished;
    finished.op = op->id;
    finished.status = static_cast<Wire::OperationStatus>(m_config.finalStatus);
    finished.code = static_cast<Wire::ErrorCode>(m_config.finalErrorCode);
    sendCbor(op->connection, Wire::toCbor(finished));
}

// ---- request handling -----------------------------------------------------------------

void FakeSocketAgent::handleRequest(Connection* connection, Wire::RequestEnvelope&& envelope,
                                    std::vector<Wire::UniqueFd>& fds)
{
    const quint64 req = envelope.req;
    Wire::Request& body = envelope.body;

    const bool lacksPinManagement = (m_config.capabilities & (1U << 3)) == 0;

    if (std::get_if<Wire::Hello>(&body) != nullptr) {
        Wire::HelloAck ack;
        ack.agentVer = m_config.agentVersion.toStdString();
        for (const QString& feature : m_config.features) {
            ack.features.push_back(feature.toStdString());
        }
        sendCbor(connection, Wire::makeReply(req, ack));
        return;
    }
    if (std::get_if<Wire::GetState>(&body) != nullptr) {
        ++m_getStateCalls;
        if (m_config.wedgeGetState) {
            return; // scripted wedge: never answers
        }
        if (m_config.nonCanonicalAfterStateReply) {
            // The awaited reply + a non-canonical frame in ONE write: the
            // client must keep the received reply while still failing the
            // connection closed on the malformed trailer.
            std::vector<std::uint8_t> batch = Wire::encodeFrame(Wire::makeReply(req, buildState()).encode());
            static constexpr std::uint8_t kNonCanonical[] = {0x19, 0x00, 0x2A};
            const std::vector<std::uint8_t> trailer = Wire::encodeFrame(kNonCanonical);
            batch.insert(batch.end(), trailer.begin(), trailer.end());
            sendRawBatch(connection, batch);
            return;
        }
        sendCbor(connection, Wire::makeReply(req, buildState()));
        return;
    }
    if (std::get_if<Wire::ReadIdentity>(&body) != nullptr) {
        if (m_config.failMethodEntry) {
            sendEntryError(connection, req, m_config.entryError);
            return;
        }
        mintOperation(connection, req, OpKind::Identity, false);
        return;
    }
    if (std::get_if<Wire::GetPhoto>(&body) != nullptr) {
        if (m_config.failMethodEntry) {
            sendEntryError(connection, req, m_config.entryError);
            return;
        }
        mintOperation(connection, req, OpKind::Photo, false);
        return;
    }
    if (std::get_if<Wire::ReadCertificates>(&body) != nullptr) {
        if (m_config.failMethodEntry) {
            sendEntryError(connection, req, m_config.entryError);
            return;
        }
        mintOperation(connection, req, OpKind::Certificates, false);
        return;
    }
    if (std::get_if<Wire::ReadTokenInfo>(&body) != nullptr) {
        // Real-agent capability entry gate: token info is PKI-adjacent
        // (pkcs15), so it shares ReadCertificates' gate bit (bit 0, Pki) —
        // enforced FOR REAL here (unlike ReadCertificates above, which only
        // models the generic failMethodEntry refusal).
        const bool lacksPki = (m_config.capabilities & 1U) == 0;
        if (lacksPki) {
            sendEntryError(connection, req, Wire::SyncError::UnsupportedOnThisCard);
            return;
        }
        if (m_config.failMethodEntry) {
            sendEntryError(connection, req, m_config.entryError);
            return;
        }
        mintOperation(connection, req, OpKind::TokenInfo, false);
        return;
    }
    if (const auto* sign = std::get_if<Wire::Sign>(&body)) {
        if (m_config.failMethodEntry) {
            sendEntryError(connection, req, m_config.entryError);
            return;
        }
        if (sign->inFd >= fds.size()) {
            sendEntryError(connection, req, Wire::SyncError::InvalidRequest);
            return; // fd index outside this frame's SCM_RIGHTS vector
        }
        // Capture the verbatim in-args (the document is read synchronously,
        // before the client closes its copy).
        m_lastSignCertId = QString::fromStdString(sign->cert);
        m_lastSignInputBytes = readFdAll(fds[static_cast<std::size_t>(sign->inFd)].get());
        m_lastSignOptions = signOptsToMap(sign->opts);
        mintOperation(connection, req, OpKind::Sign, false);
        return;
    }
    if (const auto* batch = std::get_if<Wire::SignBatch>(&body)) {
        if (m_config.failMethodEntry) {
            sendEntryError(connection, req, m_config.entryError);
            return;
        }
        QStringList names;
        QList<QByteArray> allBytes;
        names.reserve(static_cast<qsizetype>(batch->docs.size()));
        allBytes.reserve(static_cast<qsizetype>(batch->docs.size()));
        for (const Wire::BatchDocument& doc : batch->docs) {
            names.append(QString::fromStdString(doc.name));
            if (doc.fdIndex >= fds.size()) {
                sendEntryError(connection, req, Wire::SyncError::InvalidRequest);
                return; // fd index outside this frame's SCM_RIGHTS vector
            }
            allBytes.append(readFdAll(fds[static_cast<std::size_t>(doc.fdIndex)].get()));
        }
        m_lastSignBatchCertId = QString::fromStdString(batch->cert);
        m_lastSignBatchDisplayNames = names;
        m_lastSignBatchDocumentBytes = allBytes;
        m_lastSignBatchOptions = signOptsToMap(batch->opts);
        mintOperation(connection, req, OpKind::SignBatch, false, names);
        return;
    }
    if (const auto* cancel = std::get_if<Wire::CancelOp>(&body)) {
        sendCbor(connection, Wire::makeReply(req, Wire::AckReply{}));
        Op* op = findOperation(cancel->op);
        if (op != nullptr) {
            ++m_cancelledOps;
            if (!op->fired && isLive(op->connection)) {
                op->fired = true;
                Wire::OpFinished finished;
                finished.op = op->id;
                finished.status = Wire::OperationStatus::Cancelled;
                finished.code = Wire::ErrorCode::None;
                sendCbor(op->connection, Wire::toCbor(finished));
            }
        }
        return;
    }
    if (const auto* recovery = std::get_if<Wire::GetSignResult>(&body)) {
        ++m_getSignResultCalls;
        Op* op = findOperation(recovery->op);
        if (op != nullptr && op->kind == OpKind::Sign && op->retainedArtifact) {
            FdHandle artifactFd = makeMemfdDocument(m_config.signArtifactBytes);
            const int raw = artifactFd.get();
            sendCbor(connection, Wire::makeSignRecoveryReply(req, Wire::SignResult{0, signMeta()}),
                     std::span<const int>(&raw, 1));
            return;
        }
        // GetSignResult's dedicated dead-end name (see Messages.h's SyncError
        // doc comment): the op is unknown, wasn't a Sign op, or nothing was
        // ever retained for it -- previously improvised via the generic
        // InvalidRequest, now the real production socket daemon's own name
        // for this exact case (see LibreDarwin's handleGetSignResult).
        Wire::ErrInfo info;
        info.code = Wire::SyncError::NoResult;
        info.msgFallback = std::string("no retained result for this operation");
        sendCbor(connection, Wire::makeErrorReply(req, info));
        return;
    }
    if (std::get_if<Wire::GetConfig>(&body) != nullptr) {
        ++m_getConfigCalls;
        Wire::ConfigReply reply;
        for (auto it = m_config.config.constBegin(); it != m_config.config.constEnd(); ++it) {
            reply.entries.emplace(it.key().toStdString(),
                                  configValueToCbor(it.key(), it.value(), m_config.tslSourcesAsMaps));
        }
        sendCbor(connection, Wire::makeReply(req, reply));
        return;
    }
    if (const auto* setConfig = std::get_if<Wire::SetConfig>(&body)) {
        ++m_configMutationCalls;
        const QString key = QString::fromStdString(setConfig->key);
        // The structural policy, enforced for real: this arm is only ever
        // reached by a client that skipped its own local grammar check (the
        // wire's `set-config` admits a settable-config-key ONLY), so the
        // refusals it would then earn have to be the real ones.
        if (!isKnownConfigKey(key)) {
            sendEntryError(connection, req, Wire::SyncError::UnknownConfigKey);
            return;
        }
        if (!isSettableConfigKey(key)) {
            sendEntryError(connection, req, Wire::SyncError::ReadOnlyConfig);
            return;
        }
        if (m_config.configMutationError) {
            sendEntryError(connection, req, *m_config.configMutationError);
            return;
        }
        m_config.config.insert(key, cborConfigValueToVariant(key, setConfig->value));
        sendCbor(connection, Wire::makeReply(req, Wire::AckReply{}));
        emitConfigChanged(key);
        return;
    }
    if (const auto* resetConfig = std::get_if<Wire::ResetConfig>(&body)) {
        ++m_configMutationCalls;
        // `reset-config` takes the FULL config-key set, so unlike SetConfig a
        // non-settable key genuinely arrives here and earns the agent's own
        // ReadOnlyConfig — the client cannot pre-empt what the grammar admits.
        const QString key = QString::fromStdString(resetConfig->key);
        if (!isKnownConfigKey(key)) {
            sendEntryError(connection, req, Wire::SyncError::UnknownConfigKey);
            return;
        }
        if (!isSettableConfigKey(key)) {
            sendEntryError(connection, req, Wire::SyncError::ReadOnlyConfig);
            return;
        }
        if (m_config.configMutationError) {
            sendEntryError(connection, req, *m_config.configMutationError);
            return;
        }
        m_config.config.insert(key, m_configDefaults.value(key));
        sendCbor(connection, Wire::makeReply(req, Wire::AckReply{}));
        emitConfigChanged(key);
        return;
    }
    if (const auto* certDer = std::get_if<Wire::GetCertDer>(&body)) {
        m_lastCertDerReader = QString::fromStdString(certDer->reader);
        m_lastCertDerCertId = QString::fromStdString(certDer->cert);
        if (m_config.certDerKeyNotFound) {
            sendEntryError(connection, req, Wire::SyncError::KeyNotFound);
            return;
        }
        if (m_config.certDerUnexpectedArm) {
            // A valid reply frame carrying the WRONG arm for this request. The
            // transport decodes the frame fine and then finds no CertDerReply
            // and no ErrInfo in it, which is the socket wire's version of a
            // reply outside the request's contract.
            sendCbor(connection, Wire::makeReply(req, Wire::AckReply{}));
            return;
        }
        Wire::CertDerReply reply;
        const auto* derData = reinterpret_cast<const std::uint8_t*>(m_config.certDerBytes.constData());
        reply.der.assign(derData, derData + m_config.certDerBytes.size());
        sendCbor(connection, Wire::makeReply(req, reply));
        return;
    }
    if (std::get_if<Wire::LayoutVisual>(&body) != nullptr) {
        ++m_layoutCalls;
        // Card-independent and scripted, exactly like the D-Bus fake's
        // ManagerAdaptor::LayoutVisualSignature: the fake never actually
        // lays out the request's text against its box, it just serves
        // Config's fixed reply -- this exercises the WIRE round trip, not
        // LM's word-wrap algorithm.
        Wire::LayoutReply reply;
        reply.fontSize = m_config.layoutFontSize;
        reply.lineHeight = m_config.layoutLineHeight;
        for (const QString& line : m_config.layoutLines) {
            reply.lines.push_back(line.toStdString());
        }
        reply.clipped = m_config.layoutClipped;
        sendCbor(connection, Wire::makeReply(req, reply));
        return;
    }
    if (std::get_if<Wire::GetAppearanceFont>(&body) != nullptr) {
        ++m_appearanceFontCalls;
        FdHandle fontFd = makeMemfdDocument(m_config.appearanceFontBytes);
        const int raw = fontFd.get();
        sendCbor(connection, Wire::makeReply(req, Wire::AppearanceFontReply{0}), std::span<const int>(&raw, 1));
        return;
    }
    if (std::get_if<Wire::ListCredentials>(&body) != nullptr) {
        ++m_listCredentialsCalls;
        if (lacksPinManagement) {
            sendEntryError(connection, req, Wire::SyncError::UnsupportedOnThisCard);
            return;
        }
        // The listing becomes current and its ids are snapshotted — the set
        // ManagePin resolves pinIds against (list-before-mutate).
        m_hasListing = true;
        m_listedIds.clear();
        for (const FakeSocketCredRecord& record : m_config.credRecords) {
            m_listedIds.append(record.id);
        }
        mintOperation(connection, req, OpKind::Credentials, true);
        return;
    }
    if (const auto* manage = std::get_if<Wire::ManagePin>(&body)) {
        // Captured unconditionally, before any of the refusal branches below,
        // so this reflects exactly what crossed the wire in THIS request --
        // including nullopt when the client sent no activateKey field at all
        // (Change/Unblock) -- not just what a legal, accepted request carried.
        m_lastManagePinActivateKey = manage->activateKey;
        if (lacksPinManagement) {
            sendEntryError(connection, req, Wire::SyncError::UnsupportedOnThisCard);
            return;
        }
        if (m_config.credEntryError) {
            sendEntryError(connection, req, m_config.credEntryErrorName);
            return;
        }
        const QString verb = QString::fromStdString(manage->verb);
        const bool knownVerb = verb == QLatin1String("change") || verb == QLatin1String("unblock") ||
                               verb == QLatin1String("activate_pin");
        if (!knownVerb || (manage->activateKey && verb != QLatin1String("activate_pin"))) {
            sendEntryError(connection, req, Wire::SyncError::InvalidRequest);
            return;
        }
        const QString pinId = QString::fromStdString(manage->pinId);
        if (!m_hasListing || !m_listedIds.contains(pinId)) {
            sendEntryError(connection, req, Wire::SyncError::UnknownCredential);
            return;
        }
        // The mutation reaches the card: the listing cache drops, so a client
        // that skips the mandatory re-list fails loudly.
        m_hasListing = false;
        m_listedIds.clear();
        mintOperation(connection, req, OpKind::Credentials, false);
        return;
    }
    if (std::get_if<Wire::ActivateSigningKey>(&body) != nullptr) {
        if (lacksPinManagement) {
            sendEntryError(connection, req, Wire::SyncError::UnsupportedOnThisCard);
            return;
        }
        if (m_config.credEntryError) {
            sendEntryError(connection, req, m_config.credEntryErrorName);
            return;
        }
        m_hasListing = false;
        m_listedIds.clear();
        mintOperation(connection, req, OpKind::Credentials, false);
        return;
    }
    // Request families this fake does not model (Pkcs11 raw crypto):
    // answer a clean per-request refusal.
    Wire::ErrInfo info;
    info.code = Wire::SyncError::InvalidRequest;
    info.msgFallback = std::string("request family not modelled by this fake");
    sendCbor(connection, Wire::makeErrorReply(req, info));
}

// ---- live scripting ---------------------------------------------------------------------

void FakeSocketAgent::setCardPresent(bool present)
{
    if (m_config.hasCard == present) {
        return;
    }
    m_config.hasCard = present;
    if (present) {
        // Card first, then the reader's claim — a reader's card reference
        // must resolve immediately (the presence-model ordering).
        broadcastCbor(Wire::toCbor(Wire::CardAdded{buildCardState()}));
        Wire::PropertyChanged changed;
        changed.handle = kReaderHandle;
        changed.iface = kReaderIface;
        changed.props.emplace("HasCard", Wire::CborValue(true));
        changed.props.emplace("Card", Wire::CborValue(std::string(kCardHandle)));
        broadcastCbor(Wire::toCbor(changed));
        return;
    }
    m_hasListing = false;
    m_listedIds.clear();
    broadcastCbor(Wire::toCbor(Wire::CardRemoved{std::string(kCardHandle)}));
    Wire::PropertyChanged changed;
    changed.handle = kReaderHandle;
    changed.iface = kReaderIface;
    changed.props.emplace("HasCard", Wire::CborValue(false));
    changed.props.emplace("Card", Wire::CborValue(std::string()));
    broadcastCbor(Wire::toCbor(changed));
}

void FakeSocketAgent::emitCardCapabilitiesChanged(quint32 capabilities)
{
    m_config.capabilities = capabilities;
    Wire::PropertyChanged changed;
    changed.handle = kCardHandle;
    changed.iface = kCardIface;
    changed.props.emplace("Capabilities", Wire::CborValue::uint(capabilities));
    broadcastCbor(Wire::toCbor(changed));
}

void FakeSocketAgent::emitCardTypeChanged(const QString& cardType)
{
    m_config.cardType = cardType;
    Wire::PropertyChanged changed;
    changed.handle = kCardHandle;
    changed.iface = kCardIface;
    changed.props.emplace("CardType", Wire::CborValue(cardType.toStdString()));
    broadcastCbor(Wire::toCbor(changed));
}

void FakeSocketAgent::sendAgentQuiesced(quint32 reason)
{
    Wire::AgentQuiesced quiesced;
    quiesced.reason = static_cast<Wire::QuiesceReason>(reason);
    broadcastCbor(Wire::toCbor(quiesced));
}

void FakeSocketAgent::emitConfigChanged(const QString& key)
{
    broadcastCbor(Wire::toCbor(Wire::ConfigChanged{key.toStdString()}));
}

void FakeSocketAgent::sendNonCanonicalFrame()
{
    // uint 42 in TWO-byte form (0x19 0x00 0x2A): well-formed CBOR, but not
    // shortest-form — the canonical decode rejects it, so the client must
    // fail the connection closed.
    static constexpr std::uint8_t kNonCanonical[] = {0x19, 0x00, 0x2A};
    std::vector<Connection*> targets;
    targets.reserve(m_connections.size());
    for (const auto& connection : m_connections) {
        targets.push_back(connection.get());
    }
    for (Connection* connection : targets) {
        if (!Wire::sendFrame(connection->fd.get(), kNonCanonical)) {
            closeConnection(connection);
        }
    }
}

} // namespace LibreSCRS::AgentClient::Fakes
