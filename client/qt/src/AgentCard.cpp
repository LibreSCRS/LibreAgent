// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentCard.h>

#include <LibreSCRS/AgentClient/AgentCapabilities.h>

#include "TokenMap.h"
#include "TransportSeam.h"
#include "dbus/ErrorNameMap.h" // transport-neutral short-name -> SeamError classification (see its file comment)

#include <QLoggingCategory>

namespace LibreSCRS::AgentClient {

namespace {
Q_LOGGING_CATEGORY(lcAgentCard, "librescrs.agentclient.card")

QString tokenString(std::string_view token)
{
    return QString::fromLatin1(token.data(), static_cast<qsizetype>(token.size()));
}

/// SignOptions -> the wire-keyed option map. The typed members override any
/// same-named key in `extra` (the typed API wins); `extra` otherwise passes
/// through untouched, so append-only wire growth needs no client release.
QVariantMap signOptionsMap(const SignOptions& options)
{
    QVariantMap map = options.extra;
    map.insert(QStringLiteral("format"), tokenString(detail::toToken(options.format)));
    map.insert(QStringLiteral("level"), tokenString(detail::toToken(options.level)));
    map.insert(QStringLiteral("packaging"), tokenString(detail::toToken(options.packaging)));
    if (!options.tsaUrl.isEmpty()) {
        map.insert(QStringLiteral("tsaUrl"), options.tsaUrl);
    }
    if (!options.visualSignature.isEmpty()) {
        map.insert(QStringLiteral("visualSignature"), options.visualSignature);
    }
    return map;
}
} // namespace

// Live-proxy property discipline identical to AgentReader's (see the comment
// there): no ctor full fetch, direct apply of changed subsets, one superseding
// asynchronous refresh for invalidated properties, generation-guarded.
struct AgentCard::Private final : public PropertyListener
{
    AgentCard* q;
    TransportSeam* transport;
    QString id;

    quint64 propsGeneration = 0;
    quint64 fetchToken = 0;
    quint64 fetchGeneration = 0;

    std::uint32_t capabilities = 0;
    // Stored as the raw wire token; capability/pre-read-auth decode happens on
    // demand. Keeping the verbatim string lets forwarding consumers avoid a
    // decode -> re-encode round-trip.
    QString preReadAuth = QStringLiteral("None");
    QString readerId;
    // Empty until known (see AgentCard::cardType()'s doc comment).
    QString cardType;
    QString atrHex;

    Private(AgentCard* owner, TransportSeam* t, QString objectId) : q(owner), transport(t), id(std::move(objectId)) {}

    /// @returns whether CardType (specifically) moved, so the caller can fire
    ///          the dedicated `cardTypeChanged()` signal alongside `changed()`.
    bool applyProps(const QVariantMap& props)
    {
        if (props.contains(QStringLiteral("Capabilities"))) {
            capabilities = props.value(QStringLiteral("Capabilities")).toUInt();
        }
        if (props.contains(QStringLiteral("PreReadAuthMethod"))) {
            preReadAuth = props.value(QStringLiteral("PreReadAuthMethod")).toString();
        }
        if (props.contains(QStringLiteral("Reader"))) {
            readerId = props.value(QStringLiteral("Reader")).toString();
        }
        bool cardTypeMoved = false;
        if (props.contains(QStringLiteral("CardType"))) {
            const QString newCardType = props.value(QStringLiteral("CardType")).toString();
            cardTypeMoved = newCardType != cardType;
            cardType = newCardType;
        }
        if (props.contains(QStringLiteral("Atr"))) {
            atrHex = props.value(QStringLiteral("Atr")).toString();
        }
        return cardTypeMoved;
    }

    void refreshAll()
    {
        fetchGeneration = ++propsGeneration;
        fetchToken = transport->requestProperties(id, ObjectKind::Card, this);
    }

    void onPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated) override
    {
        ++propsGeneration;
        const bool cardTypeMoved = applyProps(changed);
        if (!invalidated.isEmpty()) {
            refreshAll();
        }
        Q_EMIT q->changed();
        if (cardTypeMoved) {
            Q_EMIT q->cardTypeChanged();
        }
    }

    void onPropertiesFetched(quint64 token, const std::optional<QVariantMap>& properties) override
    {
        if (token != fetchToken) {
            return; // superseded by a newer refresh — its reply drives us
        }
        fetchToken = 0;
        if (fetchGeneration != propsGeneration) {
            refreshAll(); // converge the invalidated property under the newest generation
            return;
        }
        if (!properties) {
            return; // fetch failed or timed out — leave cached values
        }
        const bool cardTypeMoved = applyProps(*properties);
        Q_EMIT q->changed();
        if (cardTypeMoved) {
            Q_EMIT q->cardTypeChanged();
        }
    }
};

AgentCard::AgentCard(TransportSeam* transport, const QString& id, QObject* parent)
    : QObject(parent), d(std::make_unique<Private>(this, transport, id))
{
    transport->subscribeProperties(id, ObjectKind::Card, d.get());
}

AgentCard::~AgentCard()
{
    d->transport->unsubscribeProperties(d->id, d.get());
}

QString AgentCard::id() const
{
    return d->id;
}

QString AgentCard::readerId() const
{
    return d->readerId;
}

QStringList AgentCard::capabilities() const
{
    return capabilityTokens(d->capabilities);
}

QString AgentCard::preReadAuth() const
{
    return d->preReadAuth;
}

QString AgentCard::cardType() const
{
    return d->cardType;
}

QString AgentCard::atrHex() const
{
    return d->atrHex;
}

void AgentCard::primeFrom(const QVariantMap& card1Props)
{
    // Discovery-fresh data: bump the generation so a fetch still in flight
    // cannot overwrite this newer state when its older reply lands.
    ++d->propsGeneration;
    d->applyProps(card1Props);
}

// One shared minting path: a refused entry never returns nullptr — it mints
// an operation that terminalizes with the mapped CallError/ErrorCode, queued
// so the consumer's connects (made right after this returns) still fire. The
// agent's error name/message is also logged — it is the only prose record of
// why.
AgentOperation* AgentCard::startOperation(OperationRequest request)
{
    const auto opKindFor = [](OperationRequest::Method method) {
        switch (method) {
        case OperationRequest::Method::ReadIdentity:
            return AgentOperation::Kind::Identity;
        case OperationRequest::Method::GetPhoto:
            return AgentOperation::Kind::Photo;
        case OperationRequest::Method::ReadCertificates:
            return AgentOperation::Kind::Certificates;
        case OperationRequest::Method::ReadTokenInfo:
            return AgentOperation::Kind::Identity;
        case OperationRequest::Method::Sign:
            return AgentOperation::Kind::Sign;
        case OperationRequest::Method::SignBatch:
            return AgentOperation::Kind::BatchSign;
        case OperationRequest::Method::ListCredentials:
        case OperationRequest::Method::ManagePin:
        case OperationRequest::Method::ActivateSigningKey:
            break;
        }
        return AgentOperation::Kind::Credentials;
    };
    const AgentOperation::Kind kind = opKindFor(request.method);

    // Transport-neutral feature-token gate: ReadTokenInfo against an agent
    // that never advertised the "token-info" token (features(), fed from
    // D-Bus Manager1.Features / socket HelloAck.features -- see
    // TransportSeam::features()'s doc comment) is refused HERE, before either
    // transport ever dials the wire, instead of forking taxonomy per
    // transport. A pre-contract agent answers the wire request differently on
    // each transport (D-Bus: UnknownMethod, which ErrorNameMap maps to
    // CallError::InvalidArguments/ErrorCode::None -- reads as a retryable bad
    // request, not the permanent version-skew it actually is; socket: the
    // whole connection drops), so classifying it centrally converges both
    // onto the SAME CapabilityMissing outcome, never touching the wire.
    // Safe against a connected-but-features-unread race: AgentClient's ctor
    // and refreshDiscovery() both probe availability (which populates
    // features() on both transports) strictly BEFORE minting any AgentCard,
    // so features() is always converged by the time a card is even
    // reachable from the public API.
    if (request.method == OperationRequest::Method::ReadTokenInfo &&
        !d->transport->features().contains(QStringLiteral("token-info"))) {
        qCWarning(lcAgentCard) << "ReadTokenInfo refused locally for" << d->id
                               << ": agent does not advertise the token-info feature";
        auto* operation = new AgentOperation(kind, this);
        operation->failEntry(mapAgentErrorShortName(QStringLiteral("NotSupported"),
                                                    QStringLiteral("agent does not advertise the token-info feature")));
        return operation;
    }

    if (request.method == OperationRequest::Method::SignBatch) {
        // Client-side count validation, BEFORE the feature-token gate below:
        // an out-of-bounds count is a caller-argument mistake, not a
        // capability question, so it is classified as CallError::
        // InvalidArguments rather than routed through the agent-error-name
        // mapper the feature-token/entry-refusal gates use.
        const std::size_t count = request.documents.size();
        if (count < kMinBatchDocuments || count > kMaxBatchDocuments) {
            qCWarning(lcAgentCard) << "signBatch refused locally for" << d->id << ": document count" << count
                                   << "outside" << kMinBatchDocuments << '-' << kMaxBatchDocuments;
            auto* operation = new AgentOperation(kind, this);
            SeamError error;
            error.callError = CallError::InvalidArguments;
            error.message = QStringLiteral("signBatch requires between %1 and %2 documents")
                                .arg(kMinBatchDocuments)
                                .arg(kMaxBatchDocuments);
            operation->failEntry(error);
            return operation;
        }
        if (!d->transport->features().contains(QStringLiteral("batch-sign"))) {
            qCWarning(lcAgentCard) << "signBatch refused locally for" << d->id
                                   << ": agent does not advertise the batch-sign feature";
            auto* operation = new AgentOperation(kind, this);
            operation->failEntry(mapAgentErrorShortName(
                QStringLiteral("NotSupported"), QStringLiteral("agent does not advertise the batch-sign feature")));
            return operation;
        }
    }

    // Same transport-neutral posture as the token-info gate above, one
    // check per gated Sign option. A plain sign (neither option set) never
    // reaches either branch — signOptionsMap() only inserts these keys when
    // the caller populated them (SignOptions.h), so an agent predating this
    // surface is still usable for every sign that does not ask for either.
    // SignBatch shares the SAME options vocabulary (format/level/packaging/
    // tsaUrl/visualSignature), so it shares this gate too.
    if (request.method == OperationRequest::Method::Sign || request.method == OperationRequest::Method::SignBatch) {
        if (request.options.contains(QStringLiteral("tsaUrl")) &&
            !d->transport->features().contains(QStringLiteral("tsa-url"))) {
            qCWarning(lcAgentCard) << "sign/signBatch refused locally for" << d->id
                                   << ": agent does not advertise the tsa-url feature";
            auto* operation = new AgentOperation(kind, this);
            operation->failEntry(mapAgentErrorShortName(
                QStringLiteral("NotSupported"), QStringLiteral("agent does not advertise the tsa-url feature")));
            return operation;
        }
        if (request.options.contains(QStringLiteral("visualSignature")) &&
            !d->transport->features().contains(QStringLiteral("visual-sign"))) {
            qCWarning(lcAgentCard) << "sign/signBatch refused locally for" << d->id
                                   << ": agent does not advertise the visual-sign feature";
            auto* operation = new AgentOperation(kind, this);
            operation->failEntry(mapAgentErrorShortName(
                QStringLiteral("NotSupported"), QStringLiteral("agent does not advertise the visual-sign feature")));
            return operation;
        }
    }

    StartOutcome outcome = d->transport->startOperation(d->id, std::move(request));
    if (outcome.operationId.isEmpty()) {
        qCWarning(lcAgentCard).noquote() << "method refused for" << d->id << ':' << outcome.error.wireName
                                         << outcome.error.message;
        auto* operation = new AgentOperation(kind, this);
        operation->failEntry(outcome.error);
        return operation;
    }
    return new AgentOperation(d->transport, outcome.operationId, kind, this);
}

AgentOperation* AgentCard::readIdentity()
{
    OperationRequest request;
    request.method = OperationRequest::Method::ReadIdentity;
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::getPhoto()
{
    // Like readIdentity/readCertificates, a card that lacks the capability is
    // refused at method entry -> an immediately-failed operation.
    OperationRequest request;
    request.method = OperationRequest::Method::GetPhoto;
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::readCertificates()
{
    OperationRequest request;
    request.method = OperationRequest::Method::ReadCertificates;
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::readTokenInfo()
{
    OperationRequest request;
    request.method = OperationRequest::Method::ReadTokenInfo;
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::sign(const QString& certId, FdHandle document, const SignOptions& options)
{
    OperationRequest request;
    request.method = OperationRequest::Method::Sign;
    request.certId = certId;
    request.document = std::move(document);
    request.options = signOptionsMap(options);
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::signBatch(const QString& certId, std::vector<BatchDocument> docs, const SignOptions& options)
{
    OperationRequest request;
    request.method = OperationRequest::Method::SignBatch;
    request.certId = certId;
    request.documents = std::move(docs);
    request.options = signOptionsMap(options);
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::listCredentials()
{
    OperationRequest request;
    request.method = OperationRequest::Method::ListCredentials;
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::managePin(const QString& pinId, PinVerb verb)
{
    OperationRequest request;
    request.method = OperationRequest::Method::ManagePin;
    request.pinId = pinId;
    request.verb = tokenString(detail::toToken(verb));
    return startOperation(std::move(request));
}

AgentOperation* AgentCard::activateSigningKey()
{
    OperationRequest request;
    request.method = OperationRequest::Method::ActivateSigningKey;
    return startOperation(std::move(request));
}

} // namespace LibreSCRS::AgentClient
