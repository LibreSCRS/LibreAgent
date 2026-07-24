// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentCard.h>

#include <LibreSCRS/AgentClient/AgentCapabilities.h>

#include "TokenMap.h"
#include "TransportSeam.h"

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

    Private(AgentCard* owner, TransportSeam* t, QString objectId) : q(owner), transport(t), id(std::move(objectId)) {}

    void applyProps(const QVariantMap& props)
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
    }

    void refreshAll()
    {
        fetchGeneration = ++propsGeneration;
        fetchToken = transport->requestProperties(id, ObjectKind::Card, this);
    }

    void onPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated) override
    {
        ++propsGeneration;
        applyProps(changed);
        if (!invalidated.isEmpty()) {
            refreshAll();
        }
        Q_EMIT q->changed();
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
        applyProps(*properties);
        Q_EMIT q->changed();
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
        case OperationRequest::Method::Sign:
            return AgentOperation::Kind::Sign;
        case OperationRequest::Method::ListCredentials:
        case OperationRequest::Method::ManagePin:
        case OperationRequest::Method::ActivateSigningKey:
            break;
        }
        return AgentOperation::Kind::Credentials;
    };
    const AgentOperation::Kind kind = opKindFor(request.method);
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

AgentOperation* AgentCard::sign(const QString& certId, FdHandle document, const SignOptions& options)
{
    OperationRequest request;
    request.method = OperationRequest::Method::Sign;
    request.certId = certId;
    request.document = std::move(document);
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
