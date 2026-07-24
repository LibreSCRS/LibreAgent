// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The public API driven over a minimal in-process TransportSeam fake (NOT the
// FakeAgent — no bus, no wire): pins the PinVerb/SignOptions -> request
// mapping the client performs, the entry-refusal / availability-sweep
// terminal behavior, registry discovery through the seam, and the
// pimpl/value-semantics contract of the exported QObjects.

#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>

#include "ClientTestAccess.h"
#include "TransportSeam.h"

#include <QCoreApplication>
#include <QHash>
#include <QVariantMap>

#include <fcntl.h>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

using namespace LibreSCRS::AgentClient;

// ---- pimpl / value semantics ---------------------------------------------------

static_assert(!std::is_copy_constructible_v<AgentClient> && !std::is_copy_assignable_v<AgentClient>);
static_assert(!std::is_copy_constructible_v<AgentReader> && !std::is_copy_assignable_v<AgentReader>);
static_assert(!std::is_copy_constructible_v<AgentCard> && !std::is_copy_assignable_v<AgentCard>);
static_assert(!std::is_copy_constructible_v<AgentOperation> && !std::is_copy_assignable_v<AgentOperation>);
// The photo payload is move-only end to end (FdHandle), never copied.
static_assert(!std::is_copy_constructible_v<PhotoItem> && std::is_move_constructible_v<PhotoItem>);
static_assert(!std::is_copy_constructible_v<OperationPayload> && std::is_move_constructible_v<OperationPayload>);

namespace {

class FakeTransportSeam : public TransportSeam
{
public:
    // ---- knobs -----------------------------------------------------------
    bool available = true;
    bool installed = true;
    RegistrySnapshot snapshot;
    QString nextOperationId; // empty -> refuse entry with entryError
    SeamError entryError;
    std::optional<TerminalSnapshot> terminal;                 // ctor lost-Finished recovery read
    std::function<std::optional<OperationPayload>()> recover; // GetResult recovery pull

    // ---- recorded --------------------------------------------------------
    struct StartRecord
    {
        QString cardId;
        OperationRequest::Method method = OperationRequest::Method::ReadIdentity;
        QString certId;
        QString pinId;
        QString verb;
        QVariantMap options;
        bool documentValid = false;
    };
    std::vector<StartRecord> starts;
    std::vector<QString> cancelled;
    struct DerRecord
    {
        QString readerId;
        QString certId;
        quint64 token = 0;
        DerListener* listener = nullptr;
    };
    std::vector<DerRecord> derRequests;

    // ---- live wiring -----------------------------------------------------
    RegistryListener* registry = nullptr;
    QHash<PropertyListener*, QString> propertySubscriptions;
    QHash<OperationListener*, QString> operationSubscriptions;

    // TransportSeam
    void setRegistryListener(RegistryListener* listener) override
    {
        registry = listener;
    }
    [[nodiscard]] bool probeAvailability() override
    {
        return available;
    }
    [[nodiscard]] bool agentInstalled() override
    {
        return installed;
    }
    [[nodiscard]] std::optional<RegistrySnapshot> fetchRegistry() override
    {
        if (!available) {
            return std::nullopt;
        }
        return snapshot;
    }
    void subscribeProperties(const QString& objectId, ObjectKind /*kind*/, PropertyListener* listener) override
    {
        propertySubscriptions.insert(listener, objectId);
    }
    void unsubscribeProperties(const QString& /*objectId*/, PropertyListener* listener) override
    {
        propertySubscriptions.remove(listener);
    }
    quint64 requestProperties(const QString& /*objectId*/, ObjectKind /*kind*/, PropertyListener* /*listener*/) override
    {
        return ++m_token;
    }
    [[nodiscard]] StartOutcome startOperation(const QString& cardId, OperationRequest request) override
    {
        StartRecord record;
        record.cardId = cardId;
        record.method = request.method;
        record.certId = request.certId;
        record.pinId = request.pinId;
        record.verb = request.verb;
        record.options = request.options;
        record.documentValid = request.document.valid();
        starts.push_back(record);

        StartOutcome outcome;
        if (nextOperationId.isEmpty()) {
            outcome.error = entryError;
        } else {
            outcome.operationId = nextOperationId;
        }
        return outcome;
    }
    void subscribeOperation(const QString& operationId, OperationKind /*kind*/, OperationListener* listener) override
    {
        operationSubscriptions.insert(listener, operationId);
    }
    void unsubscribeOperation(const QString& /*operationId*/, OperationListener* listener) override
    {
        operationSubscriptions.remove(listener);
    }
    [[nodiscard]] std::optional<TerminalSnapshot> fetchOperationState(const QString& /*operationId*/) override
    {
        return terminal;
    }
    [[nodiscard]] std::optional<OperationPayload> fetchOperationResult(const QString& /*operationId*/,
                                                                       OperationKind /*kind*/) override
    {
        return recover ? recover() : std::nullopt;
    }
    void cancelOperation(const QString& operationId) override
    {
        cancelled.push_back(operationId);
    }
    quint64 requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener) override
    {
        DerRecord record;
        record.readerId = readerId;
        record.certId = certId;
        record.token = ++m_token;
        record.listener = listener;
        derRequests.push_back(record);
        return record.token;
    }
    void cancelCertificateDer(quint64 token, DerListener* listener) override
    {
        Q_UNUSED(listener) // the fake mirrors the token-keyed production contract
        for (DerRecord& record : derRequests) {
            if (record.token == token) {
                record.listener = nullptr;
            }
        }
    }

    // ---- test drivers ------------------------------------------------------
    [[nodiscard]] OperationListener* soleOperationListener() const
    {
        EXPECT_EQ(operationSubscriptions.size(), 1);
        return operationSubscriptions.isEmpty() ? nullptr : operationSubscriptions.constBegin().key();
    }

private:
    quint64 m_token = 0;
};

RegistrySnapshot oneReaderOneCard()
{
    RegistrySnapshot snapshot;
    QVariantMap readerProps;
    readerProps.insert(QStringLiteral("Name"), QStringLiteral("Fake Reader"));
    readerProps.insert(QStringLiteral("HasCard"), true);
    readerProps.insert(QStringLiteral("Card"), QStringLiteral("/card/0"));
    snapshot.readers.append({QStringLiteral("/reader/0"), readerProps});

    QVariantMap cardProps;
    cardProps.insert(QStringLiteral("Capabilities"), 3u); // Pki | IdentityData
    cardProps.insert(QStringLiteral("PreReadAuthMethod"), QStringLiteral("PaceCan"));
    cardProps.insert(QStringLiteral("Reader"), QStringLiteral("/reader/0"));
    snapshot.cards.append({QStringLiteral("/card/0"), cardProps});
    return snapshot;
}

struct ClientOnFake
{
    FakeTransportSeam* fake;             // owned by the client
    std::unique_ptr<AgentClient> client; // owns the fake

    explicit ClientOnFake(RegistrySnapshot snapshot = oneReaderOneCard())
    {
        auto owned = std::make_unique<FakeTransportSeam>();
        fake = owned.get();
        fake->snapshot = std::move(snapshot);
        client.reset(ClientTestAccess::create(std::move(owned)));
    }
};

void spinEventLoop()
{
    QCoreApplication::processEvents();
    QCoreApplication::processEvents();
}

} // namespace

// ---- registry discovery through the seam ---------------------------------------

TEST(SeamRegistry, DiscoversReadersAndCardsFromTheSnapshot)
{
    ClientOnFake h;
    ASSERT_TRUE(h.client->isAvailable());
    EXPECT_TRUE(h.client->agentInstalled());

    ASSERT_EQ(h.client->readers().size(), 1);
    AgentReader* reader = h.client->readers().constFirst();
    EXPECT_EQ(reader->id(), QStringLiteral("/reader/0"));
    EXPECT_EQ(reader->name(), QStringLiteral("Fake Reader"));
    EXPECT_TRUE(reader->hasCard());
    EXPECT_EQ(reader->cardId(), QStringLiteral("/card/0"));

    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(reader->card(), card);
    EXPECT_EQ(card->readerId(), QStringLiteral("/reader/0"));
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki"), QStringLiteral("IdentityData")}));
    EXPECT_EQ(card->preReadAuth(), QStringLiteral("PaceCan"));
}

TEST(SeamRegistry, UnavailableAgentYieldsInertClient)
{
    auto owned = std::make_unique<FakeTransportSeam>();
    owned->available = false;
    owned->installed = false;
    std::unique_ptr<AgentClient> client{ClientTestAccess::create(std::move(owned))};
    EXPECT_FALSE(client->isAvailable());
    EXPECT_FALSE(client->agentInstalled());
    EXPECT_TRUE(client->readers().isEmpty());
}

TEST(SeamRegistry, ReadersAreSortedById)
{
    RegistrySnapshot snapshot;
    QVariantMap props;
    props.insert(QStringLiteral("Name"), QStringLiteral("B"));
    snapshot.readers.append({QStringLiteral("/reader/9"), props});
    props.insert(QStringLiteral("Name"), QStringLiteral("A"));
    snapshot.readers.append({QStringLiteral("/reader/1"), props});

    ClientOnFake h(std::move(snapshot));
    const QList<AgentReader*> readers = h.client->readers();
    ASSERT_EQ(readers.size(), 2);
    EXPECT_EQ(readers[0]->id(), QStringLiteral("/reader/1"));
    EXPECT_EQ(readers[1]->id(), QStringLiteral("/reader/9"));
}

// ---- SignOptions / PinVerb -> request mapping -----------------------------------

TEST(SeamMapping, SignOptionsMapToWireTokens)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);

    SignOptions options;
    options.format = SignatureFormat::XAdES;
    options.level = SignatureLevel::BT;
    options.packaging = Packaging::Detached;
    options.tsaUrl = QStringLiteral("http://tsa.example");
    options.extra.insert(QStringLiteral("reason"), QStringLiteral("approval"));

    FdHandle document{::open("/dev/null", O_RDONLY | O_CLOEXEC)};
    ASSERT_TRUE(document.valid());
    AgentOperation* op = card->sign(QStringLiteral("certid123"), std::move(document), options);
    ASSERT_NE(op, nullptr);
    EXPECT_FALSE(op->isFinished());

    ASSERT_EQ(h.fake->starts.size(), 1u);
    const auto& record = h.fake->starts.front();
    EXPECT_EQ(record.cardId, QStringLiteral("/card/0"));
    EXPECT_EQ(record.method, OperationRequest::Method::Sign);
    EXPECT_EQ(record.certId, QStringLiteral("certid123"));
    EXPECT_TRUE(record.documentValid);
    EXPECT_EQ(record.options.value(QStringLiteral("format")).toString(), QStringLiteral("xades"));
    EXPECT_EQ(record.options.value(QStringLiteral("level")).toString(), QStringLiteral("b-t"));
    EXPECT_EQ(record.options.value(QStringLiteral("packaging")).toString(), QStringLiteral("detached"));
    EXPECT_EQ(record.options.value(QStringLiteral("tsaUrl")).toString(), QStringLiteral("http://tsa.example"));
    // extra passes through untouched
    EXPECT_EQ(record.options.value(QStringLiteral("reason")).toString(), QStringLiteral("approval"));
}

TEST(SeamMapping, DefaultSignOptionsOmitOptionalKeys)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);

    FdHandle document{::open("/dev/null", O_RDONLY | O_CLOEXEC)};
    (void)card->sign(QStringLiteral("c"), std::move(document), SignOptions{});

    ASSERT_EQ(h.fake->starts.size(), 1u);
    const auto& record = h.fake->starts.front();
    EXPECT_EQ(record.options.value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    EXPECT_EQ(record.options.value(QStringLiteral("level")).toString(), QStringLiteral("b-b"));
    EXPECT_EQ(record.options.value(QStringLiteral("packaging")).toString(), QStringLiteral("enveloped"));
    EXPECT_FALSE(record.options.contains(QStringLiteral("tsaUrl")));
    EXPECT_FALSE(record.options.contains(QStringLiteral("visualSignature")));
}

TEST(SeamMapping, TypedSignOptionsOverrideCollidingExtraKeys)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);

    SignOptions options; // typed default: pades
    options.extra.insert(QStringLiteral("format"), QStringLiteral("evil"));
    FdHandle document{::open("/dev/null", O_RDONLY | O_CLOEXEC)};
    (void)card->sign(QStringLiteral("c"), std::move(document), options);

    EXPECT_EQ(h.fake->starts.front().options.value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
}

TEST(SeamMapping, PinVerbsMapToWireTokens)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);

    (void)card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    (void)card->managePin(QStringLiteral("user:0x86"), PinVerb::Unblock);
    (void)card->managePin(QStringLiteral("sign:0x87"), PinVerb::ActivatePin);

    ASSERT_EQ(h.fake->starts.size(), 3u);
    EXPECT_EQ(h.fake->starts[0].method, OperationRequest::Method::ManagePin);
    EXPECT_EQ(h.fake->starts[0].pinId, QStringLiteral("user:0x86"));
    EXPECT_EQ(h.fake->starts[0].verb, QStringLiteral("change"));
    EXPECT_TRUE(h.fake->starts[0].options.isEmpty()); // no secrets, no options on this wire
    EXPECT_EQ(h.fake->starts[1].verb, QStringLiteral("unblock"));
    EXPECT_EQ(h.fake->starts[2].verb, QStringLiteral("activate_pin"));
    EXPECT_EQ(h.fake->starts[2].pinId, QStringLiteral("sign:0x87"));
}

TEST(SeamMapping, ReadMethodsMapToTheirRequests)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);

    (void)card->readIdentity();
    (void)card->getPhoto();
    (void)card->readCertificates();
    (void)card->listCredentials();
    (void)card->activateSigningKey();

    ASSERT_EQ(h.fake->starts.size(), 5u);
    EXPECT_EQ(h.fake->starts[0].method, OperationRequest::Method::ReadIdentity);
    EXPECT_EQ(h.fake->starts[1].method, OperationRequest::Method::GetPhoto);
    EXPECT_EQ(h.fake->starts[2].method, OperationRequest::Method::ReadCertificates);
    EXPECT_EQ(h.fake->starts[3].method, OperationRequest::Method::ListCredentials);
    EXPECT_EQ(h.fake->starts[4].method, OperationRequest::Method::ActivateSigningKey);
}

// ---- entry refusal --------------------------------------------------------------

TEST(SeamEntryRefusal, MintsAFailedOperationWithQueuedFinished)
{
    ClientOnFake h;
    h.fake->nextOperationId.clear();
    h.fake->entryError.errorCode = ErrorCode::CapabilityMissing;
    h.fake->entryError.wireName = QStringLiteral("UnsupportedOnThisCard");
    h.fake->entryError.message = QStringLiteral("no photo on this card");

    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr); // never nullptr — the scrub's uniform failure surface

    // Polled state is terminal the moment the minting call returns...
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CapabilityMissing);
    EXPECT_EQ(op->callError(), CallError::None);
    EXPECT_EQ(op->messageFallback(), QStringLiteral("no photo on this card"));

    // ...but the signal is QUEUED so this late connect still receives it.
    int finishedCount = 0;
    QObject::connect(op, &AgentOperation::finished, op, [&finishedCount]() { ++finishedCount; });
    EXPECT_EQ(finishedCount, 0);
    spinEventLoop();
    EXPECT_EQ(finishedCount, 1);
}

TEST(SeamEntryRefusal, CallErrorRefusalsSurfaceOnCallError)
{
    ClientOnFake h;
    h.fake->nextOperationId.clear();
    h.fake->entryError.callError = CallError::InvalidArguments;
    h.fake->entryError.wireName = QStringLiteral("UnknownCredential");

    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->managePin(QStringLiteral("stale:id"), PinVerb::Change);
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->callError(), CallError::InvalidArguments);
    EXPECT_EQ(op->errorCode(), ErrorCode::None);
}

// ---- live results and terminal recovery ------------------------------------------

TEST(SeamOperation, LiveResultThenFinishedYieldsPayloadAndSyncFinished)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();
    ASSERT_FALSE(op->isFinished());

    int finishedCount = 0;
    QObject::connect(op, &AgentOperation::finished, op, [&finishedCount]() { ++finishedCount; });

    OperationListener* listener = h.fake->soleOperationListener();
    ASSERT_NE(listener, nullptr);

    OperationPayload payload;
    payload.kind = OperationKind::Identity;
    FieldGroup group;
    group.key = QStringLiteral("personal");
    Field field;
    field.key = QStringLiteral("surname");
    field.value = QStringLiteral("Doe");
    group.fields.append(field);
    payload.identity.append(group);
    listener->onResult(std::move(payload));

    listener->onFinished(OperationStatus::Ok, ErrorCode::None, QString(), QString());
    // Live terminal: the consumer is connected — synchronous emit, no spin.
    EXPECT_EQ(finishedCount, 1);
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    ASSERT_EQ(op->identityResult().size(), 1);
    EXPECT_EQ(op->identityResult().first().fields.first().value, QStringLiteral("Doe"));
}

TEST(SeamOperation, LostResultIsRecoveredThroughTheSeamPull)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    h.fake->recover = []() -> std::optional<OperationPayload> {
        OperationPayload payload;
        payload.kind = OperationKind::Certificates;
        CertificateInfo info;
        info.id = QStringLiteral("cert1");
        payload.certificates.append(info);
        return payload;
    };
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readCertificates();

    OperationListener* listener = h.fake->soleOperationListener();
    listener->onFinished(OperationStatus::Ok, ErrorCode::None, QString(), QString());

    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    ASSERT_EQ(op->certificatesResult().size(), 1);
    EXPECT_EQ(op->certificatesResult().first().id, QStringLiteral("cert1"));
}

TEST(SeamOperation, UnrecoverableLostResultFailsLoud)
{
    // Finished Ok with no delivered result and nothing to recover must NOT
    // masquerade as a silent empty success (the lifted contract).
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();

    h.fake->soleOperationListener()->onFinished(OperationStatus::Ok, ErrorCode::None, QString(), QString());

    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError);
}

TEST(SeamOperation, CredentialsSoftFailKeepsRealTerminalWithRecoveredResult)
{
    // A credentials attempt that finishes Error (invalidPin) still delivers
    // its result; the recovery pull must run for the ERROR terminal too and
    // the REAL terminal (not CommunicationError) must be reported.
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    h.fake->recover = []() -> std::optional<OperationPayload> {
        OperationPayload payload;
        payload.kind = OperationKind::Credentials;
        payload.pinResult.outcome = CredentialOutcome::InvalidPin;
        payload.pinResult.retriesLeft = 2;
        return payload;
    };
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);

    h.fake->soleOperationListener()->onFinished(OperationStatus::Error, ErrorCode::CredentialWrong, QString(),
                                                QString());

    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CredentialWrong); // NOT rewritten to CommunicationError
    EXPECT_EQ(op->pinResult().outcome, CredentialOutcome::InvalidPin);
    ASSERT_TRUE(op->pinResult().retriesLeft.has_value());
    EXPECT_EQ(*op->pinResult().retriesLeft, 2);
}

TEST(SeamOperation, CtorRecoveryTerminalizesAnAlreadyFinishedOperation)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    h.fake->terminal = TerminalSnapshot{true, OperationStatus::Ok, ErrorCode::None};
    h.fake->recover = []() -> std::optional<OperationPayload> {
        OperationPayload payload;
        payload.kind = OperationKind::Identity;
        FieldGroup group;
        group.key = QStringLiteral("g");
        Field field;
        field.key = QStringLiteral("f");
        field.value = QStringLiteral("v");
        group.fields.append(field);
        payload.identity.append(group);
        return payload;
    };
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();

    // Polled state is already terminal when the minting call returns; the
    // signal arrives queued for the late-connecting consumer.
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    int finishedCount = 0;
    QObject::connect(op, &AgentOperation::finished, op, [&finishedCount]() { ++finishedCount; });
    spinEventLoop();
    EXPECT_EQ(finishedCount, 1);
    EXPECT_EQ(op->identityResult().size(), 1);
}

TEST(SeamOperation, PhaseUpdatesAreStoredAndRelayed)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();

    OperationPhase seenPhase = OperationPhase::Created;
    double seenProgress = -1.0;
    QObject::connect(op, &AgentOperation::phaseChanged, op, [&](OperationPhase phase, double progress) {
        seenPhase = phase;
        seenProgress = progress;
    });

    h.fake->soleOperationListener()->onPhaseChanged(OperationPhase::Reading, 0.5);
    EXPECT_EQ(seenPhase, OperationPhase::Reading);
    EXPECT_EQ(seenProgress, 0.5);
    EXPECT_EQ(op->phase(), OperationPhase::Reading);
    EXPECT_EQ(op->progress(), 0.5);
}

TEST(SeamOperation, CancelForwardsToTheSeam)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/7");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();
    op->cancel();
    ASSERT_EQ(h.fake->cancelled.size(), 1u);
    EXPECT_EQ(h.fake->cancelled.front(), QStringLiteral("/op/7"));
}

TEST(SeamOperation, PhotosAreTakenOnce)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->getPhoto();

    OperationPayload payload;
    payload.kind = OperationKind::Photo;
    PhotoItem item;
    item.key = QStringLiteral("personal:photo");
    item.fd = FdHandle{::open("/dev/null", O_RDONLY | O_CLOEXEC)};
    payload.photos.push_back(std::move(item));
    OperationListener* listener = h.fake->soleOperationListener();
    listener->onResult(std::move(payload));
    listener->onFinished(OperationStatus::Ok, ErrorCode::None, QString(), QString());

    std::vector<PhotoItem> photos = op->takePhotos();
    ASSERT_EQ(photos.size(), 1u);
    EXPECT_EQ(photos[0].key, QStringLiteral("personal:photo"));
    EXPECT_TRUE(photos[0].fd.valid());
    EXPECT_TRUE(op->takePhotos().empty()); // move-out semantics: gone after the first take
}

// ---- availability sweep -----------------------------------------------------------

TEST(SeamAvailability, AgentVanishTerminalizesInFlightOperationsLoudly)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();

    bool finishedFired = false;
    OperationStatus statusAtFinish = OperationStatus::Ok;
    ErrorCode codeAtFinish = ErrorCode::None;
    CallError callAtFinish = CallError::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        finishedFired = true;
        statusAtFinish = op->status();
        codeAtFinish = op->errorCode();
        callAtFinish = op->callError();
    });

    bool sawUnavailable = false;
    QObject::connect(h.client.get(), &AgentClient::availabilityChanged, h.client.get(),
                     [&](bool available) { sawUnavailable = !available; });

    // The agent drops off the transport: the sweep must fire finished
    // SYNCHRONOUSLY (the operation is deleted with its card right after).
    h.fake->registry->onServiceUnregistered();

    EXPECT_TRUE(finishedFired);
    EXPECT_EQ(statusAtFinish, OperationStatus::Cancelled);
    EXPECT_EQ(codeAtFinish, ErrorCode::CommunicationError);
    EXPECT_EQ(callAtFinish, CallError::AgentUnavailable);
    EXPECT_TRUE(sawUnavailable);
    EXPECT_FALSE(h.client->isAvailable());
    EXPECT_TRUE(h.client->readers().isEmpty());
    EXPECT_EQ(h.client->card(QStringLiteral("/card/0")), nullptr);
}

TEST(SeamAvailability, CardRemovalTerminalizesItsOperations)
{
    ClientOnFake h;
    h.fake->nextOperationId = QStringLiteral("/op/1");
    AgentCard* card = h.client->card(QStringLiteral("/card/0"));
    AgentOperation* op = card->readIdentity();

    bool finishedFired = false;
    ErrorCode codeAtFinish = ErrorCode::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        finishedFired = true;
        codeAtFinish = op->errorCode();
    });

    QString changedId;
    QObject::connect(h.client.get(), &AgentClient::cardChanged, h.client.get(),
                     [&](const QString& objectId) { changedId = objectId; });

    h.fake->registry->onCardRemoved(QStringLiteral("/card/0"));

    EXPECT_TRUE(finishedFired);
    EXPECT_EQ(codeAtFinish, ErrorCode::CardRemoved);
    EXPECT_EQ(changedId, QStringLiteral("/card/0"));
    EXPECT_EQ(h.client->card(QStringLiteral("/card/0")), nullptr);
    EXPECT_TRUE(h.client->isAvailable()); // the agent itself is still there
}

// ---- certificateDer ---------------------------------------------------------------

TEST(SeamCertificateDer, DeliversDerAsynchronously)
{
    ClientOnFake h;
    AgentOperation* op = h.client->certificateDer(QStringLiteral("/reader/0"), QStringLiteral("certid"));
    ASSERT_NE(op, nullptr);
    EXPECT_FALSE(op->isFinished());

    ASSERT_EQ(h.fake->derRequests.size(), 1u);
    const auto& request = h.fake->derRequests.front();
    EXPECT_EQ(request.readerId, QStringLiteral("/reader/0"));
    EXPECT_EQ(request.certId, QStringLiteral("certid"));
    ASSERT_NE(request.listener, nullptr);

    int finishedCount = 0;
    QObject::connect(op, &AgentOperation::finished, op, [&finishedCount]() { ++finishedCount; });

    DerOutcome outcome;
    outcome.der = QByteArray("\x30\x82", 2);
    request.listener->onCertificateDer(request.token, std::move(outcome));

    EXPECT_EQ(finishedCount, 1);
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_EQ(op->certificateDerResult(), QByteArray("\x30\x82", 2));
}

TEST(SeamCertificateDer, UnavailableAgentFailsTheOperation)
{
    auto owned = std::make_unique<FakeTransportSeam>();
    owned->available = false;
    FakeTransportSeam* fake = owned.get();
    std::unique_ptr<AgentClient> client{ClientTestAccess::create(std::move(owned))};

    AgentOperation* op = client->certificateDer(QStringLiteral("/reader/0"), QStringLiteral("certid"));
    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->callError(), CallError::AgentUnavailable);
    EXPECT_TRUE(fake->derRequests.empty()); // never touched the transport

    int finishedCount = 0;
    QObject::connect(op, &AgentOperation::finished, op, [&finishedCount]() { ++finishedCount; });
    spinEventLoop();
    EXPECT_EQ(finishedCount, 1); // queued, like every pre-return terminal
}

TEST(SeamCertificateDer, FailedFetchCarriesTheMappedError)
{
    ClientOnFake h;
    AgentOperation* op = h.client->certificateDer(QStringLiteral("/reader/0"), QStringLiteral("nope"));
    const auto& request = h.fake->derRequests.front();

    DerOutcome outcome;
    outcome.error.errorCode = ErrorCode::KeyNotFound;
    outcome.error.wireName = QStringLiteral("KeyNotFound");
    request.listener->onCertificateDer(request.token, std::move(outcome));

    EXPECT_TRUE(op->isFinished());
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::KeyNotFound);
}

// ---- refresh discovery --------------------------------------------------------------

TEST(SeamRefresh, RefreshReconcilesAvailabilityAndRegistry)
{
    auto owned = std::make_unique<FakeTransportSeam>();
    owned->available = false;
    FakeTransportSeam* fake = owned.get();
    std::unique_ptr<AgentClient> client{ClientTestAccess::create(std::move(owned))};
    EXPECT_FALSE(client->isAvailable());

    // The agent appears without a liveness notification (a missed signal):
    // a manual refresh must reconcile from the transport itself.
    fake->available = true;
    fake->snapshot = oneReaderOneCard();

    bool sawAvailable = false;
    int readersChangedCount = 0;
    QObject::connect(client.get(), &AgentClient::availabilityChanged, client.get(),
                     [&](bool available) { sawAvailable = available; });
    QObject::connect(client.get(), &AgentClient::readersChanged, client.get(),
                     [&readersChangedCount]() { ++readersChangedCount; });

    client->refreshDiscovery();

    EXPECT_TRUE(sawAvailable);
    EXPECT_TRUE(client->isAvailable());
    EXPECT_GE(readersChangedCount, 1);
    EXPECT_EQ(client->readers().size(), 1);
}
