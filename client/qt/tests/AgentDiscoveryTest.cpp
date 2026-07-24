// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentClient ObjectManager discovery + live add/remove + availability, over a
// real DBusTransport + FakeAgent. Adapted from the lifted KDE suite of the
// same name to the scrubbed public API: AgentClient's production constructor
// no longer takes a QDBusConnection (built via ClientTestAccess instead);
// `finished()` carries no arguments anymore (poll status()/errorCode() after
// it fires); the KDE convenience finders (firstReaderWithCard/
// cardWithCapability/readersSortedByPath/readerWithCardByName) were
// deliberately not lifted — they are pure functions over `readers()`, so this
// file re-adds them locally exactly as any future consumer would.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentClient.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/AgentReader.h>

#include "fakes/ClientOnHarness.h"
#include "fakes/TestBus.h"

#include <QSignalSpy>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <unistd.h>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {

// The KDE lift's convenience finders, NOT part of the scrubbed public API:
// readers() is a pure sorted view, and consumers re-add whatever finder
// helpers they need on top of it where those items land. readers() is
// itself deterministically id-sorted now, so no separate "sorted" accessor
// is needed.

AgentReader* firstReaderWithCard(AgentClient& client)
{
    for (AgentReader* reader : client.readers()) {
        if (AgentCard* card = reader->card()) {
            Q_UNUSED(card)
            return reader;
        }
    }
    return nullptr;
}

AgentCard* cardWithCapability(AgentClient& client, std::uint32_t cap)
{
    for (AgentReader* reader : client.readers()) {
        if (AgentCard* card = reader->card()) {
            if (has(capabilityBits(card->capabilities()), cap)) {
                return card;
            }
        }
    }
    return nullptr;
}

AgentReader* readerWithCardByName(AgentClient& client, const QString& name)
{
    for (AgentReader* reader : client.readers()) {
        if (reader->name() == name && reader->card() != nullptr) {
            return reader;
        }
    }
    return nullptr;
}

} // namespace

TEST(AgentDiscovery, ListsReaderAndCardWhenAgentAlreadyPresent)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData | Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    ASSERT_EQ(client->readers().size(), 1);
    AgentReader* reader = client->readers().constFirst();
    EXPECT_EQ(reader->name(), QStringLiteral("Fake"));
    EXPECT_TRUE(reader->hasCard());
    EXPECT_EQ(reader->cardId(), h.cardPath());

    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(uiStateFor(capabilityBits(card->capabilities())), UiState::Hybrid);
}

TEST(AgentDiscovery, LiveCardInsertEmitsCardChanged)
{
    FakeAgent::Config cfg;
    cfg.hasCard = false; // start with no card
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(client->card(h.cardPath()), nullptr);

    QSignalSpy cardSpy(client.get(), &AgentClient::cardChanged);
    h.setCardPresent(true);

    ASSERT_TRUE(waitFor([&]() { return client->card(h.cardPath()) != nullptr; }));
    EXPECT_GE(cardSpy.count(), 1);
    EXPECT_EQ(uiStateFor(capabilityBits(client->card(h.cardPath())->capabilities())), UiState::PkiOnly);
}

// Covers onServiceUnregistered: when the agent's bus name vanishes, the client
// reports availabilityChanged(false), clears its reader/card registry, and
// re-emits readersChanged so consumers can drop everything.
TEST(AgentDiscovery, ServiceLossClearsRegistryAndReportsUnavailable)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(client->readers().size(), 1);
    ASSERT_NE(client->card(h.cardPath()), nullptr);

    QSignalSpy availSpy(client.get(), &AgentClient::availabilityChanged);
    QSignalSpy readersSpy(client.get(), &AgentClient::readersChanged);

    h.unregisterService();

    ASSERT_TRUE(waitFor([&]() { return !client->isAvailable(); }));
    EXPECT_TRUE(client->readers().isEmpty());
    EXPECT_EQ(client->card(h.cardPath()), nullptr);
    ASSERT_GE(availSpy.count(), 1);
    EXPECT_FALSE(availSpy.constLast().constFirst().toBool());
    EXPECT_GE(readersSpy.count(), 1);
}

TEST(AgentDiscovery, LiveCardRemoveDropsCard)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_NE(client->card(h.cardPath()), nullptr);

    QSignalSpy cardSpy(client.get(), &AgentClient::cardChanged);
    h.setCardPresent(false);

    ASSERT_TRUE(waitFor([&]() { return client->card(h.cardPath()) == nullptr; }));
    EXPECT_GE(cardSpy.count(), 1);
}

// if the agent vanishes mid-operation, no Operation1.Finished arrives.
// The client must sweep every live op and terminalize it loudly so a consumer
// (here a downstream lambda standing in for an async job awaiting the result)
// sees finished + a failure rather than hanging forever.
TEST(AgentDiscovery, AgentDeathTerminalizesLiveOperationsLoudly)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // never fires on its own within the test
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    int fd = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    AgentOperation* op = card->sign(QStringLiteral("certid"), FdHandle{fd}, SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    // Downstream consumer stand-in: a non-Ok finished is a failure. The op is
    // destroyed by clearRegistry right after terminalization, so every polled
    // getter is read from INSIDE the slot — never deref `op` post-loss.
    bool finishedSeen = false;
    bool downstreamFailed = false;
    OperationStatus seenStatus = OperationStatus::Ok;
    ErrorCode seenCode = ErrorCode::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        finishedSeen = true;
        seenStatus = op->status();
        seenCode = op->errorCode();
        if (seenStatus != OperationStatus::Ok) {
            downstreamFailed = true;
        }
    });

    h.unregisterService();

    ASSERT_TRUE(waitFor([&]() { return finishedSeen; }))
        << "agent death must terminalize the live operation, not leave it hanging";
    EXPECT_TRUE(downstreamFailed);
    EXPECT_NE(seenStatus, OperationStatus::Ok);
    EXPECT_EQ(seenCode, ErrorCode::CommunicationError);
}

// a CARD-ONLY removal (the agent pulls the card but stays on the bus, so
// no Operation1.Finished arrives) must sweep + terminalize every in-flight op on
// the going-away card BEFORE deleting it — otherwise destroying the QObject-
// parented AgentOperation auto-disconnects its consumer WITHOUT firing finished,
// and a consumer waiting on it hangs forever. The terminal must be Cancelled /
// CardRemoved, fired exactly once.
TEST(AgentDiscovery, CardRemovalTerminalizesInFlightOpsLoudly)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // never fires on its own within the test
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    int fd = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    AgentOperation* op = card->sign(QStringLiteral("certid"), FdHandle{fd}, SignOptions{});
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    int finishedCount = 0;
    OperationStatus seenStatus = OperationStatus::Ok;
    ErrorCode seenCode = ErrorCode::None;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        ++finishedCount;
        seenStatus = op->status();
        seenCode = op->errorCode();
    });

    // Card-only pull: InterfacesRemoved(Card1), agent stays on the bus.
    h.setCardPresent(false);

    ASSERT_TRUE(waitFor([&]() { return finishedCount > 0; }))
        << "card removal must terminalize the in-flight op, not leave it hanging";
    EXPECT_EQ(finishedCount, 1) << "finished must fire exactly once (emitFinishedOnce idempotency)";
    EXPECT_EQ(seenStatus, OperationStatus::Cancelled);
    EXPECT_EQ(seenCode, ErrorCode::CardRemoved);
    // The card proxy is gone.
    EXPECT_EQ(client->card(h.cardPath()), nullptr);
}

// C1: re-emitted InterfacesAdded for an ALREADY-tracked card path must UPDATE
// the live card from the new props, not silently drop them.
TEST(AgentDiscovery, ReAddedCardUpdatesCapabilitiesInPlace)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}));

    const auto next = static_cast<unsigned>(Cap::IdentityData | Cap::Pki);
    h.reAddCardWithCapabilities(next);

    ASSERT_TRUE(waitFor([&]() {
        AgentCard* c = client->card(h.cardPath());
        return c != nullptr && capabilityBits(c->capabilities()) == next;
    })) << "a re-emitted InterfacesAdded with changed caps must upgrade the existing card";
    // Same object, not a fresh one (the early-return path updates in place).
    EXPECT_EQ(client->card(h.cardPath()), card);
}

// refreshDiscovery(): a card the agent exported but whose InterfacesAdded the
// client never received (the deferred-publish window, or a dropped signal)
// leaves the reader claiming a card the client cannot resolve. A manual refresh
// re-runs GetManagedObjects and recovers it — no re-seat, no new wire.
TEST(AgentDiscovery, RefreshDiscoveryRecoversUnannouncedCard)
{
    FakeAgent::Config cfg;
    cfg.hasCard = false; // discovered empty
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(firstReaderWithCard(*client), nullptr);

    // The agent registers the Card1 and flips the reader to HasCard=true, but the
    // Card1 InterfacesAdded is suppressed: the reader claims a card the client
    // cannot see yet.
    h.exportCardSilently();
    ASSERT_TRUE(waitFor([&]() {
        AgentReader* r = client->reader(h.readerPath());
        return r != nullptr && r->hasCard();
    })) << "the reader must report HasCard from the PropertiesChanged";
    // The card is genuinely unresolved: the reader has one, but no AgentCard.
    EXPECT_EQ(client->card(h.cardPath()), nullptr);
    EXPECT_EQ(firstReaderWithCard(*client), nullptr);

    // The manual refresh re-runs GetManagedObjects (which DOES return the card)
    // and picks it up.
    client->refreshDiscovery();
    ASSERT_TRUE(waitFor([&]() { return client->card(h.cardPath()) != nullptr; }))
        << "refreshDiscovery must recover the card GetManagedObjects reports";
    AgentReader* r = firstReaderWithCard(*client);
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->cardId(), h.cardPath());
}

// refreshDiscovery() must RECONCILE the registry against GetManagedObjects, not
// clear-and-rebuild it: an object the agent still reports unchanged keeps its
// identity (same pointer) across a refresh. Otherwise every refresh destroys and
// recreates every AgentCard, so a consumer bound to a card is forced to re-read
// an identical card — the collateral flicker a refresh on one widget inflicts on
// all the others.
TEST(AgentDiscovery, RefreshDiscoveryPreservesUnchangedObjectIdentities)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    AgentReader* reader = client->reader(h.readerPath());
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(reader, nullptr);
    ASSERT_NE(card, nullptr);

    // A refresh over an UNCHANGED tree reconciles in place.
    client->refreshDiscovery();

    EXPECT_EQ(client->reader(h.readerPath()), reader) << "an unchanged reader must survive a refresh with its identity";
    EXPECT_EQ(client->card(h.cardPath()), card) << "an unchanged card must survive a refresh with its identity";
    EXPECT_EQ(card->capabilities(), (QStringList{QStringLiteral("Pki")}));
    EXPECT_EQ(client->readers().size(), 1);
}

// A refresh that finds a genuinely removed card (present in the registry, gone
// from GetManagedObjects) must drop it AND terminalize any in-flight op on it —
// the same loud-terminalization contract as a live InterfacesRemoved, so a
// consumer never hangs on a card the reconcile deleted.
TEST(AgentDiscovery, RefreshReconcileDropsGoneCardAndTerminalizesOps)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 60000; // never self-fires within the test
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);

    int fd = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    AgentOperation* op = card->sign(QStringLiteral("certid"), FdHandle{fd}, SignOptions{});
    ASSERT_NE(op, nullptr);

    int finishedCount = 0;
    OperationStatus seenStatus = OperationStatus::Ok;
    QObject::connect(op, &AgentOperation::finished, op, [&]() {
        ++finishedCount;
        seenStatus = op->status();
    });

    // The card leaves the tree WITHOUT a live InterfacesRemoved (a dropped
    // signal): GetManagedObjects no longer returns it. A refresh must reconcile
    // it away — and terminalize the in-flight op exactly like a live removal.
    h.dropCardSilently();
    client->refreshDiscovery();

    EXPECT_EQ(client->card(h.cardPath()), nullptr) << "refresh must drop a card GetManagedObjects no longer reports";
    ASSERT_TRUE(waitFor([&]() { return finishedCount > 0; }))
        << "a reconcile-removed card must terminalize its in-flight op, not leak it";
    EXPECT_EQ(finishedCount, 1);
    EXPECT_EQ(seenStatus, OperationStatus::Cancelled);
}

// firstReaderWithCard()/cardWithCapability() (this file's local re-adds)
// centralize "first reader holding a usable card" with deterministic
// (id-sorted) ordering — readers() itself is sorted now.
TEST(AgentDiscovery, FirstReaderWithCardAndCapabilityFilter)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    AgentReader* r = firstReaderWithCard(*client);
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->id(), h.readerPath());
    EXPECT_EQ(r->cardId(), h.cardPath());

    // Cap filter: the PKI card matches Cap::Pki but not Cap::IdentityData.
    AgentCard* pki = cardWithCapability(*client, Cap::Pki);
    ASSERT_NE(pki, nullptr);
    EXPECT_EQ(pki->id(), h.cardPath());
    EXPECT_EQ(cardWithCapability(*client, Cap::IdentityData), nullptr);
}

TEST(AgentDiscovery, FirstReaderWithCardNullWhenNoCard)
{
    FakeAgent::Config cfg;
    cfg.hasCard = false;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    EXPECT_EQ(firstReaderWithCard(*client), nullptr);
    EXPECT_EQ(cardWithCapability(*client, Cap::Pki), nullptr);
}

// readers(): deterministic lexicographic id order, independent of hash
// iteration. reader/0 "Fake" precedes reader/1 "Fake2".
TEST(AgentDiscovery, ReadersAreSortedById)
{
    FakeAgent::Config cfg;
    cfg.hasCard = true;
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());
    ASSERT_EQ(client->readers().size(), 1);

    // Bring up a SECOND reader (reader/1 "Fake2"), initially empty.
    h.emitReaderArrivesEmpty();
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 2; }));

    const QList<AgentReader*> ordered = client->readers();
    ASSERT_EQ(ordered.size(), 2);
    EXPECT_EQ(ordered.at(0)->name(), QStringLiteral("Fake"));
    EXPECT_EQ(ordered.at(1)->name(), QStringLiteral("Fake2"));
    // Ids are sorted, so reader/0 < reader/1 always holds.
    EXPECT_LT(ordered.at(0)->id(), ordered.at(1)->id());
}

// readerWithCardByName() (this file's local re-add): matches on the friendly
// Name AND requires a resolvable card. reader/0 "Fake" has a card; reader/1
// "Fake2" is present but empty; an unknown name never matches.
TEST(AgentDiscovery, ReaderWithCardByNameResolvesAndFiltersEmpty)
{
    FakeAgent::Config cfg;
    cfg.hasCard = true; // reader/0 "Fake" holds card/0
    cfg.capabilities = Cap::Pki;
    Harness h(cfg);

    auto client = makeClient(h);
    ASSERT_TRUE(client->isAvailable());

    // reader/1 "Fake2" arrives EMPTY (no card).
    h.emitReaderArrivesEmpty();
    ASSERT_TRUE(waitFor([&]() { return client->readers().size() == 2; }));

    AgentReader* fake = readerWithCardByName(*client, QStringLiteral("Fake"));
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->name(), QStringLiteral("Fake"));
    EXPECT_EQ(fake->cardId(), h.cardPath());

    // Present but card-less: must NOT resolve (drives the "bound reader empty"
    // waiting state at the handler level).
    EXPECT_EQ(readerWithCardByName(*client, QStringLiteral("Fake2")), nullptr);
    // Unknown name never matches.
    EXPECT_EQ(readerWithCardByName(*client, QStringLiteral("Nope")), nullptr);
}
