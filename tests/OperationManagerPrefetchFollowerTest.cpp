// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// A client's ReadIdentity that queues behind the background read of the SAME
// card gets the field groups the background read has already produced, then the
// rest as they arrive, then the Result from the cache -- and the card is read
// once. The reader is scripted: the background read stands at a gate before each
// group, so every assertion is made while it is still reading.
//
// Every wait is bounded and fails with a message; nothing here can hang.
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/ReadIdentityOperation.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>

#include "fakes/FakePrompter.h"
#include "operations/PrefetchIdentityOperation.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

constexpr auto kBound = 5s;
constexpr const char* kCard = "card-F";

class Gate
{
public:
    void release()
    {
        {
            std::lock_guard lock(m_mutex);
            m_open = true;
        }
        m_cv.notify_all();
    }
    [[nodiscard]] bool wait()
    {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, kBound, [this] { return m_open; });
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_open{false};
};

GroupSnapshot groupNamed(int index)
{
    const std::string key = "g" + std::to_string(index);
    return {key, "group." + key, key, {{"f", "field.f", "F", FieldType::Text, "VALUE-" + key, {}}}};
}

CardReadSnapshot fullSnapshot()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    for (int i = 1; i <= 3; ++i) {
        snap.groups.push_back(groupNamed(i));
    }
    return snap;
}

// The first read (the background one) stands at a gate before each of its three
// groups; every later read (a client's own) streams all three at once. Only the
// first call is gated, so "the card was read once" is `reads == 1`.
class ScriptedReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken token,
                     GroupReadCallback onGroup = {}) override
    {
        const int call = reads.fetch_add(1);
        if (call == 0) {
            const struct Returns
            {
                std::atomic<bool>& flag;
                ~Returns()
                {
                    flag.store(true);
                }
            } returns{returned};
            for (int k = 0; k < 3; ++k) {
                reached.store(k + 1);
                if (!gate[k].wait()) {
                    return {ReadOutcome::Status::CommunicationError, std::nullopt, "gate timed out"};
                }
                if (token.isCancelled()) {
                    return {ReadOutcome::Status::Cancelled, std::nullopt, ""};
                }
                if (k == failAtGate) {
                    return {ReadOutcome::Status::CommunicationError, std::nullopt, "scripted failure"};
                }
                if (onGroup) {
                    onGroup(groupNamed(k + 1));
                }
            }
            return {ReadOutcome::Status::Ok, fullSnapshot(), ""};
        }
        for (int k = 1; k <= 3; ++k) {
            if (onGroup) {
                onGroup(groupNamed(k));
            }
        }
        return {ReadOutcome::Status::Ok, fullSnapshot(), ""};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }

    Gate gate[3];
    std::atomic<int> reads{0};
    std::atomic<int> reached{0};       ///< how many gates the first read has arrived at
    std::atomic<bool> returned{false}; ///< the first read has returned
    int failAtGate{-1};                ///< the first read fails at this gate instead of emitting its group
};

class EventLog
{
public:
    void add(std::string event)
    {
        {
            std::lock_guard lock(m_mutex);
            m_events.push_back(std::move(event));
        }
        m_cv.notify_all();
    }
    [[nodiscard]] std::vector<std::string> events() const
    {
        std::lock_guard lock(m_mutex);
        return m_events;
    }
    [[nodiscard]] bool waitFor(const std::function<bool(const std::vector<std::string>&)>& pred) const
    {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, kBound, [&] { return pred(m_events); });
    }
    [[nodiscard]] bool waitForCount(std::size_t n) const
    {
        return waitFor([n](const std::vector<std::string>& e) { return e.size() >= n; });
    }

private:
    mutable std::mutex m_mutex;
    mutable std::condition_variable m_cv;
    std::vector<std::string> m_events;
};

std::string finished(OperationStatus status, ErrorCode code)
{
    return "F:" + std::to_string(static_cast<std::uint32_t>(status)) + ":" +
           std::to_string(static_cast<std::uint32_t>(code));
}

// What the channel did when it was destroyed, for the tests that follow an op's
// death: the thread it died on and how many have died.
struct Deaths
{
    std::mutex mutex;
    std::vector<std::thread::id> threads;
    [[nodiscard]] std::size_t count()
    {
        std::lock_guard lock(mutex);
        return threads.size();
    }
};

class RecordingChannel final : public OperationChannel
{
public:
    RecordingChannel(std::shared_ptr<EventLog> log, bool awaits, std::shared_ptr<Deaths> deaths = {},
                     std::function<void(const std::string&)> onGroup = {})
        : m_log(std::move(log)), m_awaits(awaits), m_deaths(std::move(deaths)), m_onGroup(std::move(onGroup))
    {}
    ~RecordingChannel() override
    {
        if (m_deaths) {
            std::lock_guard lock(m_deaths->mutex);
            m_deaths->threads.push_back(std::this_thread::get_id());
        }
    }
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus status, ErrorCode code, std::string_view, std::string_view) noexcept override
    {
        m_log->add(finished(status, code));
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        m_log->add("R");
        return true;
    }
    void emitGroup(const GroupSnapshot& group) noexcept override
    {
        m_log->add("G:" + group.groupKey);
        if (m_onGroup) {
            m_onGroup(group.groupKey);
        }
    }
    [[nodiscard]] bool groupsAwaitObserver() const noexcept override
    {
        return m_awaits;
    }

private:
    std::shared_ptr<EventLog> m_log;
    bool m_awaits;
    std::shared_ptr<Deaths> m_deaths;
    std::function<void(const std::string&)> m_onGroup;
};

std::unique_ptr<CardSessionHolder> makeHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver));
}

// Everything one scenario needs. The manager is the LAST member, so its workers
// are joined before the reader, the caches and the holder they use are freed.
struct Rig
{
    std::unique_ptr<CardSessionHolder> holder = makeHolder();
    ScriptedReader reader;
    CardReadCache readCache;
    CredentialCache credentials;
    PromptSerializer serializer;
    NullCredentialDepositor depositor;
    FakePrompter prompter;
    std::shared_ptr<EventLog> log = std::make_shared<EventLog>();
    std::shared_ptr<Deaths> deaths = std::make_shared<Deaths>();
    std::unique_ptr<OperationManager> mgr = std::make_unique<OperationManager>();

    static ObjectId readerId()
    {
        return ObjectId{1};
    }

    void startPrefetch(const std::string& cardKey = kCard)
    {
        mgr->setBackgroundForTest(readerId(),
                                  std::make_unique<PrefetchIdentityOperation>(PrefetchIdentityOperation::Deps{
                                      .holder = holder.get(),
                                      .reader = reader,
                                      .readCache = readCache,
                                      .cardKey = cardKey,
                                      .readerName = "FakeReader",
                                      .onCardType = {},
                                  }),
                                  0s);
    }

    // The client op is queued behind the running background read.
    std::shared_ptr<OperationState> queueClient(OperationId id, bool awaitsObserver, const std::string& cardKey = kCard,
                                                std::function<void(const std::string&)> onGroup = {})
    {
        auto state = std::make_shared<OperationState>();
        auto op = std::make_unique<ReadIdentityOperation>(
            std::make_unique<RecordingChannel>(log, awaitsObserver, deaths, std::move(onGroup)),
            ReadIdentityOperation::Deps{.holder = holder.get(),
                                        .reader = reader,
                                        .depositor = depositor,
                                        .prompter = prompter,
                                        .serializer = serializer,
                                        .credentials = credentials,
                                        .readCache = readCache,
                                        .cardKey = cardKey,
                                        .readerName = "FakeReader",
                                        .requester = "test",
                                        .artifact = "identity",
                                        .onCardType = {}},
            state);
        mgr->enqueueTrackedForTest(readerId(), std::move(op), id, CallerToken{":1.1"});
        return state;
    }

    [[nodiscard]] bool waitReached(int gates) const
    {
        const auto deadline = std::chrono::steady_clock::now() + kBound;
        while (reader.reached.load() < gates) {
            if (std::chrono::steady_clock::now() > deadline) {
                return false;
            }
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }
};

using Events = std::vector<std::string>;

// Test 1 (socket shape) as a function: the loop test runs it many times.
void socketShapeScenario()
{
    Rig rig;
    rig.startPrefetch();
    ASSERT_TRUE(rig.waitReached(1)) << "the background read never started";
    rig.queueClient(OperationId{7}, false);

    rig.reader.gate[0].release();
    ASSERT_TRUE(rig.log->waitForCount(1)) << "g1 did not reach the client while the background read was running";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1"}));
    ASSERT_TRUE(rig.waitReached(2));
    EXPECT_EQ(rig.reader.reached.load(), 2) << "the background read must still be reading";

    rig.reader.gate[1].release();
    ASSERT_TRUE(rig.log->waitForCount(2)) << "g2 did not reach the client before the background read ended";

    rig.reader.gate[2].release();
    ASSERT_TRUE(rig.log->waitForCount(5)) << "the client op did not finish";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", "G:g2", "G:g3", "R", finished(OperationStatus::Ok, ErrorCode::None)}));
    EXPECT_EQ(rig.reader.reads.load(), 1) << "the card must be read exactly once";
}

} // namespace

// 1. Socket shape: groups reach the client before the background read ends; one
//    Result; Finished(Ok); the card is read once.
TEST(OperationManagerPrefetchFollower, ClientReceivesGroupsWhileTheBackgroundReadRuns)
{
    socketShapeScenario();
}

// 1b. Socket shape, client attached late: g1 was recorded while nobody followed.
//     Attaching replays it at once, before the background read moves on.
TEST(OperationManagerPrefetchFollower, ALateSocketClientGetsTheRecordedGroupsAtOnce)
{
    Rig rig;
    rig.startPrefetch();
    ASSERT_TRUE(rig.waitReached(1));
    rig.reader.gate[0].release();
    ASSERT_TRUE(rig.waitReached(2)) << "the background read did not record g1";
    EXPECT_TRUE(rig.log->events().empty());

    rig.queueClient(OperationId{7}, false);
    ASSERT_TRUE(rig.log->waitForCount(1)) << "g1 was not replayed on attach (gate 2 still closed)";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1"}));
    EXPECT_EQ(rig.reader.reached.load(), 2) << "the background read must still be standing at gate 2";

    rig.reader.gate[1].release();
    ASSERT_TRUE(rig.log->waitForCount(2)) << "g2 did not arrive live";
    rig.reader.gate[2].release();
    ASSERT_TRUE(rig.log->waitForCount(5)) << "the client op did not finish";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", "G:g2", "G:g3", "R", finished(OperationStatus::Ok, ErrorCode::None)}));
    EXPECT_EQ(rig.reader.reads.load(), 1) << "the card must be read exactly once";
}

// 2. D-Bus shape: nothing until the client has read the op's state, then the
//    groups read so far at once (the background read still standing), then the
//    rest live.
TEST(OperationManagerPrefetchFollower, GroupsWaitForTheClientToReadTheStateThenReplayAndGoLive)
{
    Rig rig;
    rig.startPrefetch();
    ASSERT_TRUE(rig.waitReached(1));
    auto state = rig.queueClient(OperationId{7}, true);

    rig.reader.gate[0].release();
    ASSERT_TRUE(rig.waitReached(2)) << "the background read did not pass its first gate";
    std::this_thread::sleep_for(50ms); // a wrongly early emit would land in this window
    EXPECT_TRUE(rig.log->events().empty()) << "a group was emitted before the client could receive it";

    state->noteObserved();
    ASSERT_TRUE(rig.log->waitForCount(1)) << "g1 was not replayed on observation";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1"}));
    EXPECT_EQ(rig.reader.reached.load(), 2) << "g1 must arrive while the background read is still reading";

    rig.reader.gate[1].release();
    ASSERT_TRUE(rig.log->waitForCount(2)) << "g2 did not arrive live";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", "G:g2"}));

    rig.reader.gate[2].release();
    ASSERT_TRUE(rig.log->waitForCount(5));
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", "G:g2", "G:g3", "R", finished(OperationStatus::Ok, ErrorCode::None)}));
    EXPECT_EQ(rig.reader.reads.load(), 1);
}

// 3. The background read fails after g1: the client reads for itself and never
//    sends g1 again.
TEST(OperationManagerPrefetchFollower, ABackgroundFailureLetsTheClientReadWithoutRepeatingAGroup)
{
    Rig rig;
    rig.reader.failAtGate = 1;
    rig.startPrefetch();
    ASSERT_TRUE(rig.waitReached(1));
    rig.queueClient(OperationId{7}, false);

    rig.reader.gate[0].release();
    ASSERT_TRUE(rig.log->waitForCount(1)) << "g1 was not delivered while the background read stood";
    ASSERT_TRUE(rig.waitReached(2));
    EXPECT_EQ(rig.log->events(), (Events{"G:g1"})) << "asserted before the background read fails";

    rig.reader.gate[1].release(); // the background read fails here
    ASSERT_TRUE(rig.log->waitForCount(5)) << "the client op did not finish its own read";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", "G:g2", "G:g3", "R", finished(OperationStatus::Ok, ErrorCode::None)}));
    EXPECT_EQ(rig.reader.reads.load(), 2) << "the client reads for itself after the failure";
}

// 4. A cancel after g1 ends the client op at once; nothing follows its Finished;
//    the background read goes on and fills the cache.
TEST(OperationManagerPrefetchFollower, CancelAfterAGroupEndsTheClientAndLeavesTheBackgroundReadRunning)
{
    Rig rig;
    rig.startPrefetch();
    ASSERT_TRUE(rig.waitReached(1));
    rig.queueClient(OperationId{7}, false);
    rig.reader.gate[0].release();
    ASSERT_TRUE(rig.log->waitForCount(1)) << "g1 was not delivered before the cancel";
    EXPECT_EQ(rig.log->events(), (Events{"G:g1"}));

    rig.mgr->cancel(OperationId{7});
    ASSERT_TRUE(rig.log->waitForCount(2));
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", finished(OperationStatus::Cancelled, ErrorCode::None)}));

    rig.reader.gate[1].release();
    rig.reader.gate[2].release();
    const auto deadline = std::chrono::steady_clock::now() + kBound;
    while (!rig.readCache.get(kCard).has_value() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_TRUE(rig.readCache.get(kCard).has_value()) << "the background read must still fill the cache";
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", finished(OperationStatus::Cancelled, ErrorCode::None)}))
        << "nothing may follow Finished";
    EXPECT_EQ(rig.reader.reads.load(), 1);
}

// 5. The card is removed in the middle of the background read: the client op
//    ends with CardRemoved and nothing follows.
TEST(OperationManagerPrefetchFollower, CardRemovedMidReadEndsTheClientWithCardRemoved)
{
    Rig rig;
    rig.startPrefetch();
    ASSERT_TRUE(rig.waitReached(1));
    rig.queueClient(OperationId{7}, false);
    rig.reader.gate[0].release();
    ASSERT_TRUE(rig.log->waitForCount(1));

    rig.mgr->endOperationsOnCardRemoved(Rig::readerId());
    ASSERT_TRUE(rig.log->waitForCount(2));
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", finished(OperationStatus::Error, ErrorCode::CardRemoved)}));

    rig.reader.gate[1].release();
    rig.reader.gate[2].release();
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", finished(OperationStatus::Error, ErrorCode::CardRemoved)}))
        << "nothing may follow Finished";
}

// The tests that abandon a worker leave it running past the test, as production
// does: the rig it reads from must outlive it, so those rigs are parked here.
std::vector<std::shared_ptr<Rig>>& graveyard()
{
    static std::vector<std::shared_ptr<Rig>> rigs;
    return rigs;
}

// Parks the background read on a blocking emit of the client op's first group, so
// the relay is mid-emit when the test acts. Returns the thread that emits.
struct BlockedEmit
{
    Gate entered;
    Gate hold;
    std::mutex mutex;
    std::thread::id emitter;

    [[nodiscard]] std::function<void(const std::string&)> hook()
    {
        return [this](const std::string&) {
            {
                std::lock_guard lock(mutex);
                if (emitter != std::thread::id{}) {
                    return;
                }
                emitter = std::this_thread::get_id();
            }
            entered.release();
            (void)hold.wait();
        };
    }
    [[nodiscard]] std::thread::id emitterId()
    {
        std::lock_guard lock(mutex);
        return emitter;
    }
};

// 6. removeReader while the attached op's relay is mid-emit returns within the
//    abandon grace, not after the emit; Finished(CardRemoved) follows the last
//    group; the op is destroyed when the inbox is emptied, not on the emitting
//    thread.
TEST(OperationManagerPrefetchFollower, RemoveReaderDuringAnEmitDoesNotWaitForItNorDestroyTheOpThere)
{
    auto rig = std::make_shared<Rig>();
    graveyard().push_back(rig);
    BlockedEmit blocked;
    rig->startPrefetch();
    ASSERT_TRUE(rig->waitReached(1));
    rig->queueClient(OperationId{7}, false, kCard, blocked.hook());
    rig->reader.gate[0].release();
    ASSERT_TRUE(blocked.entered.wait()) << "the relay never started emitting";

    const auto start = std::chrono::steady_clock::now();
    rig->mgr->removeReader(Rig::readerId());
    const auto took = std::chrono::steady_clock::now() - start;
    EXPECT_LT(took, 1500ms) << "removeReader waited for the emit (grace is 250 ms; the emit is held for longer)";
    EXPECT_EQ(rig->log->events(), (Events{"G:g1"})) << "nothing may be finished while a group is being emitted";
    EXPECT_EQ(rig->deaths->count(), 0u);

    blocked.hold.release();
    ASSERT_TRUE(rig->log->waitForCount(2)) << "Finished did not follow the last group";
    EXPECT_EQ(rig->log->events(), (Events{"G:g1", finished(OperationStatus::Error, ErrorCode::CardRemoved)}));
    EXPECT_EQ(rig->deaths->count(), 0u) << "the op died before the inbox was emptied";

    // The deferred action finishes the op before it parks it in the inbox, so
    // Finished can be seen a moment before there is anything to empty.
    const auto parked = std::chrono::steady_clock::now() + kBound;
    while (rig->deaths->count() == 0 && std::chrono::steady_clock::now() < parked) {
        rig->mgr->drainDeferredForTest();
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(rig->deaths->count(), 1u);
    {
        std::lock_guard lock(rig->deaths->mutex);
        EXPECT_EQ(rig->deaths->threads[0], std::this_thread::get_id()) << "the op died on the wrong thread";
        EXPECT_NE(rig->deaths->threads[0], blocked.emitterId()) << "the op died on the emitting thread";
    }

    rig->reader.gate[1].release();
    rig->reader.gate[2].release();
    const auto deadline = std::chrono::steady_clock::now() + kBound;
    while (!rig->reader.returned.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_TRUE(rig->reader.returned.load());
}

// 6a. cancel while the relay emits, then the manager is destroyed, then the emit
//     is released: the action still runs, Finished(Cancelled) arrives, nothing
//     touches the dead manager, and the op dies with the last reference to the
//     inbox -- on the emitting thread, the one documented exception.
TEST(OperationManagerPrefetchFollower, CancelDuringAnEmitThenTheManagerIsDestroyed)
{
    auto rig = std::make_shared<Rig>();
    graveyard().push_back(rig);
    BlockedEmit blocked;
    rig->startPrefetch();
    ASSERT_TRUE(rig->waitReached(1));
    rig->queueClient(OperationId{7}, false, kCard, blocked.hook());
    rig->reader.gate[0].release();
    ASSERT_TRUE(blocked.entered.wait());

    rig->mgr->cancel(OperationId{7});
    EXPECT_EQ(rig->log->events(), (Events{"G:g1"})) << "cancel finished the op under an emit";
    rig->mgr.reset(); // the manager goes away; its worker is abandoned mid-emit
    EXPECT_EQ(rig->deaths->count(), 0u);

    blocked.hold.release();
    ASSERT_TRUE(rig->log->waitForCount(2)) << "the deferred Finished never came";
    EXPECT_EQ(rig->log->events(), (Events{"G:g1", finished(OperationStatus::Cancelled, ErrorCode::None)}));
    const auto deadline = std::chrono::steady_clock::now() + kBound;
    while (rig->deaths->count() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(rig->deaths->count(), 1u) << "the op was never destroyed";
    {
        std::lock_guard lock(rig->deaths->mutex);
        EXPECT_EQ(rig->deaths->threads[0], blocked.emitterId())
            << "with the manager gone, the op dies on the thread that emptied the relay";
    }

    rig->reader.gate[1].release();
    rig->reader.gate[2].release();
    const auto until = std::chrono::steady_clock::now() + kBound;
    while (!rig->reader.returned.load() && std::chrono::steady_clock::now() < until) {
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_TRUE(rig->reader.returned.load());
}

// 7. Another card, or no background read to attach to: the sequence is today's.
TEST(OperationManagerPrefetchFollower, AnotherCardsClientIsNotAttached)
{
    Rig rig;
    rig.startPrefetch("card-other");
    ASSERT_TRUE(rig.waitReached(1));
    rig.queueClient(OperationId{7}, false, kCard);

    rig.reader.gate[0].release();
    rig.reader.gate[1].release();
    rig.reader.gate[2].release();
    ASSERT_TRUE(rig.log->waitForCount(5));
    // Its own read, streamed by its own op: groups once each, then the Result.
    EXPECT_EQ(rig.log->events(), (Events{"G:g1", "G:g2", "G:g3", "R", finished(OperationStatus::Ok, ErrorCode::None)}));
    EXPECT_EQ(rig.reader.reads.load(), 2);
}

TEST(OperationManagerPrefetchFollower, ACachedCardIsServedWithoutGroups)
{
    Rig rig;
    rig.readCache.put(kCard, fullSnapshot());
    rig.mgr->enqueueTrackedForTest(
        Rig::readerId(),
        std::make_unique<ReadIdentityOperation>(std::make_unique<RecordingChannel>(rig.log, false),
                                                ReadIdentityOperation::Deps{.holder = rig.holder.get(),
                                                                            .reader = rig.reader,
                                                                            .depositor = rig.depositor,
                                                                            .prompter = rig.prompter,
                                                                            .serializer = rig.serializer,
                                                                            .credentials = rig.credentials,
                                                                            .readCache = rig.readCache,
                                                                            .cardKey = kCard,
                                                                            .readerName = "FakeReader",
                                                                            .requester = "test",
                                                                            .artifact = "identity",
                                                                            .onCardType = {}},
                                                std::make_shared<OperationState>()),
        OperationId{7}, CallerToken{":1.1"});
    ASSERT_TRUE(rig.log->waitForCount(2));
    EXPECT_EQ(rig.log->events(), (Events{"R", finished(OperationStatus::Ok, ErrorCode::None)}));
    EXPECT_EQ(rig.reader.reads.load(), 0);
}

// 8. Stability of the whole scenario, many times over.
TEST(OperationManagerPrefetchFollower, TheSocketShapeIsStableOver200Runs)
{
    for (int i = 0; i < 200 && !::testing::Test::HasFailure(); ++i) {
        SCOPED_TRACE("iteration " + std::to_string(i));
        socketShapeScenario();
    }
}
