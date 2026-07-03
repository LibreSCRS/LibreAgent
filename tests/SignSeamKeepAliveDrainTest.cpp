// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Faithful drain proof for the qualified-timestamped-sign path's engine + config
// keep-alive. An abandoned sign worker wedged inside the (uncancellable) on-card
// signing call unblocks later and runs, in order, the signing-engine provider's
// snapshot() at entry and recordLastTsaUrlUsed() at success-exit — the latter
// writing the config's read-only LastTsaUrl. Both the provider and the config it
// borrows are core members; if freed with the composition while the worker is
// parked, the unblock dereferences freed memory.
//
// The fix folds the provider + config into the single CryptoWorkerContext (as
// shared_ptr), captured WHOLE by the worker, so the abandoned worker co-owns both
// and its post-unblock snapshot() + recordLastTsaUrlUsed() touch LIVE memory. Here
// a worker co-owns the context and wedges in the "sign" until the test releases it;
// the composition then drops its provider + config + context shares while the
// worker is parked, so only the worker's co-owned share keeps them alive; the
// delayed unblock runs snapshot() + recordLastTsaUrlUsed() (TSan-clean) and reads
// the recorded URL back through the still-live config.
//
// PROVE TEETH (manual): remove `.config` + `.signingEngine` from the context below
// (modelling them as value members the composition frees) and re-run under
// ThreadSanitizer — the provider + config are then freed at the composition drop
// and the wedged worker's recordLastTsaUrlUsed traps on freed memory. Meaningful
// under TSan.

#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/CancelToken.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

constexpr int kMarker = 0x515A;
const ObjectId kReader{31};
constexpr const char* kTsaUrl = "https://tsa.example.test/tsr";

fs::path uniqueDir(const char* tag)
{
    return fs::temp_directory_path() / (std::string{"ll-signseamdrain-"} + tag);
}

struct Latch
{
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};

    void release()
    {
        {
            std::lock_guard lock(mutex);
            released = true;
        }
        cv.notify_all();
    }
    void waitForRelease()
    {
        std::unique_lock lock(mutex);
        cv.wait(lock, [this] { return released; });
    }
};

struct TypedSlots
{
    std::atomic<int> finishCount{0};
};

class RecordingChannel final : public OperationChannel
{
public:
    explicit RecordingChannel(std::shared_ptr<TypedSlots> slots) : m_slots(std::move(slots)) {}
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus, ErrorCode, std::string_view, std::string_view) noexcept override
    {
        m_slots->finishCount.fetch_add(1, std::memory_order_acq_rel);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    std::shared_ptr<TypedSlots> m_slots;
};

// A typed sign op whose doWork models the LmSigner touch sequence around the
// uncancellable on-card sign: it derefs the signing-engine provider by BARE
// reference (exactly as LmSigner holds SigningEngineProvider& m_engine), wedges on
// a latch (the wedge inside engine->sign), then on unblock runs snapshot() at entry
// and recordLastTsaUrlUsed() at success-exit — the config write that outlives the
// flow's post-return token gate. It reads the recorded URL back through the config
// (also by bare reference) to confirm the write landed on live memory, then skips
// its wire completion on the shutdown-cancel path exactly as SignOperation does.
class WedgingSignOp final : public OperationBase
{
public:
    WedgingSignOp(std::unique_ptr<OperationChannel> ch, std::shared_ptr<OperationState> st,
                  SigningEngineProvider& engine, const Config::ConfigStore& config, Latch& latch,
                  std::atomic<int>& entered, std::atomic<int>& observed)
        : OperationBase(std::move(ch), std::move(st), []() noexcept {}), m_engine(engine), m_config(config),
          m_latch(latch), m_entered(entered), m_observed(observed)
    {}

protected:
    void doWork() override
    {
        m_entered.fetch_add(1, std::memory_order_acq_rel);
        const int mine = kMarker;
        m_latch.waitForRelease();
        // Post-unblock deref of the co-owned provider + config, in LmSigner's order.
        const auto snap = m_engine.snapshot();           // LmSeams.cpp: snapshot() at entry
        m_engine.recordLastTsaUrlUsed(snap.boundTsaUrl); // LmSeams.cpp: record at success-exit -> config write
        if (!snap.boundTsaUrl.empty() && m_config.lastTsaUrl() == snap.boundTsaUrl) {
            m_observed.store(mine, std::memory_order_release); // read-back through the live config
        }
        if (shutdownRequested()) {
            return; // teardown: skip the wire completion (as the real typed ops do)
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
    }

private:
    SigningEngineProvider& m_engine;
    const Config::ConfigStore& m_config;
    Latch& m_latch;
    std::atomic<int>& m_entered;
    std::atomic<int>& m_observed;
};

} // namespace

// The abandoned qualified-sign worker keeps the signing-engine provider + the
// config it borrows alive through its co-owned crypto context, so the delayed
// unblock's snapshot() + recordLastTsaUrlUsed() run against live memory.
TEST(SignSeamKeepAliveDrain, AbandonedSignOpKeepsEngineAndConfigAliveThroughCoOwnedContext)
{
    const auto dir = uniqueDir("engineconfig");
    fs::remove_all(dir);

    Latch latch;
    std::atomic<int> entered{0};
    std::atomic<int> observedMarker{0};
    auto slots = std::make_shared<TypedSlots>();

    LibreSCRS::CancelSource shutdown; // the agent-wide shutdown-cancel source

    // The composition (AgentCore-analogue) owns the config + provider as shared_ptr
    // and gathers both into the single crypto-worker context — the exact shares the
    // real AgentCore ctor populates. A configured TSA makes the bound URL non-empty
    // so recordLastTsaUrlUsed actually writes the config.
    auto config = std::make_shared<Config::ConfigStore>(dir / "agent.conf", dir / "cache");
    ASSERT_TRUE(config->setTsaUrls(std::vector<std::string>{kTsaUrl}).ok);
    auto engine = std::make_shared<SigningEngineProvider>(*config);
    ASSERT_EQ(engine->snapshot().boundTsaUrl, kTsaUrl);

    auto ctx = std::make_shared<CryptoWorkerContext>(CryptoWorkerContext{
        .shutdown = shutdown.token(),
        .config = config,
        .signingEngine = engine,
    });

    {
        OperationManager mgr; // bus-less worker path

        auto op = std::make_unique<WedgingSignOp>(std::make_unique<RecordingChannel>(slots),
                                                  std::make_shared<OperationState>(), *engine, *config, latch, entered,
                                                  observedMarker);
        // Co-own the whole context (provider + config shares) + bind the shutdown
        // token, exactly as CardObject::attachLifetimeGuards does for the sign op.
        op->keepAlive(ctx);
        op->bindShutdownToken(shutdown.token());
        mgr.enqueueForTest(kReader, std::move(op));

        const auto enteredDeadline = std::chrono::steady_clock::now() + 2s;
        while (entered.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < enteredDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_EQ(entered.load(std::memory_order_acquire), 1) << "sign op never entered the wedge";

        // The op co-owns the context, so the composition is not the sole owner of
        // the provider + config (each is co-owned via the context share).
        EXPECT_GE(ctx.use_count(), 2);
        EXPECT_GE(engine.use_count(), 2);
        EXPECT_GE(config.use_count(), 2);

        // Model quiesce: cancel the shutdown token, then abandon the still-wedged
        // worker (it is detached to the process-lifetime zombie list).
        shutdown.requestCancel();
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReader);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged sign worker";

        // Drop the composition's shares: only the abandoned op's co-owned context
        // share keeps the provider + config alive now (the RED-proof deletes the
        // context's .config/.signingEngine so this drop frees them).
        ctx.reset();
        engine.reset();
        config.reset();

        // Delayed unblock (the late CancelCurrent / on-card sign finally returns).
        latch.release();

        const auto readDeadline = std::chrono::steady_clock::now() + 2s;
        while (observedMarker.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < readDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(observedMarker.load(std::memory_order_acquire), kMarker)
            << "the abandoned sign op never completed snapshot() + recordLastTsaUrlUsed() on the co-owned "
               "engine/config";
        // Shutdown-cancel skip: the op must NOT have driven its wire completion.
        EXPECT_EQ(slots->finishCount.load(std::memory_order_acquire), 0)
            << "the sign op drove its completion on the shutdown-cancel path";

        std::this_thread::sleep_for(100ms); // let the zombie thread fully unwind
    }

    fs::remove_all(dir);
}
