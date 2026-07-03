// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Sustained-load + shutdown regression: hammer many per-reader workers with
// queued ops, then tear the manager down mid-flight. Every op must reach a
// terminal status (no stranded worker, no lost completion latch) and the
// teardown must finish within a bounded deadline. Meaningful under TSan.
//
// This is the safety net for the clean-layered-lifetime refactor: it exercises
// the UAF-prone surface (many per-reader workers under sustained enqueue, torn
// down while ops are in flight) and MUST stay green through every later
// lifetime change (AgentCore bundle, transport decoupling, explicit quiesce).

#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

// Terminal observation for one op. Heap-allocated + shared so it outlives the
// op regardless of which thread finishes (or, defensively, abandons) it: the
// channel captures the shared_ptr by value, so a write to the atomic can never
// touch freed test-frame storage even if a worker were detached. status stays
// at the 99 sentinel until emitFinished drives the op to a terminal state.
struct Slots
{
    std::atomic<std::uint32_t> status{99};
};

// Minimal emit-only channel: records the terminal status the lifecycle core
// hands it. Mirrors the ZombieWorkerDrainTest capturing double.
class CapturingChannel final : public OperationChannel
{
public:
    explicit CapturingChannel(std::shared_ptr<Slots> slots) : m_slots(std::move(slots)) {}
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus status, ErrorCode, std::string_view, std::string_view) noexcept override
    {
        m_slots->status.store(static_cast<std::uint32_t>(status), std::memory_order_release);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    std::shared_ptr<Slots> m_slots;
};

// Short-running op: a few cancel-token polls then finishes Ok, so the worker
// keeps draining its queue under sustained load. Cooperates with cancel so the
// manager can JOIN (not abandon) it during teardown.
class BriefOp final : public OperationBase
{
public:
    BriefOp(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state)
        : OperationBase(std::move(channel), std::move(state))
    {}

protected:
    void doWork() override
    {
        for (int i = 0; i < 5; ++i) {
            if (isCancelled() || token().isCancelled()) {
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(2ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

} // namespace

// Sustained concurrent enqueue across N readers, then destroy the manager while
// ops are in flight: teardown must return within a bounded deadline (no hang
// from a joined-not-abandoned worker) and every enqueued op must reach a
// terminal status (fail-closed; none left at the 99 sentinel).
TEST(AgentShutdownUnderLoad, ManagerTeardownMidFlightTerminatesEveryOpBounded)
{
    constexpr int kReaders = 8;
    constexpr int kPerReader = 40;

    std::mutex slotsMutex;
    std::vector<std::shared_ptr<Slots>> slots;

    auto mgr = std::make_unique<OperationManager>(); // bus-less worker path
    std::atomic<bool> stop{false};

    std::vector<std::thread> feeders;
    feeders.reserve(kReaders);
    for (int r = 0; r < kReaders; ++r) {
        feeders.emplace_back([&, r] {
            const ObjectId reader{static_cast<std::uint64_t>(r) + 1};
            for (int j = 0; j < kPerReader && !stop.load(std::memory_order_acquire); ++j) {
                auto s = std::make_shared<Slots>();
                {
                    std::lock_guard lk(slotsMutex);
                    slots.push_back(s);
                }
                mgr->enqueueForTest(reader, std::make_unique<BriefOp>(std::make_unique<CapturingChannel>(s),
                                                                      std::make_shared<OperationState>()));
                std::this_thread::sleep_for(1ms);
            }
        });
    }

    std::this_thread::sleep_for(60ms); // let workers spin up and run under load
    const auto start = std::chrono::steady_clock::now();
    stop.store(true, std::memory_order_release);
    for (auto& f : feeders) {
        f.join();
    }
    mgr.reset(); // ~OperationManager: join/abandon every worker, drain queued ops
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, 10s) << "manager teardown under load must not hang";

    // Guard the safety net against silently degrading into a no-op: a real load
    // must have been enqueued for the terminal-status check below to mean anything.
    ASSERT_FALSE(slots.empty()) << "no ops were enqueued — the load never ran";

    // All feeders have joined and the manager is destroyed (its workers joined),
    // so no thread can be touching `slots` here — the reads need no lock.
    for (const auto& s : slots) {
        EXPECT_NE(s->status.load(std::memory_order_acquire), 99u) << "an enqueued op never reached a terminal status";
    }
}
