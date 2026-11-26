// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The cleanup thread sweeps finished operations out of the id and sender tables.
// A manager destroyed while it does so must keep those tables alive until the
// thread is joined: members die in reverse order of declaration, so the thread
// has to be declared after everything it touches. Run under TSan, the old order
// shows up as a race on the destroyed tables.
#include <LibreSCRS/Agent/operations/OperationManager.h>

#include "fakes/FakeOperationChannel.h"

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

class InstantOp final : public OperationBase
{
public:
    InstantOp(std::shared_ptr<std::atomic<int>> done)
        : OperationBase(std::make_unique<FakeOperationChannel>(), std::make_shared<OperationState>()),
          m_done(std::move(done))
    {}

protected:
    void doWork() override
    {
        finish(OperationStatus::Ok, ErrorCode::None, "ok", "ok");
        m_done->fetch_add(1);
    }

private:
    std::shared_ptr<std::atomic<int>> m_done;
};

} // namespace

TEST(OperationManagerCleanupOrder, DestroyingAManagerWhileTheCleanupThreadSweepsIsSafe)
{
    for (int round = 0; round < 150; ++round) {
        auto manager = std::make_unique<OperationManager>(nullptr);
        manager->setCleanupCadenceForTest(1ms, 0ms);
        auto done = std::make_shared<std::atomic<int>>(0);
        for (std::uint64_t i = 1; i <= 3; ++i) {
            manager->enqueueTrackedForTest(ObjectId{1}, std::make_unique<InstantOp>(done), OperationId{i},
                                           CallerToken{":1." + std::to_string(i)});
        }
        // Destroyed as soon as the ops have run: they are in the grace queue and the
        // cleanup thread (ticking every millisecond, no grace) is sweeping them.
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (done->load() < 3 && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        ASSERT_EQ(done->load(), 3);
        manager.reset();
    }
}
