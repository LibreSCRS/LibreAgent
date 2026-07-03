// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Worker-side semantics test for OperationBase. No bus: a fake
// OperationChannel captures emit calls into vectors the test inspects.

#include <LibreSCRS/Agent/operations/OperationBase.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string_view>
#include <thread>
#include <vector>

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationBase;
using LibreSCRS::Agent::Operations::OperationChannel;
using LibreSCRS::Agent::Operations::OperationState;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Agent::Operations::ResultPayload;

namespace {

struct EmittedFinish
{
    std::uint32_t status;
    std::uint32_t errorCode;
    std::string msgKey;
    std::string msgFallback;
};

class FakeOperationChannel final : public OperationChannel
{
public:
    void emitFinished(OperationStatus status, ErrorCode errorCode, std::string_view msgKey,
                      std::string_view msgFallback) noexcept override
    {
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(errorCode),
                            std::string{msgKey}, std::string{msgFallback}});
    }
    void emitPropertiesChanged() noexcept override
    {
        propertyEmits.fetch_add(1);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

    std::vector<EmittedFinish> finishes;
    std::atomic<int> propertyEmits{0};
};

class NoopOp final : public OperationBase
{
public:
    NoopOp(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state)
        : OperationBase(std::move(channel), std::move(state))
    {}

protected:
    void doWork() override
    {
        // Card-I/O ops are honest spinners: flag indeterminate at start.
        setIndeterminate(true);
        setPhase(static_cast<std::uint32_t>(LibreSCRS::Agent::Operations::OperationPhase::Reading));
        setProgress(0.5);
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Operation completed");
    }
};

// Op that finishes with an Error so the terminal Status/ErrorCode mirrors
// carry non-trivial values the recovery test can distinguish from defaults.
class FailingOp final : public OperationBase
{
public:
    FailingOp(std::unique_ptr<OperationChannel> channel, std::shared_ptr<OperationState> state)
        : OperationBase(std::move(channel), std::move(state))
    {}

protected:
    void doWork() override
    {
        setIndeterminate(true);
        setPhase(static_cast<std::uint32_t>(LibreSCRS::Agent::Operations::OperationPhase::Reading));
        finish(OperationStatus::Error, ErrorCode::CardRemoved, "op.card_removed", "Card removed");
    }
};

} // namespace

TEST(OperationBase, RunOnWorkerEmitsFinishedExactlyOnce)
{
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    NoopOp op(std::move(adaptor), state);
    op.runOnWorker();
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, 0u);
    EXPECT_EQ(raw->finishes[0].errorCode, 0u);
    EXPECT_EQ(raw->finishes[0].msgKey, "op.ok");

    // Double-call must be a no-op (finish-once flag).
    op.runOnWorker();
    EXPECT_EQ(raw->finishes.size(), 1u) << "finish must be idempotent (std::once_flag)";
}

TEST(OperationBase, CancelTokenObservesCancelMethod)
{
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    NoopOp op(std::move(adaptor), state);
    EXPECT_FALSE(op.cancelTokenForTest().isCancelled());
    op.requestCancel();
    EXPECT_TRUE(state->cancelled.load()) << "requestCancel must flip the shared cancel atomic";
    EXPECT_TRUE(op.cancelTokenForTest().isCancelled());
    op.runOnWorker();
    // finish() still fires (the doWork above doesn't observe the token —
    // the Cancelled status is the subclass's responsibility).
    EXPECT_EQ(raw->finishes.size(), 1u);
}

TEST(OperationBase, PhaseAndProgressVisibleToAdaptorHooks)
{
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    NoopOp op(std::move(adaptor), state);
    EXPECT_EQ(op.phase(), 0u); // Created
    EXPECT_DOUBLE_EQ(op.progress(), 0.0);
    op.runOnWorker();
    EXPECT_EQ(op.phase(), static_cast<std::uint32_t>(LibreSCRS::Agent::Operations::OperationPhase::Done));
    EXPECT_DOUBLE_EQ(op.progress(), 1.0) << "Done phase implies 100% progress";
    EXPECT_GE(raw->propertyEmits.load(), 1) << "phase transitions must propagate at least once";
}

TEST(OperationBase, SetsIndeterminateOnStartAndExposesTerminalPropsAfterFinish)
{
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    NoopOp op(std::move(adaptor), state);

    // Before running: an honest spinner has not been engaged and no
    // terminal result is published yet.
    EXPECT_FALSE(op.isIndeterminate());
    EXPECT_FALSE(op.completed());

    op.runOnWorker();

    // (a) Card-I/O op set IsIndeterminate=true at start; it stays true
    // through the op (no determinate Progress was reported).
    EXPECT_TRUE(op.isIndeterminate()) << "card-I/O op must present an honest spinner";
    EXPECT_TRUE(state->isIndeterminate.load());

    // (b) Terminal-property mirrors are populated after finish() so a
    // client that missed Finished can read them race-free.
    EXPECT_TRUE(op.completed()) << "Completed must be true after the op finishes";
    EXPECT_TRUE(state->completed.load());
    EXPECT_EQ(op.terminalStatus(), static_cast<std::uint32_t>(OperationStatus::Ok));
    EXPECT_EQ(op.terminalErrorCode(), static_cast<std::uint32_t>(ErrorCode::None));

    // The Finished signal still fired with the same values the mirrors carry.
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, op.terminalStatus());
    EXPECT_EQ(raw->finishes[0].errorCode, op.terminalErrorCode());
}

TEST(OperationBase, TerminalPropsMirrorErrorOutcome)
{
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    FailingOp op(std::move(adaptor), state);
    op.runOnWorker();

    EXPECT_TRUE(op.completed());
    EXPECT_EQ(op.terminalStatus(), static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(op.terminalErrorCode(), static_cast<std::uint32_t>(ErrorCode::CardRemoved));

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CardRemoved));
}

namespace {

// Op variant that just sits in AwaitingConsent until cancelled.
class WaitingForConsentOp final : public OperationBase
{
public:
    WaitingForConsentOp(std::unique_ptr<OperationChannel> a,
                        std::shared_ptr<LibreSCRS::Agent::Operations::OperationState> s, std::function<void()> cb)
        : OperationBase(std::move(a), std::move(s), std::move(cb))
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(LibreSCRS::Agent::Operations::OperationPhase::AwaitingConsent));
        for (int i = 0; i < 250; ++i) {
            if (isCancelled()) {
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

} // namespace

TEST(OperationBase, RequestCancelFromAwaitingConsentInvokesPrompterCancelCallback)
{
    std::atomic<int> cancelCalls{0};
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    // Pre-set the phase to AwaitingConsent so a synchronous requestCancel
    // (no worker thread) exercises the prompter-cancel hook directly.
    state->phase.store(static_cast<std::uint32_t>(LibreSCRS::Agent::Operations::OperationPhase::AwaitingConsent));
    WaitingForConsentOp op(std::move(adaptor), state, [&cancelCalls]() noexcept { cancelCalls.fetch_add(1); });

    op.requestCancel();

    EXPECT_EQ(cancelCalls.load(), 1) << "requestCancel from AwaitingConsent must invoke the prompter-cancel callback";
    EXPECT_TRUE(state->cancelled.load());
}

TEST(OperationBase, RequestCancelFromOtherPhasesDoesNotInvokePrompterCancel)
{
    // Cancel issued while the op is in Reading (or any non-
    // AwaitingConsent phase) must NOT call the prompter-cancel callback
    // -- the prompter is not showing a modal so there is nothing to
    // dismiss; firing the call would spam the prompter service.
    std::atomic<int> cancelCalls{0};
    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto state = std::make_shared<LibreSCRS::Agent::Operations::OperationState>();
    state->phase.store(static_cast<std::uint32_t>(LibreSCRS::Agent::Operations::OperationPhase::Reading));
    WaitingForConsentOp op(std::move(adaptor), state, [&cancelCalls]() noexcept { cancelCalls.fetch_add(1); });

    op.requestCancel();

    EXPECT_EQ(cancelCalls.load(), 0) << "requestCancel from non-AwaitingConsent must NOT invoke prompter-cancel";
    EXPECT_TRUE(state->cancelled.load());
}
