// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Since the prompt gate was keyed by card, two dialogs can stand at once. An
// unaddressed dismissal closes whichever one is topmost -- very often another
// card's. These drive the real gate + decorator, not a copy of their logic.

#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/CancelToken.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using LibreSCRS::Agent::PinChangePromptResult;
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::Operations::PrompterClientBase;
using LibreSCRS::Agent::Operations::PromptSerializer;
using LibreSCRS::Agent::Operations::SerializingPrompter;

namespace {

// Records what each prompt was asked and which ids were dismissed. Can be told
// to hold inside a request so two prompts are genuinely live at once.
class RecordingPrompter final : public PrompterClientBase
{
public:
    std::vector<PromptOptions> seen;
    std::vector<std::string> cancelledIds;

    void holdInsideRequests()
    {
        m_hold = true;
    }
    void release()
    {
        {
            const std::lock_guard lock{m_mutex};
            m_hold = false;
        }
        m_cv.notify_all();
    }
    bool waitForPrompts(std::size_t count, std::chrono::milliseconds budget)
    {
        std::unique_lock lock{m_mutex};
        return m_cv.wait_for(lock, budget, [&] { return seen.size() >= count; });
    }

    [[nodiscard]] PromptResult requestPin(const PromptOptions& o) override
    {
        return record(o);
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions& o) override
    {
        return record(o);
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions& o) override
    {
        return record(o);
    }
    [[nodiscard]] PinChangePromptResult requestPinChange(const PromptOptions& o) override
    {
        std::unique_lock lock{m_mutex};
        seen.push_back(o);
        m_cv.notify_all();
        m_cv.wait(lock, [&] { return !m_hold; });
        PinChangePromptResult r;
        r.status = PromptStatus::Cancelled;
        return r;
    }
    void cancel(const std::string& promptId) noexcept override
    {
        const std::lock_guard lock{m_mutex};
        cancelledIds.push_back(promptId);
    }

private:
    PromptResult record(const PromptOptions& o)
    {
        std::unique_lock lock{m_mutex};
        seen.push_back(o);
        m_cv.notify_all();
        m_cv.wait(lock, [&] { return !m_hold; });
        // Cancelled rather than Ok: nothing here should look like a collected
        // secret.
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_hold{false};
};

} // namespace

TEST(AddressedCancel, ADismissalNamesOnePromptAndLeavesTheOther)
{
    PromptSerializer serializer;
    RecordingPrompter inner;
    inner.holdInsideRequests();
    LibreSCRS::CancelSource sourceA;
    LibreSCRS::CancelSource sourceB;
    SerializingPrompter cardA{serializer, inner, sourceA.token(), "card-a"};
    SerializingPrompter cardB{serializer, inner, sourceB.token(), "card-b"};

    // Sequenced, not merely concurrent: with both prompts raised in a known
    // ORDER their ids have a known order too, and the assertions below can then
    // discriminate an implementation that dismisses "the first live prompt" or
    // "the last" from one that dismisses the prompt it was told to.
    std::jthread ta([&] { static_cast<void>(cardA.requestCan(PromptOptions{})); });
    ASSERT_TRUE(inner.waitForPrompts(1, std::chrono::seconds{5}));
    std::jthread tb([&] { static_cast<void>(cardB.requestPin(PromptOptions{})); });
    ASSERT_TRUE(inner.waitForPrompts(2, std::chrono::seconds{5})) << "both cards must prompt concurrently";

    const auto liveA = serializer.liveIdsFor("card-a");
    const auto liveB = serializer.liveIdsFor("card-b");
    ASSERT_EQ(liveA.size(), 1u);
    ASSERT_EQ(liveB.size(), 1u);
    ASSERT_NE(liveA.front(), liveB.front());

    // Dismiss the LATER prompt first, then the earlier one. Anything that
    // ignores the id has to pick, and either choice gets one of the two wrong.
    cardB.cancel(liveB.front());
    cardA.cancel(liveA.front());
    inner.release();
    ta.join();
    tb.join();

    ASSERT_EQ(inner.cancelledIds.size(), 2u);
    EXPECT_EQ(inner.cancelledIds[0], liveB.front()) << "the dismissal closed the other card's dialog";
    EXPECT_EQ(inner.cancelledIds[1], liveA.front()) << "the dismissal closed the other card's dialog";
}

TEST(AddressedCancel, TheLiveSetIsEmptyOnceEveryPromptHasAnswered)
{
    // Shutdown needs the SET of outstanding ids, not a boolean it then acts on
    // blind.
    PromptSerializer serializer;
    RecordingPrompter inner;
    LibreSCRS::CancelSource source;
    SerializingPrompter gated{serializer, inner, source.token(), "card-a"};

    EXPECT_TRUE(serializer.liveIds().empty());
    static_cast<void>(gated.requestPin(PromptOptions{}));
    EXPECT_TRUE(serializer.liveIds().empty());
    EXPECT_TRUE(serializer.liveIdsFor("card-a").empty());
}

TEST(AddressedCancel, TheLiveSetSpansEveryCardForShutdown)
{
    PromptSerializer serializer;
    RecordingPrompter inner;
    inner.holdInsideRequests();
    LibreSCRS::CancelSource sourceA;
    LibreSCRS::CancelSource sourceB;
    SerializingPrompter cardA{serializer, inner, sourceA.token(), "card-a"};
    SerializingPrompter cardB{serializer, inner, sourceB.token(), "card-b"};

    std::jthread ta([&] { static_cast<void>(cardA.requestCan(PromptOptions{})); });
    std::jthread tb([&] { static_cast<void>(cardB.requestPin(PromptOptions{})); });
    ASSERT_TRUE(inner.waitForPrompts(2, std::chrono::seconds{5}));

    auto all = serializer.liveIds();
    std::ranges::sort(all);
    auto expected = serializer.liveIdsFor("card-a");
    for (const auto& id : serializer.liveIdsFor("card-b")) {
        expected.push_back(id);
    }
    std::ranges::sort(expected);
    EXPECT_EQ(all, expected);
    EXPECT_EQ(all.size(), 2u);

    inner.release();
}

TEST(AddressedCancel, AWorkerCancelledWhileQueuedNeverBecomesLive)
{
    // No dialog was raised, so there is nothing to dismiss and no id to leak
    // into the shutdown set.
    PromptSerializer serializer;
    RecordingPrompter inner;
    LibreSCRS::CancelSource source;
    source.requestCancel();
    SerializingPrompter gated{serializer, inner, source.token(), "card-a"};

    static_cast<void>(gated.requestCan(PromptOptions{}));

    EXPECT_TRUE(inner.seen.empty());
    EXPECT_TRUE(serializer.liveIds().empty());
}

TEST(AddressedCancel, TheChangePinModalIsAddressableToo)
{
    // The change modal takes a different route through the gate; a registration
    // added only to the shared path would leave it undismissable.
    PromptSerializer serializer;
    RecordingPrompter inner;
    inner.holdInsideRequests();
    LibreSCRS::CancelSource source;
    SerializingPrompter gated{serializer, inner, source.token(), "card-a"};

    std::jthread t([&] { static_cast<void>(gated.requestPinChange(PromptOptions{})); });
    ASSERT_TRUE(inner.waitForPrompts(1, std::chrono::seconds{5}));

    EXPECT_EQ(serializer.liveIdsFor("card-a").size(), 1u);
    inner.release();
}
