// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentCore::quiesce() is the one policy for what the agent forgets when the
// holder's session goes away: sleep and a user switch forget the CAN/MRZ
// secrets, the credential snapshots, every reader's session (and with it any
// secure channel) and every PKCS#11 lease; a screen lock forgets only the
// leases. Driven over a real aggregate with three readers, two of them holding
// a card, so "every reader" and "every card" are measured on more than one.
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/wire/QuiesceReason.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include "fakes/FakeAuthorizer.h"
#include "fakes/FakePrompter.h"
#include "fakes/ScratchDir.h"

#include <gtest/gtest.h>
#include <array>
#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

class NeutralResolver final : public CapabilityResolver
{};

constexpr std::array<const char*, 3> kReaders{"reader-A", "reader-B", "reader-C"};
const CallerToken kFirefox{":1.5"};
const CallerToken kSsh{":1.9"};

// One aggregate, three readers, a card in A and C (B stays empty), a session
// open on every reader's worker, a CAN and an MRZ cached for both cards, a
// credential snapshot for both, and a lease for two callers on both.
class AgentCoreQuiesce : public ::testing::Test
{
protected:
    AgentCoreQuiesce()
    {
        core.emplace(
            resolver, authorizer, prompter, dir() / "agent.conf", dir() / "cache",
            [](const std::string&) -> std::optional<ReaderCard> { return std::nullopt; },
            [](const std::string&) -> std::optional<ObjectId> { return std::nullopt; });
        core->operationManager().setSessionFactoryForTest(
            [this](const std::string& reader)
                -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
                std::lock_guard lk(opensMutex);
                ++opens[reader];
                return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(reader);
            });

        for (const char* reader : kReaders) {
            core->presenceModel().onReaderAdded(reader);
        }
        core->presenceModel().onCardInserted("reader-A", {0x3B, 0x00});
        core->presenceModel().onCardInserted("reader-C", {0x3B, 0x01});
        cards = {core->presenceModel().cardIdFor("reader-A"), core->presenceModel().cardIdFor("reader-C")};

        for (const char* reader : kReaders) {
            acquireOn(reader);
        }
        const auto now = std::chrono::steady_clock::now();
        for (const ObjectId card : cards) {
            const std::string key = std::to_string(card.value());
            core->credentialCache().putCan(key, CredentialCache::Secret{"123456"});
            core->credentialCache().putMrz(key, CredentialCache::Secret{"L898902C<369080619406236"});
            static_cast<void>(core->credentialSnapshotCache().put(key, CredentialSnapshot{}));
            for (const CallerToken& caller : {kFirefox, kSsh}) {
                core->leaseManager().grant(Pkcs11::LeaseKey{.caller = caller, .card = card}, now);
            }
        }
    }

    ~AgentCoreQuiesce() override
    {
        core.reset();
        fs::remove_all(dir());
    }

    const fs::path m_dir = LibreSCRS::Agent::Testing::makeScratchDir("libreagent-agentcore-quiesce-");
    [[nodiscard]] const fs::path& dir() const
    {
        return m_dir;
    }

    // Acquire the reader's shared session on its own worker thread (opening it
    // when none is held) and wait for the probe to run.
    void acquireOn(const std::string& reader)
    {
        std::atomic<bool> done{false};
        ASSERT_TRUE(core->operationManager().enqueueOnReaderWorker(core->presenceModel().readerIdFor(reader), reader,
                                                                   [&done](Operations::CardSessionHolder& holder) {
                                                                       static_cast<void>(holder.acquire());
                                                                       done.store(true);
                                                                   }));
        const auto start = std::chrono::steady_clock::now();
        while (!done.load() && std::chrono::steady_clock::now() - start < 2s) {
            std::this_thread::sleep_for(2ms);
        }
        ASSERT_TRUE(done.load()) << "the worker of " << reader << " did not run its probe";
    }

    int opensOf(const std::string& reader)
    {
        std::lock_guard lk(opensMutex);
        return opens[reader];
    }

    int activeLeases()
    {
        const auto now = std::chrono::steady_clock::now();
        int active = 0;
        for (const ObjectId card : cards) {
            for (const CallerToken& caller : {kFirefox, kSsh}) {
                active += core->leaseManager().isActive(Pkcs11::LeaseKey{.caller = caller, .card = card}, now) ? 1 : 0;
            }
        }
        return active;
    }

    int cachedSecrets()
    {
        int cached = 0;
        for (const ObjectId card : cards) {
            const std::string key = std::to_string(card.value());
            cached += core->credentialCache().getCan(key).has_value() ? 1 : 0;
            cached += core->credentialCache().getMrz(key).has_value() ? 1 : 0;
            cached += core->credentialSnapshotCache().get(key).has_value() ? 1 : 0;
        }
        return cached;
    }

    // Every reader re-acquires once more: a reader whose session the quiesce
    // invalidated opens a new one, a reader whose session survived does not.
    std::map<std::string, int> opensAfterReacquire()
    {
        std::map<std::string, int> out;
        for (const char* reader : kReaders) {
            acquireOn(reader);
            out[reader] = opensOf(reader);
        }
        return out;
    }

    void expectStartingState()
    {
        ASSERT_EQ(cards.size(), 2u);
        ASSERT_NE(cards[0], ObjectId{});
        ASSERT_NE(cards[1], ObjectId{});
        for (const char* reader : kReaders) {
            ASSERT_EQ(opensOf(reader), 1) << reader << " holds one session before the quiesce";
        }
        ASSERT_EQ(cachedSecrets(), 6) << "CAN, MRZ and a snapshot for each of the two cards";
        ASSERT_EQ(activeLeases(), 4) << "two callers on each of the two cards";
    }

    void expectFullScrub()
    {
        EXPECT_EQ(cachedSecrets(), 0) << "no CAN, MRZ or credential snapshot survives the quiesce";
        EXPECT_EQ(activeLeases(), 0) << "no PKCS#11 lease survives the quiesce";
        const std::map<std::string, int> expected{{"reader-A", 2}, {"reader-B", 2}, {"reader-C", 2}};
        EXPECT_EQ(opensAfterReacquire(), expected)
            << "every reader's session, secure channel included, was invalidated: the next operation re-opens";
    }

    NeutralResolver resolver;
    FakeAuthorizer authorizer;
    std::shared_ptr<Operations::FakePrompter> prompter = std::make_shared<Operations::FakePrompter>();
    // Declared before the core: the workers the core joins on teardown write it.
    std::mutex opensMutex;
    std::map<std::string, int> opens;
    std::optional<AgentCore> core;
    std::vector<ObjectId> cards;
};

} // namespace

TEST_F(AgentCoreQuiesce, SleepForgetsSecretsSessionsAndLeases)
{
    expectStartingState();
    core->quiesce(QuiesceReason::SystemSleep);
    expectFullScrub();
}

TEST_F(AgentCoreQuiesce, SwitchingAwayFromTheSessionForgetsSecretsSessionsAndLeases)
{
    expectStartingState();
    core->quiesce(QuiesceReason::SessionInactive);
    expectFullScrub();
}

// A reason appended after this build takes the full scrub: forgetting too
// much costs a prompt, forgetting too little leaks a secret.
TEST_F(AgentCoreQuiesce, AReasonPastThisBuildForgetsEverything)
{
    expectStartingState();
    core->quiesce(static_cast<QuiesceReason>(42));
    expectFullScrub();
}

TEST_F(AgentCoreQuiesce, AScreenLockRevokesTheLeasesAndKeepsTheSession)
{
    expectStartingState();
    core->quiesce(QuiesceReason::ScreenLocked);
    EXPECT_EQ(activeLeases(), 0) << "the next PKCS#11 operation asks for the PIN again";
    EXPECT_EQ(cachedSecrets(), 6) << "a lock is not a sleep: the CAN/MRZ secrets and snapshots stay";
    const std::map<std::string, int> expected{{"reader-A", 1}, {"reader-B", 1}, {"reader-C", 1}};
    EXPECT_EQ(opensAfterReacquire(), expected) << "a lock keeps every reader's session";
}

TEST_F(AgentCoreQuiesce, RevokeLeasesTouchesNothingElse)
{
    expectStartingState();
    core->revokeLeases();
    EXPECT_EQ(activeLeases(), 0);
    EXPECT_EQ(cachedSecrets(), 6);
    const std::map<std::string, int> expected{{"reader-A", 1}, {"reader-B", 1}, {"reader-C", 1}};
    EXPECT_EQ(opensAfterReacquire(), expected);
}
