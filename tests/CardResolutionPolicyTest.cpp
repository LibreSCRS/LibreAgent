// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The insertion rule every host follows: probe a fresh card on its reader's
// worker, ask again only when the probe could not open it, within a budget the
// host chooses, and hold the reader only for a served card on the contact slot
// of a dual-interface unit. The cases drive the real per-reader worker with a
// counting session factory in place of PC/SC, and play the host's loop
// themselves: probe, ask the policy, probe again or publish. They do not sleep
// through the waits -- a wait is the host's to keep; what is under test is
// which waits the policy asks for and when it stops.

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/presence/CardResolutionPolicy.h>
#include "fakes/PinStubPlugin.h" // BasePinPlugin
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace std::chrono_literals;
using LibreSCRS::SmartCard::OpenError;
using Kind = LibreSCRS::SmartCard::OpenError::Kind;

namespace {

constexpr auto kPki = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);

// A single-interface reader and both slots of a dual-interface OMNIKEY 5422,
// whose two names share a serial and differ in the bracketed product string.
// Readers 1..3, cards 11..13.
struct BenchReader
{
    ObjectId reader;
    const char* cardKey;
    const char* name;
};
const std::array<BenchReader, 3> kBench{{
    {ObjectId(1), "11", "Gemalto PC Twin Reader (69988A87) 02 00"},
    {ObjectId(2), "12",
     "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00"},
    {ObjectId(3), "13",
     "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00"},
}};
const BenchReader& kContactSlot = kBench[1];

// The bench with one card, in @p at; every other reader is empty.
PresenceRoster rosterWithCardIn(const BenchReader& at)
{
    PresenceRoster roster;
    for (const auto& b : kBench) {
        roster.readerNames.emplace_back(b.name);
        roster.cardKeys.emplace_back(b.reader == at.reader ? b.cardKey : "");
    }
    return roster;
}

// Serves every card when @c serves, none otherwise; resolvePlugin finds none,
// so the ATR alone never decides.
class InsertionResolver final : public CapabilityResolver
{
public:
    explicit InsertionResolver(bool servesCards) : m_serves(servesCards) {}
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t> /*atr*/, LibreSCRS::SmartCard::CardSession& /*session*/) override
    {
        if (m_serves) {
            return {
                std::make_shared<Operations::BasePinPlugin>("serving-stub", LibreSCRS::Plugin::CardCapabilities::PKI)};
        }
        return {};
    }

private:
    bool m_serves;
};

// The PC/SC code a card session open fails with for @p kind, so a refusal
// carries the detail the open reports with it: a card another process holds
// is a refused session (SCARD_E_SHARING_VIOLATION), not an unavailable reader.
std::string pcscCodeFor(Kind kind)
{
    switch (kind) {
    case Kind::SessionRefused:
        return "SCARD_E_SHARING_VIOLATION";
    case Kind::NoCardPresent:
        return "SCARD_E_NO_SMARTCARD";
    case Kind::ProtocolError:
        return "SCARD_F_COMM_ERROR";
    case Kind::ReaderUnavailable:
        return "SCARD_E_READER_UNAVAILABLE";
    }
    return {};
}

// One reader worker per bench reader and a session factory that refuses the
// first opens with @p refusals (in order), the way a card another process
// holds refuses them, then opens a detached session. The open count is
// shared-owned, so a worker that outlives a case counts into live memory.
class Insertion
{
public:
    Insertion(bool servesCards, std::vector<Kind> refusals) : m_resolver(servesCards), m_operations(&m_resolver)
    {
        m_operations.setSessionFactoryForTest(
            [opens = m_opens, refusals = std::move(refusals)](const std::string& reader)
                -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, OpenError> {
                const auto n = static_cast<std::size_t>(opens->fetch_add(1));
                if (n < refusals.size()) {
                    return std::unexpected{
                        OpenError{refusals[n], LibreSCRS::Auth::ErrorKeys::genericComm(), pcscCodeFor(refusals[n])}};
                }
                return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(reader);
            });
    }

    // One probe on @p at's worker, delivered the way a host receives it.
    CardProbe probeOnce(const BenchReader& at)
    {
        auto delivered = std::make_shared<std::promise<CardProbe>>();
        auto result = delivered->get_future();
        const bool queued = CardResolutionPolicy::probeOnWorker(
            m_operations, at.reader, at.name, [delivered](CardProbe probe) { delivered->set_value(std::move(probe)); });
        if (!queued || result.wait_for(5s) != std::future_status::ready) {
            ADD_FAILURE() << "the probe was not delivered within 5 s";
            CardProbe undelivered;
            undelivered.openFailure =
                OpenError{Kind::ProtocolError, LibreSCRS::Auth::ErrorKeys::genericComm(), std::string{"not delivered"}};
            return undelivered;
        }
        return result.get();
    }

    struct Outcome
    {
        CardProbe probe;
        ResolveAttempts attempts;
        std::vector<std::chrono::milliseconds> waits;
    };

    // The host's loop for one insertion: probe, and probe again for as long
    // as the policy asks for a wait.
    Outcome insert(const CardResolutionPolicy& policy, const BenchReader& at)
    {
        Outcome out;
        for (int guard = 0; guard < 100; ++guard) {
            out.probe = probeOnce(at);
            const auto wait = policy.retryAfter(out.probe, out.attempts);
            if (!wait) {
                return out;
            }
            out.waits.push_back(*wait);
        }
        ADD_FAILURE() << "the policy never stopped asking";
        return out;
    }

    [[nodiscard]] int opens() const
    {
        return m_opens->load();
    }

    Operations::OperationManager& operations()
    {
        return m_operations;
    }

    // Run nothing on @p at's worker and wait for it: every flag set before
    // this has been applied once it returns.
    void drain(const BenchReader& at)
    {
        auto ran = std::make_shared<std::promise<void>>();
        auto done = ran->get_future();
        m_operations.enqueueHolderProbeForTest(at.reader, [ran](Operations::CardSessionHolder&) { ran->set_value(); });
        ASSERT_EQ(done.wait_for(5s), std::future_status::ready) << "the worker did not run within 5 s";
    }

private:
    std::shared_ptr<std::atomic<int>> m_opens = std::make_shared<std::atomic<int>>(0);
    InsertionResolver m_resolver; // outlives the workers m_operations joins
    Operations::OperationManager m_operations;
};

CardProbe failedProbe(Kind kind)
{
    CardProbe probe;
    probe.openFailure = OpenError{kind, LibreSCRS::Auth::ErrorKeys::genericComm(), pcscCodeFor(kind)};
    return probe;
}

CardProbe openedProbe(std::uint32_t capabilities)
{
    CardProbe probe;
    probe.capabilities = capabilities;
    return probe;
}

std::vector<Kind> refused(int n, Kind kind = Kind::SessionRefused)
{
    return std::vector<Kind>(static_cast<std::size_t>(n), kind);
}

// A host whose sessions are exclusive: a probe can lose the card to another
// prober for seconds, so the waits grow from 50 ms to 1 s and stop once they
// add up to 10 s.
const ResolveRetryBudget kExclusiveAccess{
    .maxRetries = std::numeric_limits<int>::max(),
    .firstDelay = 50ms,
    .growth = 2,
    .maxDelay = 1000ms,
    .totalBudget = 10000ms,
};

} // namespace

// A card no plugin serves is opened once: the probe's answer is definitive,
// and every repeat would connect to a card that belongs to someone else, probe
// it and let it go. Nor is it held on the contact slot.
TEST(CardResolutionPolicy, AnUnservedCardIsOpenedOnceAndNotHeld)
{
    Insertion bench(/*servesCards=*/false, {});
    const CardResolutionPolicy policy;
    const auto out = bench.insert(policy, kContactSlot);

    EXPECT_TRUE(out.probe.opened());
    EXPECT_EQ(out.probe.capabilities, 0U);
    EXPECT_TRUE(out.waits.empty());
    EXPECT_EQ(bench.opens(), 1) << "an unserved card was opened again after the probe said no plugin serves it";
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(out.probe, rosterWithCardIn(kContactSlot), kContactSlot.cardKey))
        << "the contact slot holds a card no plugin serves";
}

// A served card on the contact slot takes the hold, and the probe's own
// session becomes it: no second open.
TEST(CardResolutionPolicy, AServedContactSlotCardIsHeldOnTheProbesSession)
{
    Insertion bench(/*servesCards=*/true, {});
    const CardResolutionPolicy policy;
    const auto out = bench.insert(policy, kContactSlot);

    ASSERT_TRUE(out.probe.opened());
    EXPECT_EQ(out.probe.capabilities, kPki);
    EXPECT_EQ(out.probe.cardType, "serving-stub");
    ASSERT_TRUE(CardResolutionPolicy::holdsReader(out.probe, rosterWithCardIn(kContactSlot), kContactSlot.cardKey));

    bench.operations().setReaderHold(kContactSlot.reader, true);
    ASSERT_NO_FATAL_FAILURE(bench.drain(kContactSlot));
    EXPECT_TRUE(bench.operations().isReaderHeldForTest(kContactSlot.reader));
    EXPECT_EQ(bench.opens(), 1) << "the hold opened a second connection beside the probe's";
}

// Only the contact slot of a dual-interface unit is held; its contactless
// twin and a single-interface reader never are, served or not.
TEST(CardResolutionPolicy, OnlyTheContactSlotOfADualInterfaceUnitIsHeld)
{
    const CardProbe served = openedProbe(kPki);
    const CardProbe unserved = openedProbe(0);
    const CardProbe refusedProbe = failedProbe(Kind::SessionRefused);
    PresenceRoster all;
    for (const auto& b : kBench) {
        all.readerNames.emplace_back(b.name);
        all.cardKeys.emplace_back(b.cardKey);
    }
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(served, all, "11")) << "a single-interface reader is never held";
    EXPECT_TRUE(CardResolutionPolicy::holdsReader(served, all, "12")) << "the OMNIKEY contact slot is held";
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(served, all, "13")) << "the OMNIKEY CL slot is never held";
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(unserved, all, "12"));
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(refusedProbe, all, "12"));
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(served, all, "99")) << "a card that is gone holds nothing";
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(served, all, ""));
}

// A probe that could not open the card says nothing about it, so it is asked
// again: two refused opens, then the open that served.
TEST(CardResolutionPolicy, AProbeThatCouldNotOpenTheCardIsAskedAgain)
{
    Insertion bench(/*servesCards=*/true, refused(2));
    const CardResolutionPolicy policy;
    const auto out = bench.insert(policy, kContactSlot);

    ASSERT_TRUE(out.probe.opened());
    EXPECT_EQ(out.probe.capabilities, kPki);
    EXPECT_EQ(bench.opens(), 3) << "two refused opens, then the one that served";
    EXPECT_EQ(out.waits, (std::vector<std::chrono::milliseconds>{50ms, 50ms}));
}

// The default budget is three quick repeats 50 ms apart. A card still refused
// after them is published with what is known -- nothing -- and not held.
TEST(CardResolutionPolicy, TheDefaultBudgetIsThreeQuickRepeats)
{
    Insertion bench(/*servesCards=*/true, refused(100));
    const CardResolutionPolicy policy;
    const auto out = bench.insert(policy, kContactSlot);

    EXPECT_FALSE(out.probe.opened());
    EXPECT_EQ(out.probe.capabilities, 0U);
    EXPECT_EQ(bench.opens(), 4) << "the first open and three repeats";
    EXPECT_EQ(out.waits, (std::vector<std::chrono::milliseconds>{50ms, 50ms, 50ms}));
    EXPECT_EQ(out.attempts.retries, 3);
    EXPECT_EQ(out.attempts.waited, 150ms);
    EXPECT_FALSE(CardResolutionPolicy::holdsReader(out.probe, rosterWithCardIn(kContactSlot), kContactSlot.cardKey));
}

// Another prober holding the card at insertion may keep it for longer than a
// few quick repeats last. Under the exclusive-access budget, six refused opens
// (2.55 s of growing waits) still end in the card published with what its
// plugin serves.
TEST(CardResolutionPolicy, AProbeRefusedForSecondsStillPublishesTheServedCard)
{
    Insertion bench(/*servesCards=*/true, refused(6));
    const CardResolutionPolicy policy{kExclusiveAccess};
    const auto out = bench.insert(policy, kContactSlot);

    ASSERT_TRUE(out.probe.opened());
    EXPECT_EQ(out.probe.capabilities, kPki) << "published with what its plugin serves";
    EXPECT_EQ(bench.opens(), 7) << "six refused opens, then the one that served";
    EXPECT_EQ(out.waits, (std::vector<std::chrono::milliseconds>{50ms, 100ms, 200ms, 400ms, 800ms, 1000ms}));
    EXPECT_EQ(out.attempts.waited, 2550ms);
}

// The waits grow to their cap and stop once together they reach the budget;
// the schedule is finite whatever the card does.
TEST(CardResolutionPolicy, GrowsToItsCapAndEndsAtTheBudget)
{
    const CardResolutionPolicy policy{kExclusiveAccess};
    EXPECT_EQ(policy.nextRetry({.retries = 0, .waited = 0ms}), 50ms);
    EXPECT_EQ(policy.nextRetry({.retries = 1, .waited = 50ms}), 100ms);
    EXPECT_EQ(policy.nextRetry({.retries = 40, .waited = 0ms}), 1000ms);
    EXPECT_FALSE(policy.nextRetry({.retries = 3, .waited = 10000ms}).has_value());

    const CardProbe refusedProbe = failedProbe(Kind::SessionRefused);
    ResolveAttempts attempts;
    while (policy.retryAfter(refusedProbe, attempts)) {
        ASSERT_LT(attempts.retries, 100) << "the schedule never ended";
    }
    EXPECT_GE(attempts.waited, kExclusiveAccess.totalBudget);
    EXPECT_LT(attempts.waited, kExclusiveAccess.totalBudget + kExclusiveAccess.maxDelay);
    EXPECT_EQ(attempts.retries, 14) << "50 + 100 + 200 + 400 + 800 + 9 x 1000 ms";
}

// A growth so large that one step would overflow the duration still lands on
// the cap, not on a wrapped-around wait.
TEST(CardResolutionPolicy, ALargeGrowthLandsOnTheCap)
{
    const CardResolutionPolicy policy{ResolveRetryBudget{.maxRetries = 10,
                                                         .firstDelay = 50ms,
                                                         .growth = std::numeric_limits<int>::max(),
                                                         .maxDelay = 1000ms,
                                                         .totalBudget = std::chrono::milliseconds::max()}};
    for (int retries = 1; retries < 10; ++retries) {
        EXPECT_EQ(policy.nextRetry({.retries = retries, .waited = 0ms}), 1000ms) << retries;
    }
}

// The host decides which failures are worth another try. A refusal its
// predicate turns down is answered at once: one open, nothing asked again.
TEST(CardResolutionPolicy, AFailureThePredicateTurnsDownIsAnsweredAtOnce)
{
    Insertion bench(/*servesCards=*/true, refused(2, Kind::NoCardPresent));
    const CardResolutionPolicy policy{kExclusiveAccess,
                                      [](const OpenError& failure) { return failure.kind != Kind::NoCardPresent; }};
    const auto out = bench.insert(policy, kContactSlot);

    EXPECT_FALSE(out.probe.opened());
    EXPECT_EQ(bench.opens(), 1) << "an empty reader was asked again";
    EXPECT_TRUE(out.waits.empty());
    EXPECT_EQ(out.attempts.retries, 0);
}

// The predicate sees each failure as it comes: a refusal it retries, then one
// it does not, ends the insertion on the second open.
TEST(CardResolutionPolicy, ThePredicateJudgesEachFailure)
{
    Insertion bench(/*servesCards=*/true, {Kind::SessionRefused, Kind::NoCardPresent});
    const CardResolutionPolicy policy{kExclusiveAccess,
                                      [](const OpenError& failure) { return failure.kind == Kind::SessionRefused; }};
    const auto out = bench.insert(policy, kContactSlot);

    ASSERT_FALSE(out.probe.opened());
    EXPECT_EQ(out.probe.openFailure->kind, Kind::NoCardPresent);
    EXPECT_EQ(bench.opens(), 2);
    EXPECT_EQ(out.waits, (std::vector<std::chrono::milliseconds>{50ms}));
}

// A probe that opened the card is an answer whatever the predicate says: the
// predicate is consulted only for a failed open.
TEST(CardResolutionPolicy, AnOpenedProbeIsNeverAskedAgain)
{
    int asked = 0;
    const CardResolutionPolicy policy{{}, [&asked](const OpenError&) {
                                          ++asked;
                                          return true;
                                      }};
    ResolveAttempts attempts;
    EXPECT_FALSE(policy.retryAfter(openedProbe(0), attempts).has_value());
    EXPECT_FALSE(policy.retryAfter(openedProbe(kPki), attempts).has_value());
    EXPECT_EQ(asked, 0);
    EXPECT_EQ(attempts.retries, 0);
}

// An empty predicate is the default one, not a call through an empty
// std::function on the first refusal.
TEST(CardResolutionPolicy, AnEmptyPredicateRetriesEveryFailedOpen)
{
    const CardResolutionPolicy policy{{}, CardResolutionPolicy::RetryPredicate{}};
    ResolveAttempts attempts;
    EXPECT_EQ(policy.retryAfter(failedProbe(Kind::ProtocolError), attempts), 50ms);
}

// Card removal releases the hold of the card's reader and nothing else, so a
// later idle sweep cannot re-acquire a hold on an empty reader. Driven through
// releaseReaderOnCardRemoved() -- the helper every host's removal hook calls.
TEST(CardRemoval, ReleasesTheHoldOfItsReaderOnly)
{
    Insertion bench(/*servesCards=*/true, {});
    auto& ops = bench.operations();
    for (const auto& b : kBench) {
        ASSERT_NO_FATAL_FAILURE(bench.drain(b)); // materialise every worker
        ops.setReaderHold(b.reader, true);
    }

    releaseReaderOnCardRemoved(ops, kContactSlot.reader);

    EXPECT_FALSE(ops.isReaderHeldForTest(kContactSlot.reader)) << "the flag is the host's to clear on removal";
    EXPECT_TRUE(ops.isReaderHeldForTest(kBench[0].reader)) << "an unrelated reader is untouched";
    EXPECT_TRUE(ops.isReaderHeldForTest(kBench[2].reader)) << "an unrelated reader is untouched";
}
