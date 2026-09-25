// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <memory>

using namespace LibreSCRS::Agent::Operations;
using Cap = LibreSCRS::Plugin::CardCapabilities;
using LibreSCRS::Auth::PreReadAuthMethod;

TEST(CardSessionHolder, OpensOnceAndReuses)
{
    int opens = 0;
    auto factory = [&opens](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        ++opens;
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    auto map = std::make_shared<LibreSCRS::SmartCard::CardMap>();
    CardSessionHolder h{"R", factory, resolver, map};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 1) << "second acquire reuses the held session";
    EXPECT_EQ(a->session.get(), b->session.get()) << "same session handle";

    h.invalidate();
    auto c = h.acquire();
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(opens, 2) << "acquire after invalidate re-opens";
}

TEST(CardSessionHolder, ResolvesCandidatesOnce)
{
    int resolves = 0;
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [&resolves](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) {
        ++resolves;
        return CandidateList{};
    };
    CardSessionHolder h{"R", factory, resolver, std::make_shared<LibreSCRS::SmartCard::CardMap>()};
    (void)h.acquire();
    (void)h.acquire();
    EXPECT_EQ(resolves, 1) << "candidates resolved once per held session";
}

namespace {

// Counting factory: returns a fresh detached CardSession each call and bumps
// @p opens. A canned resolver and a fake, test-advanced clock complete the
// deterministic idle-close fixture (no PC/SC, no wall clock).
SessionFactory makeCountingFactory(int& opens)
{
    return [&opens](const std::string& r)
               -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        ++opens;
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
}

CandidateResolver makeCannedResolver()
{
    return [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
}

// Minimal CardPlugin double that declares fixed capabilities and reports a
// fixed pre-read auth method, counting how many times preReadAuth() is invoked
// on the held session (to assert the holder memoizes it).
class PreReadStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    PreReadStubPlugin(std::string id, Cap caps, PreReadAuthMethod method, int* preReadCalls)
        : m_caps(caps), m_method(method), m_preReadCalls(preReadCalls)
    {
        setIdentity(std::move(id), "preread-stub", 0);
    }
    Cap capabilities() const override
    {
        return m_caps;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        if (m_preReadCalls != nullptr) {
            ++(*m_preReadCalls);
        }
        return m_method;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    Cap m_caps;
    PreReadAuthMethod m_method;
    int* m_preReadCalls;
};

// Resolver seam that always returns a fixed candidate list (held-session
// resolution double): the holder copies it once per open session.
CandidateResolver makeCandidateResolver(CandidateList list)
{
    return [list = std::move(list)](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return list; };
}

} // namespace

TEST(CardSessionHolder, ResolvesPreReadAuthOnceAndClearsOnInvalidate)
{
    int opens = 0;
    int preReadCalls = 0;
    CandidateList candidates{
        std::make_shared<PreReadStubPlugin>("pace", Cap::IdentityData, PreReadAuthMethod::Can, &preReadCalls)};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(candidates),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    EXPECT_EQ(h.fullResolution().preReadAuth, PreReadAuthMethod::Can);
    EXPECT_EQ(h.fullResolution().preReadAuth, PreReadAuthMethod::Can);
    EXPECT_EQ(preReadCalls, 1) << "pre-read auth is memoized per held session (plugin queried once)";

    h.invalidate();
    EXPECT_EQ(h.fullResolution().preReadAuth, PreReadAuthMethod::Can);
    EXPECT_EQ(preReadCalls, 2) << "invalidate() clears the memo so the next call re-resolves";
}

TEST(CardSessionHolder, FullResolutionFromHeldSession)
{
    int opens = 0;
    int preReadCalls = 0;
    CandidateList candidates{std::make_shared<PreReadStubPlugin>("pace", Cap::IdentityData | Cap::PKI,
                                                                 PreReadAuthMethod::Can, &preReadCalls)};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(candidates),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    auto r = h.fullResolution();
    EXPECT_EQ(r.capabilities, static_cast<std::uint32_t>(Cap::IdentityData | Cap::PKI));
    EXPECT_EQ(r.preReadAuth, PreReadAuthMethod::Can);
    EXPECT_FALSE(r.candidates.empty());
    EXPECT_EQ(opens, 1) << "fullResolution() resolves on the single held session";
}

TEST(CardSessionHolder, IdleCloseClosesAndReopens)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(opens, 1);

    now += CardSessionHolder::kIdleClose;
    h.closeIfIdle();

    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 2) << "idle session was closed and the next acquire re-opened";
    EXPECT_NE(a->session.get(), b->session.get()) << "re-opened session is a distinct handle";
}

TEST(CardSessionHolder, NotYetIdleIsNoOp)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(opens, 1);

    now += CardSessionHolder::kIdleClose / 2;
    h.closeIfIdle();

    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 1) << "not-yet-idle session is kept open";
    EXPECT_EQ(a->session.get(), b->session.get()) << "same session handle";
}

TEST(CardSessionHolder, ActivityResetsIdle)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(opens, 1);

    // Advance < kIdleClose, then acquire again (this must re-stamp lastUsed).
    now += CardSessionHolder::kIdleClose * 3 / 4;
    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 1);

    // Total elapsed since the FIRST acquire now exceeds kIdleClose, but the
    // gap since the SECOND acquire is still below it: a correctly-stamped
    // lastUsed keeps the session open.
    now += CardSessionHolder::kIdleClose / 2;
    h.closeIfIdle();

    auto c = h.acquire();
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(opens, 1) << "every acquire re-stamps lastUsed, so the reader is not idle";
    EXPECT_EQ(b->session.get(), c->session.get()) << "same session handle";
}

// ---- Power hold: a bare second session that keeps the card powered ----------

// A counting resolver, so a test can prove the hold is NEVER resolved (no
// plugin ever sees the hold session).
namespace {
CandidateResolver makeCountingResolver(int& resolves)
{
    return [&resolves](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) {
        ++resolves;
        return CandidateList{};
    };
}
} // namespace

TEST(CardSessionHolder, HoldOpensThroughFactoryWithoutResolving)
{
    int opens = 0;
    int resolves = 0;
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCountingResolver(resolves),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    EXPECT_FALSE(h.hasHoldForTest());
    h.acquireHold();
    EXPECT_TRUE(h.hasHoldForTest());
    EXPECT_EQ(opens, 1) << "the hold is one bare session open";
    EXPECT_EQ(resolves, 0) << "the hold is never resolved: no plugin sees it";

    h.acquireHold();
    EXPECT_EQ(opens, 1) << "a second acquireHold is a no-op while the hold exists";
    EXPECT_TRUE(h.hasHoldForTest());
}

TEST(CardSessionHolder, HoldSurvivesIdleCloseOfLogicalSession)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    h.acquireHold();
    EXPECT_EQ(opens, 2) << "logical session + hold";

    now += CardSessionHolder::kIdleClose;
    h.closeIfIdle();

    EXPECT_TRUE(h.hasHoldForTest()) << "idle-close touches only the logical session";
    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 3) << "the logical session was closed and re-opened";
    EXPECT_NE(a->session.get(), b->session.get());
}

TEST(CardSessionHolder, ReleaseHoldDropsOnlyTheHold)
{
    int opens = 0;
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    h.acquireHold();
    ASSERT_TRUE(h.hasHoldForTest());

    h.releaseHold();
    EXPECT_FALSE(h.hasHoldForTest());
    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(a->session.get(), b->session.get()) << "the logical session is untouched by releaseHold";
    EXPECT_EQ(opens, 2);

    h.releaseHold(); // no-op without a hold
    EXPECT_FALSE(h.hasHoldForTest());
}

TEST(CardSessionHolder, HoldOpenFailureLeavesNoHold)
{
    int calls = 0;
    SessionFactory failing = [&calls](const std::string&)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        ++calls;
        return std::unexpected{LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                               LibreSCRS::LocalizedText{}, std::nullopt}};
    };
    CardSessionHolder h{"R", failing, makeCannedResolver(), std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    EXPECT_NO_THROW(h.acquireHold());
    EXPECT_FALSE(h.hasHoldForTest());
    EXPECT_EQ(calls, 1);
    h.acquireHold(); // retry is allowed: the worker retries at its next sweep
    EXPECT_EQ(calls, 2);
    EXPECT_FALSE(h.hasHoldForTest());
}

TEST(CardSessionHolder, InvalidateLeavesHoldAlone)
{
    int opens = 0;
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    ASSERT_TRUE(h.acquire().has_value());
    h.acquireHold();
    h.invalidate();
    EXPECT_TRUE(h.hasHoldForTest()) << "the worker, not the holder, decides when the hold goes";
    ASSERT_TRUE(h.acquire().has_value());
    EXPECT_EQ(opens, 3) << "logical re-opened after invalidate; the hold was not re-opened";
}

// ---- Secure-channel probe seam ---------------------------------------------

TEST(CardSessionHolder, SmProbeIsConsultedByAcquireHold)
{
    int opens = 0;
    int probeCalls = 0;
    CardSessionHolder h{"R",
                        makeCountingFactory(opens),
                        makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(),
                        {},
                        [&probeCalls](const LibreSCRS::SmartCard::CardSession&) {
                            ++probeCalls;
                            return false;
                        }};

    ASSERT_TRUE(h.acquire().has_value());
    EXPECT_EQ(probeCalls, 0) << "acquire() does not consult the probe";

    h.acquireHold();
    EXPECT_EQ(probeCalls, 1) << "acquireHold() asks the injected probe about the held session";
}

// The hold is a SECOND PC/SC connection on the same reader. Opening one while
// the logical session on that reader is mid-secure-channel puts a second
// handle on a card that is already powered and already talking, for no gain.
// The skip is deliberately narrow: only while that session is also still
// active, so the sweep that is about to idle-close it takes the hold FIRST and
// the handle-free window stays the one the power-hold design measured.

TEST(CardSessionHolder, HoldIsSkippedWhileSecureChannelLivesOnAnActiveSession)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R",
                        makeCountingFactory(opens),
                        makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(),
                        [&now] { return now; },
                        [](const LibreSCRS::SmartCard::CardSession&) { return true; }};

    ASSERT_TRUE(h.acquire().has_value());
    EXPECT_EQ(opens, 1);

    h.acquireHold();
    EXPECT_FALSE(h.hasHoldForTest()) << "no second handle while the session carries a live secure channel";
    EXPECT_EQ(opens, 1) << "the factory was not called a second time";
}

TEST(CardSessionHolder, HoldIsTakenBeforeIdleCloseEvenWithLiveSecureChannel)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R",
                        makeCountingFactory(opens),
                        makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(),
                        [&now] { return now; },
                        [](const LibreSCRS::SmartCard::CardSession&) { return true; }};

    ASSERT_TRUE(h.acquire().has_value());
    EXPECT_EQ(opens, 1);

    // The session has gone idle: the sweep is about to close it, so the hold
    // must be taken now or the card loses power between the two.
    now += CardSessionHolder::kIdleClose;
    h.acquireHold();
    EXPECT_TRUE(h.hasHoldForTest()) << "a session about to idle-close is held first";
    EXPECT_EQ(opens, 2);
}

TEST(CardSessionHolder, HoldIsTakenWhenNoSecureChannel)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R",
                        makeCountingFactory(opens),
                        makeCannedResolver(),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>(),
                        [&now] { return now; },
                        [](const LibreSCRS::SmartCard::CardSession&) { return false; }};

    ASSERT_TRUE(h.acquire().has_value());
    h.acquireHold();
    EXPECT_TRUE(h.hasHoldForTest()) << "an active session without a secure channel does not block the hold";
    EXPECT_EQ(opens, 2);
}
