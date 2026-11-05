// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include "operations/FlowPrelude.h"
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <gtest/gtest.h>

#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <memory>
#include <utility>

using namespace LibreSCRS::Agent::Operations;
using Cap = LibreSCRS::Plugin::CardCapabilities;
using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Auth::PreReadAuthMethod;

TEST(CardSessionHolder, OpensOnceAndReuses)
{
    int opens = 0;
    auto factory = [&opens](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        ++opens;
        return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    CardSessionHolder h{"R", factory, resolver};

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
        return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
    };
    auto resolver = [&resolves](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) {
        ++resolves;
        return CandidateList{};
    };
    CardSessionHolder h{"R", factory, resolver};
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
        return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
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
        setIdentity(std::move(id), 0);
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
    void clearCredentials(LibreSCRS::SmartCard::CardSession& /*session*/) noexcept override
    {
        ++m_clearCalls;
    }

    int m_clearCalls = 0;

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
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(candidates)};

    EXPECT_EQ(h.fullResolution().value().preReadAuth, PreReadAuthMethod::Can);
    EXPECT_EQ(h.fullResolution().value().preReadAuth, PreReadAuthMethod::Can);
    EXPECT_EQ(preReadCalls, 1) << "pre-read auth is memoized per held session (plugin queried once)";

    h.invalidate();
    EXPECT_EQ(h.fullResolution().value().preReadAuth, PreReadAuthMethod::Can);
    EXPECT_EQ(preReadCalls, 2) << "invalidate() clears the memo so the next call re-resolves";
}

TEST(CardSessionHolder, FullResolutionFromHeldSession)
{
    int opens = 0;
    int preReadCalls = 0;
    CandidateList candidates{std::make_shared<PreReadStubPlugin>("pace", Cap::IdentityData | Cap::PKI,
                                                                 PreReadAuthMethod::Can, &preReadCalls)};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(candidates)};

    auto r = h.fullResolution();
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->capabilities, static_cast<std::uint32_t>(Cap::IdentityData | Cap::PKI));
    EXPECT_EQ(r->preReadAuth, PreReadAuthMethod::Can);
    EXPECT_FALSE(r->candidates.empty());
    EXPECT_EQ(opens, 1) << "fullResolution() resolves on the single held session";
}

TEST(CardSessionHolder, IdleCloseClosesAndReopens)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(opens, 1);

    now += CardSessionHolder::kIdleClose;
    h.sweep(/*holdWanted=*/false);

    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 2) << "idle session was closed and the next acquire re-opened";
    EXPECT_NE(a->session.get(), b->session.get()) << "re-opened session is a distinct handle";
}

TEST(CardSessionHolder, NotYetIdleIsNoOp)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(opens, 1);

    now += CardSessionHolder::kIdleClose / 2;
    h.sweep(/*holdWanted=*/false);

    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 1) << "not-yet-idle session is kept open";
    EXPECT_EQ(a->session.get(), b->session.get()) << "same session handle";
}

TEST(CardSessionHolder, ActivityResetsIdle)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(), [&now] { return now; }};

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
    h.sweep(/*holdWanted=*/false);

    auto c = h.acquire();
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(opens, 1) << "every acquire re-stamps lastUsed, so the reader is not idle";
    EXPECT_EQ(b->session.get(), c->session.get()) << "same session handle";
}

// ---- Power hold: the reader's one session, parked to keep the card powered ---

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

// A resolver that throws must not leave a session behind: the next acquire
// would otherwise reuse it with no candidates and never resolve again.
TEST(CardSessionHolder, AResolverThatThrowsLeavesNoSessionBehind)
{
    int opens = 0;
    int resolves = 0;
    auto plugin = std::make_shared<PreReadStubPlugin>("pkcs15", Cap::PKI, PreReadAuthMethod::None, nullptr);
    CandidateResolver resolver = [&resolves, plugin](std::span<const std::uint8_t>,
                                                     LibreSCRS::SmartCard::CardSession&) -> CandidateList {
        if (++resolves == 1) {
            throw std::runtime_error("plugin probe failed");
        }
        return CandidateList{plugin};
    };
    CardSessionHolder h{"R", makeCountingFactory(opens), resolver};

    EXPECT_THROW(static_cast<void>(h.acquire()), std::runtime_error);
    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(resolves, 2) << "the second acquire resolves again";
    ASSERT_EQ(a->candidates.size(), 1U);
    EXPECT_EQ(a->candidates[0], plugin);
}

TEST(CardSessionHolder, HoldOpensThroughFactoryWithoutResolving)
{
    int opens = 0;
    int resolves = 0;
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCountingResolver(resolves)};

    EXPECT_FALSE(h.hasHoldForTest());
    h.acquireHold();
    EXPECT_TRUE(h.hasHoldForTest());
    EXPECT_EQ(opens, 1) << "the hold is one bare session open";
    EXPECT_EQ(resolves, 0) << "the hold is never resolved: no plugin sees it";

    h.acquireHold();
    EXPECT_EQ(opens, 1) << "a second acquireHold is a no-op while the hold exists";
    EXPECT_TRUE(h.hasHoldForTest());
}

// A reader has at most one connection: the hold is the logical session itself,
// demoted once idle, never a second open beside it.
TEST(CardSessionHolder, IdleSweepWithHoldDemotesInsteadOfClosing)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(), [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    h.acquireHold();
    EXPECT_FALSE(h.hasHoldForTest()) << "no second connection while the session stands";
    EXPECT_EQ(opens, 1);

    now += CardSessionHolder::kIdleClose;
    h.sweep(/*holdWanted=*/true);
    EXPECT_TRUE(h.hasHoldForTest()) << "the idle session became the hold";
    EXPECT_EQ(opens, 1) << "demote opens nothing";

    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(opens, 1) << "the next operation reuses the held connection";
    EXPECT_EQ(a->session.get(), b->session.get());
    EXPECT_FALSE(h.hasHoldForTest()) << "promoted back: never both slots";
}

TEST(CardSessionHolder, ReleaseHoldDropsOnlyTheHold)
{
    int opens = 0;
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver()};

    h.acquireHold();
    ASSERT_TRUE(h.hasHoldForTest());
    h.releaseHold();
    EXPECT_FALSE(h.hasHoldForTest());

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    h.releaseHold(); // no hold: the logical session is untouched
    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(a->session.get(), b->session.get());
    EXPECT_EQ(opens, 2);
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
    CardSessionHolder h{"R", failing, makeCannedResolver()};

    EXPECT_NO_THROW(h.acquireHold());
    EXPECT_FALSE(h.hasHoldForTest());
    EXPECT_EQ(calls, 1);
    h.acquireHold(); // retry is allowed: the worker retries at its next sweep
    EXPECT_EQ(calls, 2);
    EXPECT_FALSE(h.hasHoldForTest());
}

TEST(CardSessionHolder, InvalidateDropsBothSlots)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(), [&now] { return now; }};

    ASSERT_TRUE(h.acquire().has_value());
    now += CardSessionHolder::kIdleClose;
    h.sweep(true);
    ASSERT_TRUE(h.hasHoldForTest());

    h.invalidate(); // the card was removed: nothing is left to keep powered
    EXPECT_FALSE(h.hasHoldForTest());
    ASSERT_TRUE(h.acquire().has_value());
    EXPECT_EQ(opens, 2) << "a new card is opened afresh";
}

TEST(CardSessionHolder, HoldIsNeverOpenedWhileASessionExists)
{
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCannedResolver(), [&now] { return now; }};

    ASSERT_TRUE(h.acquire().has_value());
    for (int i = 0; i < 3; ++i) {
        h.acquireHold();
        now += CardSessionHolder::kIdleClose / 2;
        h.sweep(true);
        ASSERT_TRUE(h.acquire().has_value());
    }
    EXPECT_EQ(opens, 1) << "one connection for the whole run";
}

namespace {

// Counts the sessions alive at once on the reader: each one the factory opens
// is counted until its last owner lets go of it.
struct LiveCount
{
    int live = 0;
    int maxLive = 0;
    int opens = 0;
};

SessionFactory makeLiveCountingFactory(const std::shared_ptr<LiveCount>& count)
{
    return [count](const std::string& r)
               -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        auto real = LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
        ++count->opens;
        count->maxLive = std::max(count->maxLive, ++count->live);
        auto* raw = real.get();
        return std::shared_ptr<LibreSCRS::SmartCard::CardSession>(
            raw, [count, real](LibreSCRS::SmartCard::CardSession*) mutable {
                --count->live;
                real.reset();
            });
    };
}

} // namespace

TEST(CardSessionHolder, LiveSessionsNeverExceedOneOnAReader)
{
    auto count = std::make_shared<LiveCount>();
    auto now = std::chrono::steady_clock::time_point{};
    CardSessionHolder h{"R", makeLiveCountingFactory(count), makeCannedResolver(), [&now] { return now; }};

    {
        auto a = h.acquire();
        ASSERT_TRUE(a.has_value());
    }
    EXPECT_EQ(count->live, 1);
    h.acquireHold(); // the hold is wanted from here on
    EXPECT_LE(count->live, 1);

    now += CardSessionHolder::kIdleClose;
    h.sweep(true);
    EXPECT_EQ(count->live, 1) << "while the hold is wanted the card stays connected";

    {
        auto b = h.acquire();
        ASSERT_TRUE(b.has_value());
    }
    EXPECT_EQ(count->live, 1);
    now += CardSessionHolder::kIdleClose;
    h.sweep(true);
    EXPECT_EQ(count->live, 1);

    h.releaseHold(); // the hold is no longer wanted
    h.sweep(false);
    EXPECT_LE(count->live, 1);

    h.invalidate();
    EXPECT_EQ(count->live, 0);
    EXPECT_EQ(count->maxLive, 1) << "never two connections at once";
}

TEST(CardSessionHolder, DemoteErasesWhatThePluginsHeldAndKeepsTheHandle)
{
    int opens = 0;
    int resolves = 0;
    auto now = std::chrono::steady_clock::time_point{};
    auto pki = std::make_shared<PreReadStubPlugin>("pkcs15", Cap::PKI, PreReadAuthMethod::None, nullptr);
    auto emrtd = std::make_shared<PreReadStubPlugin>("emrtd", Cap::EmrtdCrypto, PreReadAuthMethod::Can, nullptr);
    CandidateResolver resolver = [&resolves, pki, emrtd](std::span<const std::uint8_t>,
                                                         LibreSCRS::SmartCard::CardSession&) {
        ++resolves;
        return CandidateList{pki, emrtd};
    };
    CardSessionHolder h{"R", makeCountingFactory(opens), resolver, [&now] { return now; }};

    auto a = h.acquire();
    ASSERT_TRUE(a.has_value());
    now += CardSessionHolder::kIdleClose;
    h.sweep(true);

    EXPECT_EQ(pki->m_clearCalls, 1) << "every candidate forgets what it held for the session";
    EXPECT_EQ(emrtd->m_clearCalls, 1);
    EXPECT_TRUE(h.hasHoldForTest());
    EXPECT_EQ(opens, 1);
    EXPECT_FALSE(a->session->hasLiveSecureChannel());

    // AcquireAfterDemotePromotesWithoutTheFactory, and the composite card keeps
    // the union of its plugins: the candidates are resolved again, in order.
    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->session.get(), a->session.get());
    EXPECT_EQ(opens, 1);
    EXPECT_EQ(resolves, 2);
    ASSERT_EQ(b->candidates.size(), 2U);
    EXPECT_EQ(b->candidates[0], pki);
    EXPECT_EQ(b->candidates[1], emrtd);
}

// A session that ran secure messaging is never parked: clearing the host's
// keys leaves the chip mid-session, and a held connection would keep it
// powered there. The idle sweep closes it even though a hold is wanted; the
// next operation opens a fresh connection.
TEST(CardSessionHolder, AnIdleSessionWithLiveSecureMessagingIsClosedNotHeld)
{
    auto count = std::make_shared<LiveCount>();
    auto now = std::chrono::steady_clock::time_point{};
    auto plugin = std::make_shared<PreReadStubPlugin>("emrtd", Cap::EmrtdCrypto, PreReadAuthMethod::Can, nullptr);
    CardSessionHolder h{"R", makeLiveCountingFactory(count), makeCandidateResolver(CandidateList{plugin}),
                        [&now] { return now; }};

    {
        auto a = h.acquire();
        ASSERT_TRUE(a.has_value());
        LibreSCRS::SmartCard::Testing::installStandInChannel(
            *a->session, LibreSCRS::SmartCard::Testing::StandInChannel::LiveSecureMessaging);
        ASSERT_TRUE(a->session->hasLiveSecureChannel());
    }

    now += CardSessionHolder::kIdleClose;
    h.sweep(/*holdWanted=*/true);
    EXPECT_FALSE(h.hasHoldForTest()) << "a secure-messaging session is not parked in the hold";
    EXPECT_EQ(count->live, 0) << "its connection is closed";
    EXPECT_EQ(plugin->m_clearCalls, 1) << "and what the plugins held for it is erased";

    auto b = h.acquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(count->opens, 2) << "the next operation opens a fresh connection";
    EXPECT_FALSE(b->session->hasLiveSecureChannel());
}

// The other channel states are no reason to drop the connection: a plain
// channel, or one whose secure messaging already failed, is parked like a
// session with no channel at all.
TEST(CardSessionHolder, AnIdleSessionWithoutLiveSecureMessagingIsDemoted)
{
    using LibreSCRS::SmartCard::Testing::StandInChannel;
    for (const auto channel : {StandInChannel::Plain, StandInChannel::FailedSecureMessaging}) {
        SCOPED_TRACE(static_cast<int>(channel));
        auto count = std::make_shared<LiveCount>();
        auto now = std::chrono::steady_clock::time_point{};
        CardSessionHolder h{"R", makeLiveCountingFactory(count), makeCannedResolver(), [&now] { return now; }};

        auto a = h.acquire();
        ASSERT_TRUE(a.has_value());
        LibreSCRS::SmartCard::Testing::installStandInChannel(*a->session, channel);
        ASSERT_FALSE(a->session->hasLiveSecureChannel());

        now += CardSessionHolder::kIdleClose;
        h.sweep(/*holdWanted=*/true);
        EXPECT_TRUE(h.hasHoldForTest()) << "the idle session became the hold";

        auto b = h.acquire();
        ASSERT_TRUE(b.has_value());
        EXPECT_EQ(b->session.get(), a->session.get()) << "the held connection is reused";
        EXPECT_EQ(count->opens, 1);
    }
}

TEST(CardSessionHolder, ClosingTheSessionErasesWhatThePluginsHeldForIt)
{
    // A plugin may keep a PIN deposited for the session's lease; closing the
    // session (card removal, idle close) is where it is forgotten.
    int opens = 0;
    auto now = std::chrono::steady_clock::time_point{};
    auto plugin = std::make_shared<PreReadStubPlugin>("pkcs15", Cap::PKI, PreReadAuthMethod::None, nullptr);
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(CandidateList{plugin}),
                        [&now] { return now; }};

    ASSERT_TRUE(h.acquire().has_value());
    h.invalidate();
    EXPECT_EQ(plugin->m_clearCalls, 1) << "invalidate() erases the plugin's per-session credentials";

    ASSERT_TRUE(h.acquire().has_value());
    now += CardSessionHolder::kIdleClose;
    h.sweep(/*holdWanted=*/false);
    EXPECT_EQ(plugin->m_clearCalls, 2) << "and so does the idle close";
}

// What the user is told when the session cannot be opened: a card that is not
// in the reader (never inserted, or pulled out between the presence event and
// the operation) is a removed card, not a communication fault. Every other
// open failure is one -- including a session the reader or the platform
// refused for now, which the user can retry.
TEST(FlowPreludeOpen, AnEmptyReaderIsARemovedCardAndEveryOtherFailureIsCommunication)
{
    using Kind = LibreSCRS::SmartCard::OpenError::Kind;
    const std::pair<Kind, ErrorCode> table[] = {
        {Kind::NoCardPresent, ErrorCode::CardRemoved},
        {Kind::ReaderUnavailable, ErrorCode::CommunicationError},
        {Kind::ProtocolError, ErrorCode::CommunicationError},
        {Kind::SessionRefused, ErrorCode::CommunicationError},
    };
    for (const auto& [kind, expected] : table) {
        SessionFactory failing = [kind](const std::string&)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            return std::unexpected{LibreSCRS::SmartCard::OpenError{kind, LibreSCRS::LocalizedText{}, std::nullopt}};
        };
        CardSessionHolder h{"R", failing, makeCannedResolver()};

        const auto out = FlowPrelude::openSession(h, LibreSCRS::CancelToken{});
        EXPECT_EQ(out.status, FlowPrelude::OpenStatus::OpenFailed) << static_cast<int>(kind);
        EXPECT_EQ(out.code, expected) << static_cast<int>(kind);
    }
}
