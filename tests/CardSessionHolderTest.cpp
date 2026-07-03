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
        std::make_shared<PreReadStubPlugin>("pace", Cap::IdentityData, PreReadAuthMethod::PaceCan, &preReadCalls)};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(candidates),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    EXPECT_EQ(h.fullResolution().preReadAuth, PreReadAuthMethod::PaceCan);
    EXPECT_EQ(h.fullResolution().preReadAuth, PreReadAuthMethod::PaceCan);
    EXPECT_EQ(preReadCalls, 1) << "pre-read auth is memoized per held session (plugin queried once)";

    h.invalidate();
    EXPECT_EQ(h.fullResolution().preReadAuth, PreReadAuthMethod::PaceCan);
    EXPECT_EQ(preReadCalls, 2) << "invalidate() clears the memo so the next call re-resolves";
}

TEST(CardSessionHolder, FullResolutionFromHeldSession)
{
    int opens = 0;
    int preReadCalls = 0;
    CandidateList candidates{std::make_shared<PreReadStubPlugin>("pace", Cap::IdentityData | Cap::PKI,
                                                                 PreReadAuthMethod::PaceCan, &preReadCalls)};
    CardSessionHolder h{"R", makeCountingFactory(opens), makeCandidateResolver(candidates),
                        std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    auto r = h.fullResolution();
    EXPECT_EQ(r.capabilities, static_cast<std::uint32_t>(Cap::IdentityData | Cap::PKI));
    EXPECT_EQ(r.preReadAuth, PreReadAuthMethod::PaceCan);
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
