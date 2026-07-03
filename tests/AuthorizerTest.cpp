// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic conformance coverage for the Authorizer backend interface and its
// two in-core implementations (AllowAllAuthorizer,
// DefaultAuthorizer). A recording FakeAuthorizer proves the interface is
// drivable with the frozen CallerToken key — no bus-name string leaks into the
// core surface. No live authorization backend is involved.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/Identity.h>

#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

using namespace LibreSCRS::Agent;

namespace {

// Records every (actionId, caller) pair it is asked to authorize and returns a
// caller-controlled verdict, proving the interface is implementable by a fake
// keyed on the opaque CallerToken.
class FakeAuthorizer final : public Authorizer
{
public:
    struct Call
    {
        std::string actionId;
        CallerToken caller;
    };

    explicit FakeAuthorizer(bool verdict) noexcept : m_verdict(verdict) {}

    [[nodiscard]] bool authorize(std::string_view actionId, const CallerToken& caller) override
    {
        m_calls.push_back(Call{std::string{actionId}, caller});
        return m_verdict;
    }

    [[nodiscard]] const std::vector<Call>& calls() const noexcept
    {
        return m_calls;
    }

private:
    bool m_verdict;
    std::vector<Call> m_calls;
};

} // namespace

TEST(Authorizer, FakeRecordsActionAndCallerAndReturnsVerdict)
{
    FakeAuthorizer allow{true};
    EXPECT_TRUE(allow.authorize(kActionSign, CallerToken{":1.42"}));
    ASSERT_EQ(allow.calls().size(), 1u);
    EXPECT_EQ(allow.calls()[0].actionId, std::string{kActionSign});
    EXPECT_EQ(allow.calls()[0].caller, CallerToken{":1.42"});

    FakeAuthorizer deny{false};
    EXPECT_FALSE(deny.authorize(kActionConfigure, CallerToken{":1.7"}));
    ASSERT_EQ(deny.calls().size(), 1u);
    EXPECT_EQ(deny.calls()[0].caller, CallerToken{":1.7"});
}

// The explicit "no policy gate" mode permits every action for any caller.
TEST(Authorizer, AllowAllPermitsEveryAction)
{
    AllowAllAuthorizer auth;
    EXPECT_TRUE(auth.authorize(kActionConfigure, CallerToken{":1.9"}));
    EXPECT_TRUE(auth.authorize(kActionConfigureTrust, CallerToken{":1.9"}));
    EXPECT_TRUE(auth.authorize(kActionSign, CallerToken{":1.9"}));
    EXPECT_TRUE(auth.authorize(kActionPkcs11Login, CallerToken{":1.9"}));
    EXPECT_TRUE(auth.authorize("org.librescrs.agent.future.unknown", CallerToken{":1.9"}));
    EXPECT_TRUE(auth.authorize(kActionConfigure, CallerToken{}));
}

// The authorizer-unreachable fallback is a fail-closed allow-LIST: the low-tier
// configure, the default-allow sign and the default-allow PKCS#11 login are
// permitted; the trust tier and any unknown action id are denied.
TEST(Authorizer, DefaultAllowsLowTierAndSignAndPkcs11LoginOnly)
{
    DefaultAuthorizer auth;
    EXPECT_TRUE(auth.authorize(kActionConfigure, CallerToken{":1.7"}));
    EXPECT_TRUE(auth.authorize(kActionSign, CallerToken{":1.7"}));
    EXPECT_TRUE(auth.authorize(kActionPkcs11Login, CallerToken{":1.7"}));
    EXPECT_FALSE(auth.authorize(kActionConfigureTrust, CallerToken{":1.7"}));
    EXPECT_FALSE(auth.authorize("org.librescrs.agent.future.unknown", CallerToken{":1.7"}));
}
