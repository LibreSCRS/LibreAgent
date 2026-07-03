// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic conformance test pinning the frozen Prompter backend surface
// (PrompterClientBase). Proves the interface with a fake so any drift in the
// signatures/semantics the platform impls must honour is caught at compile
// time (static_asserts) and run time:
//   1. The cleansing secret round-trips as std::optional<Secure::String>,
//      never an fd — value preserved, empty-but-present distinguishable.
//   2. requestPin/Can/Mrz take a const PromptOptions& and return PromptResult.
//   3. cancel() is noexcept and its default base implementation is a no-op
//      (a trivial subclass that does not override it stays valid + silent);
//      an overriding fake still observes the call.

#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>

#include <LibreSCRS/Secure/String.h>
#include <gtest/gtest.h>

#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>

using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PromptStatus;
using LibreSCRS::Agent::Operations::PrompterClientBase;

namespace {

// A fake exercising every arm of the frozen surface: Ok+secret from
// requestPin, Cancelled from requestCan, Error from requestMrz, and a
// recorded cancel().
class FakePrompter final : public PrompterClientBase
{
public:
    int cancelCount{0};

    PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"}, {}};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, {}};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Error, std::nullopt, {}};
    }
    void cancel() noexcept override
    {
        ++cancelCount;
    }
};

// A trivial subclass that deliberately does NOT override cancel(), proving the
// base default is a usable no-op (test fakes that ignore the cancel path stay
// simple).
class TrivialPrompter final : public PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
};

// --- Frozen-surface locks (compile-time) --------------------------------

// The cleansing secret is a std::optional<Secure::String> (never an fd).
static_assert(std::is_same_v<decltype(PromptResult::secret), std::optional<LibreSCRS::Secure::String>>,
              "frozen: PromptResult::secret is std::optional<Secure::String>");

// The three request methods take a const PromptOptions& and return PromptResult.
static_assert(std::is_same_v<decltype(&PrompterClientBase::requestPin),
                             PromptResult (PrompterClientBase::*)(const PromptOptions&)>,
              "frozen: requestPin(const PromptOptions&) -> PromptResult");
static_assert(std::is_same_v<decltype(&PrompterClientBase::requestCan),
                             PromptResult (PrompterClientBase::*)(const PromptOptions&)>,
              "frozen: requestCan(const PromptOptions&) -> PromptResult");
static_assert(std::is_same_v<decltype(&PrompterClientBase::requestMrz),
                             PromptResult (PrompterClientBase::*)(const PromptOptions&)>,
              "frozen: requestMrz(const PromptOptions&) -> PromptResult");

// cancel() is part of the frozen noexcept contract.
static_assert(noexcept(std::declval<PrompterClientBase&>().cancel()), "frozen: Prompter::cancel() must be noexcept");

} // namespace

TEST(PrompterConformance, CleansingSecretRoundTrips)
{
    FakePrompter fake;
    const PromptOptions options{};

    const PromptResult pin = fake.requestPin(options);
    ASSERT_EQ(pin.status, PromptStatus::Ok);
    ASSERT_TRUE(pin.secret.has_value());
    EXPECT_FALSE(pin.secret->empty());
    EXPECT_EQ(pin.secret->view(), std::string_view{"1234"});
}

TEST(PrompterConformance, CancelledAndErrorCarryNoSecret)
{
    FakePrompter fake;
    const PromptOptions options{};

    const PromptResult can = fake.requestCan(options);
    EXPECT_EQ(can.status, PromptStatus::Cancelled);
    EXPECT_FALSE(can.secret.has_value());

    const PromptResult mrz = fake.requestMrz(options);
    EXPECT_EQ(mrz.status, PromptStatus::Error);
    EXPECT_FALSE(mrz.secret.has_value());
}

TEST(PrompterConformance, CancelIsRecordedByOverrideAndNoopByDefault)
{
    FakePrompter fake;
    EXPECT_EQ(fake.cancelCount, 0);
    fake.cancel();
    EXPECT_EQ(fake.cancelCount, 1);

    // The base default cancel() is a no-op: calling it on a subclass that does
    // not override it must be silent and must not throw (it is noexcept).
    TrivialPrompter trivial;
    trivial.cancel();
    SUCCEED();
}
