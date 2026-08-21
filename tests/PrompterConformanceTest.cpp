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
//   3. cancel(promptId) is noexcept, ADDRESSED (it names which prompt to
//      dismiss, because more than one dialog can be on screen), and its default
//      base implementation is a no-op (a trivial subclass that does not
//      override it stays valid + silent); an overriding fake observes the id.

#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>

#include <LibreSCRS/Secure/String.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
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
    std::string lastCancelledId;

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
    void cancel(const std::string& promptId) noexcept override
    {
        ++cancelCount;
        lastCancelledId = promptId;
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

// cancel is addressed AND noexcept -- both halves of the frozen contract. The
// signature is asserted, not just the noexcept: an unaddressed cancel would
// compile everywhere and close the wrong card's dialog at runtime.
static_assert(
    std::is_same_v<decltype(&PrompterClientBase::cancel), void (PrompterClientBase::*)(const std::string&) noexcept>,
    "frozen: Prompter::cancel(const std::string& promptId) is the addressed, noexcept cancel");

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

TEST(PrompterConformance, CancelCarriesItsPromptIdAndIsNoopByDefault)
{
    FakePrompter fake;
    EXPECT_EQ(fake.cancelCount, 0);
    fake.cancel("nonce:7");
    EXPECT_EQ(fake.cancelCount, 1);
    EXPECT_EQ(fake.lastCancelledId, "nonce:7");

    // The base default is a no-op: calling it on a subclass that does not
    // override it must be silent and must not throw (it is noexcept).
    TrivialPrompter trivial;
    trivial.cancel("nonce:8");
    SUCCEED();
}

TEST(PrompterConformance, EntryExpiryIsNotAUserCancellation)
{
    // A window that ran out of time and a holder who dismissed it are different
    // events, and a client that conflates them tells the holder they cancelled
    // something the clock took.
    EXPECT_NE(PromptStatus::Timeout, PromptStatus::Cancelled);
    EXPECT_NE(PromptStatus::Timeout, PromptStatus::Ok);
    EXPECT_NE(PromptStatus::Timeout, PromptStatus::Error);
    // A refusal to raise the prompt is none of the three above: not a cancel,
    // not a broken prompter, and not a clock that ran out.
    EXPECT_NE(PromptStatus::HelperTooOld, PromptStatus::Cancelled);
    EXPECT_NE(PromptStatus::HelperTooOld, PromptStatus::Error);
    EXPECT_NE(PromptStatus::HelperTooOld, PromptStatus::Timeout);
}

// Appended, never inserted: the three values below it are compiled into every
// consumer built against an older header, so renumbering them would silently
// change what an existing binary reads off the wire.
static_assert(static_cast<std::uint8_t>(PromptStatus::Ok) == 0);
static_assert(static_cast<std::uint8_t>(PromptStatus::Cancelled) == 1);
static_assert(static_cast<std::uint8_t>(PromptStatus::Error) == 2);
static_assert(static_cast<std::uint8_t>(PromptStatus::Timeout) == 3);
static_assert(static_cast<std::uint8_t>(PromptStatus::HelperTooOld) == 4);
