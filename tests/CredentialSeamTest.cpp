// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Deterministic, card-free unit coverage for the credential seam and the
// multi-secret prompter seam:
//  - LmCredentialManager routing: every method reaches the matching CardPlugin
//    entry point on the passed session; list() lazy-falls-back to the first
//    non-empty getPINList; the mutating entry points route a REAL base-default
//    Unsupported to the next candidate but NEVER retry a mutation after any
//    other outcome (retry-counter safety).
//  - PrompterClientBase::requestPinChange: the appended defaulted virtual
//    fails closed (status Error, no secrets) for implementers of the frozen
//    single-secret surface.
//  - FakePrompter / FakeCredentialManager scriptability locks.
//  - The change_pin prompt-kind mirror string.
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include "fakes/FakeCredentialManager.h"
#include "fakes/FakePrompter.h"
#include "fakes/PinStubPlugin.h"

#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

static_assert(std::is_abstract_v<CredentialManager>);
static_assert(std::is_base_of_v<CredentialManager, LmCredentialManager>);
static_assert(std::is_base_of_v<CredentialManager, FakeCredentialManager>);

// PinOpsRecorder / BasePinPlugin / PinStubPlugin moved to fakes/PinStubPlugin.h
// (shared with the flow-level routing tests).

LibreSCRS::Plugin::PINResult pinResult(LibreSCRS::Plugin::PINResultOutcome outcome,
                                       std::optional<int> retriesLeft = std::nullopt)
{
    LibreSCRS::Plugin::PINResult r;
    r.outcome = outcome;
    r.retriesLeft = retriesLeft;
    return r;
}

LibreSCRS::Plugin::PinStatusEntry pinEntry(std::string label)
{
    LibreSCRS::Plugin::PinStatusEntry e;
    e.label = std::move(label);
    return e;
}

// A detached CardSession: the stubs ignore it, so it is never touched.
std::shared_ptr<LibreSCRS::SmartCard::CardSession> detachedSession()
{
    return LibreSCRS::SmartCard::detail::makeDetachedCardSession("FakeReader");
}

} // namespace

// --- LmCredentialManager::list (first-non-empty routing) -------------------

TEST(CredentialSeamRouting, ListFirstCandidateWithANonEmptyPinListWins)
{
    auto recEmpty = std::make_shared<PinOpsRecorder>();
    auto empty = std::make_shared<PinStubPlugin>("empty", recEmpty);
    auto rec = std::make_shared<PinOpsRecorder>();
    auto owner = std::make_shared<PinStubPlugin>("owner", rec);
    owner->pinList = {pinEntry("UserPIN"), pinEntry("SignaturePIN")};

    CandidateList candidates{empty, owner};
    auto session = detachedSession();

    auto listing = LmCredentialManager{}.list(*session, candidates);
    ASSERT_EQ(listing.entries.size(), 2u) << "the first non-empty candidate's PIN list is returned";
    EXPECT_EQ(listing.entries[0].label, "UserPIN");
    EXPECT_EQ(listing.pluginId, "owner") << "the listing is bound to the winning candidate's identity";
    EXPECT_EQ(recEmpty->pinListCalls, 1) << "the empty candidate was consulted first";
    EXPECT_EQ(rec->pinListCalls, 1);
}

TEST(CredentialSeamRouting, ListReachesGetPinListThroughTheLmBaseDefault)
{
    // A plugin that never overrode getPINList answers through the LM base
    // default: an empty list, not an error.
    CandidateList candidates{std::make_shared<BasePinPlugin>("base-only")};
    auto session = detachedSession();

    auto listing = LmCredentialManager{}.list(*session, candidates);
    EXPECT_TRUE(listing.entries.empty()) << "the LM base default reports no PINs";
    EXPECT_TRUE(listing.pluginId.empty()) << "no winner for an all-empty list";
}

TEST(CredentialSeamRouting, ListSkipsNullAndThrowingCandidates)
{
    auto recThrow = std::make_shared<PinOpsRecorder>();
    auto throwing = std::make_shared<PinStubPlugin>("throws", recThrow);
    throwing->throwOnPinList = true;
    auto rec = std::make_shared<PinOpsRecorder>();
    auto owner = std::make_shared<PinStubPlugin>("owner", rec);
    owner->pinList = {pinEntry("UserPIN")};

    CandidateList candidates{nullptr, throwing, owner};
    auto session = detachedSession();

    auto listing = LmCredentialManager{}.list(*session, candidates);
    ASSERT_EQ(listing.entries.size(), 1u) << "a throwing candidate is skipped, not fatal (read-only op)";
    EXPECT_EQ(listing.entries[0].label, "UserPIN");
    EXPECT_EQ(listing.pluginId, "owner") << "the skip does not confuse the winner identity";
}

TEST(CredentialSeamRouting, ListAllEmptyYieldsEmpty)
{
    auto rec = std::make_shared<PinOpsRecorder>();
    CandidateList candidates{std::make_shared<PinStubPlugin>("empty", rec)};
    auto session = detachedSession();

    auto listing = LmCredentialManager{}.list(*session, candidates);
    EXPECT_TRUE(listing.entries.empty());
    EXPECT_TRUE(listing.pluginId.empty());
}

// --- LmCredentialManager::changePIN ----------------------------------------

TEST(CredentialSeamRouting, ChangePinRoutesLabelAndSecretsToThePlugin)
{
    auto rec = std::make_shared<PinOpsRecorder>();
    auto stub = std::make_shared<PinStubPlugin>("owner", rec);
    stub->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    CandidateList candidates{stub};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.changePIN(*session, candidates, "UserPIN", LibreSCRS::Secure::String{"1111"},
                                             LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Ok);
    EXPECT_EQ(r.retriesLeft, 3) << "the plugin's PINResult is returned unmodified";
    EXPECT_EQ(rec->changeCalls, 1);
    EXPECT_EQ(rec->lastLabel, "UserPIN");
    EXPECT_TRUE(rec->lastOldPin == LibreSCRS::Secure::String{"1111"}) << "oldPin reaches the plugin verbatim";
    EXPECT_TRUE(rec->lastNewPin == LibreSCRS::Secure::String{"2222"}) << "newPin reaches the plugin verbatim";
}

TEST(CredentialSeamRouting, ChangePinBaseDefaultUnsupportedFallsThroughToTheNextCandidate)
{
    // First candidate never overrode changePIN: the seam observes the REAL LM
    // base default (Unsupported, no card interaction) and keeps routing.
    auto rec = std::make_shared<PinOpsRecorder>();
    auto impl = std::make_shared<PinStubPlugin>("implements", rec);
    impl->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok);
    CandidateList candidates{std::make_shared<BasePinPlugin>("base-only"), impl};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.changePIN(*session, candidates, "UserPIN", LibreSCRS::Secure::String{"1111"},
                                             LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Ok);
    EXPECT_EQ(rec->changeCalls, 1) << "the implementing candidate was reached";
}

TEST(CredentialSeamRouting, ChangePinRealFailureNeverFallsThrough)
{
    // InvalidPin is the card's answer (a retry was burned): the seam must
    // return it immediately and MUST NOT retry the mutation on the next
    // candidate — that would burn a second retry counter.
    auto recA = std::make_shared<PinOpsRecorder>();
    auto rejects = std::make_shared<PinStubPlugin>("rejects", recA);
    rejects->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::InvalidPin, 2);
    auto recB = std::make_shared<PinOpsRecorder>();
    auto wouldAccept = std::make_shared<PinStubPlugin>("would-accept", recB);
    wouldAccept->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok);
    CandidateList candidates{rejects, wouldAccept};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.changePIN(*session, candidates, "UserPIN", LibreSCRS::Secure::String{"0000"},
                                             LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::InvalidPin);
    EXPECT_EQ(r.retriesLeft, 2);
    EXPECT_EQ(recB->changeCalls, 0) << "a mutation is never retried on another candidate";
}

TEST(CredentialSeamRouting, ChangePinAllUnsupportedYieldsUnsupported)
{
    // A card whose plugins advertise no PIN change: a VALID call whose answer
    // is the Unsupported outcome (not an entry error).
    CandidateList candidates{std::make_shared<BasePinPlugin>("base-only")};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.changePIN(*session, candidates, "UserPIN", LibreSCRS::Secure::String{"1111"},
                                             LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
}

TEST(CredentialSeamRouting, ChangePinEmptyCandidateListYieldsUnsupported)
{
    auto session = detachedSession();
    auto r = LmCredentialManager{}.changePIN(*session, CandidateList{}, "UserPIN", LibreSCRS::Secure::String{"1111"},
                                             LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
}

TEST(CredentialSeamRouting, ChangePinThrowingCandidateYieldsPluginErrorAndStopsRouting)
{
    // A throw mid-mutation leaves the card state unknown: fail with
    // PluginError and do NOT try the next candidate.
    auto recA = std::make_shared<PinOpsRecorder>();
    auto throwing = std::make_shared<PinStubPlugin>("throws", recA);
    throwing->throwOnMutation = true;
    auto recB = std::make_shared<PinOpsRecorder>();
    auto next = std::make_shared<PinStubPlugin>("next", recB);
    next->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok);
    CandidateList candidates{throwing, next};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.changePIN(*session, candidates, "UserPIN", LibreSCRS::Secure::String{"1111"},
                                             LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::PluginError);
    EXPECT_EQ(recB->changeCalls, 0) << "routing stops after a throw (card state unknown)";
}

// --- LmCredentialManager::activateTransportPin -----------------------------

TEST(CredentialSeamRouting, ActivateTransportPinReachesItsEntryPoint)
{
    auto rec = std::make_shared<PinOpsRecorder>();
    auto stub = std::make_shared<PinStubPlugin>("owner", rec);
    stub->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok);
    CandidateList candidates{stub};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.activateTransportPin(
        *session, candidates, "UserPIN", LibreSCRS::Secure::String{"77777"}, LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Ok);
    EXPECT_EQ(rec->transportCalls, 1) << "reaches activateTransportPin, not another entry point";
    EXPECT_EQ(rec->changeCalls, 0);
    EXPECT_EQ(rec->lastLabel, "UserPIN");
    EXPECT_TRUE(rec->lastTransportValue == LibreSCRS::Secure::String{"77777"});
    EXPECT_TRUE(rec->lastNewPin == LibreSCRS::Secure::String{"2222"});
}

TEST(CredentialSeamRouting, ActivateTransportPinAllUnsupportedYieldsUnsupported)
{
    CandidateList candidates{std::make_shared<BasePinPlugin>("base-only")};
    auto session = detachedSession();
    auto r = LmCredentialManager{}.activateTransportPin(
        *session, candidates, "UserPIN", LibreSCRS::Secure::String{"77777"}, LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Unsupported);
}

// --- LmCredentialManager::activateSigningKey -------------------------------

TEST(CredentialSeamRouting, ActivateSigningKeyReachesItsEntryPoint)
{
    auto rec = std::make_shared<PinOpsRecorder>();
    auto stub = std::make_shared<PinStubPlugin>("owner", rec);
    stub->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::KeyActivationFailed, 3);
    CandidateList candidates{stub};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.activateSigningKey(*session, candidates, LibreSCRS::Secure::String{"123456"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::KeyActivationFailed)
        << "the plugin's outcome is returned unmodified";
    EXPECT_EQ(r.retriesLeft, 3);
    EXPECT_EQ(rec->signKeyCalls, 1) << "reaches activateSigningKey, not another entry point";
    EXPECT_EQ(rec->changeCalls, 0);
    EXPECT_TRUE(rec->lastSignPin == LibreSCRS::Secure::String{"123456"});
}

TEST(CredentialSeamRouting, ActivateSigningKeyBaseDefaultUnsupportedFallsThrough)
{
    auto rec = std::make_shared<PinOpsRecorder>();
    auto impl = std::make_shared<PinStubPlugin>("implements", rec);
    impl->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok);
    CandidateList candidates{std::make_shared<BasePinPlugin>("base-only"), impl};
    auto session = detachedSession();

    auto r = LmCredentialManager{}.activateSigningKey(*session, candidates, LibreSCRS::Secure::String{"123456"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Ok);
    EXPECT_EQ(rec->signKeyCalls, 1);
}

// --- PrompterClientBase::requestPinChange (appended defaulted virtual) -----

namespace {

// Overrides ONLY the frozen single-secret pure virtuals — proves an existing
// implementer keeps compiling untouched and inherits the fail-closed default.
struct LegacyPrompter final : PrompterClientBase
{
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

} // namespace

TEST(PrompterPinChange, DefaultImplementationFailsClosed)
{
    LegacyPrompter p;
    const auto r = p.requestPinChange(PromptOptions{});
    EXPECT_EQ(r.status, PromptStatus::Error) << "an unwired backend fails closed";
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
    EXPECT_FALSE(r.userMessage.empty()) << "the default carries a diagnostic";
}

TEST(PrompterPinChange, FakeUnseededIsErrorWithNoSecrets)
{
    FakePrompter p;
    const auto r = p.requestPinChange(PromptOptions{});
    EXPECT_EQ(r.status, PromptStatus::Error);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
    ASSERT_EQ(p.calls.size(), 1u);
    EXPECT_EQ(p.calls[0], FakePrompter::Kind::PinChange) << "the call is recorded with its own kind";
}

TEST(PrompterPinChange, FakeSeededOkReturnsBothSecrets)
{
    FakePrompter p;
    p.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"},
                                              LibreSCRS::Secure::String{"5678"}, ""};
    const auto r = p.requestPinChange(PromptOptions{});
    EXPECT_EQ(r.status, PromptStatus::Ok);
    ASSERT_TRUE(r.current.has_value());
    ASSERT_TRUE(r.newPin.has_value());
    EXPECT_TRUE(*r.current == LibreSCRS::Secure::String{"1234"});
    EXPECT_TRUE(*r.newPin == LibreSCRS::Secure::String{"5678"});
}

TEST(PrompterPinChange, FakeSeededCancelReturnsNoSecrets)
{
    FakePrompter p;
    p.pinChangeResult = PinChangePromptResult{PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};
    const auto r = p.requestPinChange(PromptOptions{});
    EXPECT_EQ(r.status, PromptStatus::Cancelled);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
}

// --- FakeCredentialManager scriptability lock ------------------------------

TEST(FakeCredentialManagerLock, RecordsCallsAndReturnsSeededResults)
{
    FakeCredentialManager fake;
    fake.listResult = {pinEntry("UserPIN")};
    fake.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    auto session = detachedSession();
    const CandidateList none;
    CredentialManager& seam = fake; // exercised through the seam interface

    auto listing = seam.list(*session, none);
    ASSERT_EQ(listing.entries.size(), 1u);
    EXPECT_EQ(listing.entries[0].label, "UserPIN");

    auto r =
        seam.changePIN(*session, none, "UserPIN", LibreSCRS::Secure::String{"1111"}, LibreSCRS::Secure::String{"2222"});
    EXPECT_EQ(r.outcome, LibreSCRS::Plugin::PINResultOutcome::Ok);
    EXPECT_EQ(r.retriesLeft, 3);

    ASSERT_EQ(fake.calls.size(), 2u);
    EXPECT_EQ(fake.calls[0], FakeCredentialManager::Call::List);
    EXPECT_EQ(fake.calls[1], FakeCredentialManager::Call::ChangePin);
    EXPECT_EQ(fake.lastPinLabel, "UserPIN");
    EXPECT_TRUE(fake.lastOldPin == LibreSCRS::Secure::String{"1111"});
    EXPECT_TRUE(fake.lastNewPin == LibreSCRS::Secure::String{"2222"});
}

TEST(FakeCredentialManagerLock, UnseededMutationsAnswerUnsupported)
{
    // The unseeded default mirrors a card that advertises no credential
    // management: a valid call answered with the Unsupported outcome.
    FakeCredentialManager fake;
    auto session = detachedSession();
    const CandidateList none;

    EXPECT_EQ(fake.activateTransportPin(*session, none, "UserPIN", LibreSCRS::Secure::String{"77777"},
                                        LibreSCRS::Secure::String{"2222"})
                  .outcome,
              LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    EXPECT_EQ(fake.activateSigningKey(*session, none, LibreSCRS::Secure::String{"123456"}).outcome,
              LibreSCRS::Plugin::PINResultOutcome::Unsupported);
    EXPECT_TRUE(fake.lastTransportValue == LibreSCRS::Secure::String{"77777"});
    EXPECT_TRUE(fake.lastSignPin == LibreSCRS::Secure::String{"123456"});
}

// --- change_pin prompt-kind mirror -----------------------------------------

TEST(PrompterWireKinds, ChangePinKindStringIsStable)
{
    EXPECT_STREQ(LibreSCRS::PrompterWire::kKindChangePin, "change_pin");
}
