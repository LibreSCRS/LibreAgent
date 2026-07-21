// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of runKeyActivation (increment #1 = the signing-key
// activation flow is fully wired, but no LM plugin overrides activateSigningKey
// yet, so the real seam answers Unsupported and the flow passes that through as
// a well-formed CredentialOpResult). Every seam is a Fake; the flow runs
// synchronously on the test thread. The FakeCredentialManager ignores the
// session, so the open/install-provider prelude is exercised without a card.
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/KeyActivationFlow.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h> // seed the read cache for residency assertions
#include <LibreSCRS/Agent/value/CredentialRecord.h>

#include "fakes/FakeCredentialManager.h"
#include "fakes/FakePrompter.h"
#include "fakes/PinStubPlugin.h"
#include <LibreSCRS/Agent/operations/LmSeams.h> // real routing seam for the listing-plugin-first rig

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith = std::nullopt,
                                              CandidateList candidates = {})
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [candidates = std::move(candidates)](std::span<const std::uint8_t>,
                                                         LibreSCRS::SmartCard::CardSession&) { return candidates; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

CardReadSnapshot makeReadSnapshotFixture()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    return snap;
}

class RecordingPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t phase) noexcept override
    {
        phases.push_back(phase);
    }
    std::vector<std::uint32_t> phases;
};

// A signing-key credential as the list flow would have produced it. keyActivatable
// is the capability gate: false means the card cannot activate its signing key, so
// the flow must answer Unsupported WITHOUT ever raising a PIN prompt.
CredentialRecord makeSignRecord(bool keyActivatable)
{
    CredentialRecord r;
    r.id = "sign:0x92";
    r.kind = "sign";
    r.label = "Qualified Signature PIN";
    r.state = "operational";
    r.minLength = 4;
    r.maxLength = 8;
    r.keyActivatable = keyActivatable;
    return r;
}

struct Harness
{
    // Set BEFORE run() to drive an acquire failure; the holder is built lazily.
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    // Set BEFORE run() to pre-acquire the held session and mark it dead, so the
    // flow observes card removal (isDead()) AFTER the activateSigningKey seam.
    bool deadSession = false;
    // Resolved candidate plugin list the holder hands the flow (empty for the
    // Fake-seam cases; the listing-plugin-first rig seeds stub plugins here).
    CandidateList candidates;
    std::unique_ptr<CardSessionHolder> holder;
    FakeCredentialManager credentials;
    // When set, run() binds THIS seam instead of `credentials` (the REAL
    // LmCredentialManager for the routing rig).
    CredentialManager* seamOverride = nullptr;
    // Snapshot binding carried into the deps (empty = unbound).
    std::string listPluginId;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    LibreSCRS::Agent::CredentialSnapshotCache snapshotCache;
    LibreSCRS::Agent::CardReadCache cardReadCache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    std::string cardKey = "card-A";

    CredentialRecord record = makeSignRecord(/*keyActivatable=*/true);
    std::optional<bool> pinActivated; // continuation carry-through (nullopt = standalone run)

    Harness()
    {
        // A collectable SIGN PIN by default; the capability-gated tests never
        // reach it, the seam-driven tests do.
        prompter.pinResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"}, ""};
    }

    // Seed BOTH invalidatable caches for this card so a residency assertion can
    // check they are dropped (reached-card) or preserved (no card contact).
    void seedCaches()
    {
        snapshotCache.put(cardKey, CredentialSnapshot{});
        cardReadCache.put(cardKey, makeReadSnapshotFixture());
    }
    [[nodiscard]] bool snapshotPresent()
    {
        return snapshotCache.get(cardKey).has_value();
    }
    [[nodiscard]] bool readPresent()
    {
        return cardReadCache.get(cardKey).has_value();
    }

    CredentialOpResult run()
    {
        holder = makeHolder(failWith, candidates);
        if (deadSession) {
            auto acq = holder->acquire();
            if (acq) {
                acq->session->markDead();
            }
        }
        return runKeyActivation(KeyActivationFlowDeps{
            .holder = *holder,
            .credentials = seamOverride != nullptr ? *seamOverride : credentials,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .snapshotCache = snapshotCache,
            .cardReadCache = cardReadCache,
            .phaseSink = phaseSink,
            .record = record,
            .listPluginId = listPluginId,
            .cardKey = "card-A",
            .requester = "test-client",
            .reader = "FakeReader",
            .artifact = "signing-key",
            .pinActivated = pinActivated,
            .token = source.token(),
        });
    }
};

bool promptedForPin(const FakePrompter& p)
{
    for (const auto k : p.calls) {
        if (k == FakePrompter::Kind::Pin) {
            return true;
        }
    }
    return false;
}

bool calledSeam(const FakeCredentialManager& c)
{
    for (const auto k : c.calls) {
        if (k == FakeCredentialManager::Call::ActivateSigningKey) {
            return true;
        }
    }
    return false;
}

} // namespace

// (1) Capability gate: a record that is not keyActivatable answers Unsupported
// and NEVER prompts (prompt-before-capability is forbidden) — nor touches the
// seam.
TEST(KeyActivationFlow, NotActivatableAnswersUnsupportedWithoutPrompting)
{
    Harness h;
    h.record = makeSignRecord(/*keyActivatable=*/false);

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_FALSE(promptedForPin(h.prompter)) << "must not prompt when the record is not keyActivatable";
    EXPECT_FALSE(calledSeam(h.credentials)) << "must not reach the seam when the record is not keyActivatable";
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_FALSE(*result.keyActivated);
}

// (2) LM base default (no plugin overrides activateSigningKey): keyActivatable,
// so the flow prompts and reaches the seam, which answers Unsupported — the
// flow passes that valid outcome through.
TEST(KeyActivationFlow, SeamUnsupportedPassesThrough)
{
    Harness h;
    h.credentials.activateSigningKeyResult =
        LibreSCRS::Plugin::PINResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_TRUE(promptedForPin(h.prompter));
    EXPECT_TRUE(calledSeam(h.credentials));
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_FALSE(*result.keyActivated);
}

// (3) A future plugin that activates: outcome Ok -> keyActivated == true, and
// the collected SIGN PIN is exactly what reached the seam.
TEST(KeyActivationFlow, SeamOkSetsKeyActivated)
{
    Harness h;
    h.credentials.activateSigningKeyResult =
        LibreSCRS::Plugin::PINResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok};

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_TRUE(*result.keyActivated);
    EXPECT_EQ(h.credentials.lastSignPin, LibreSCRS::Secure::String{"1234"})
        << "the prompted SIGN PIN must be the exact secret handed to activateSigningKey";
}

// (4) Wrong SIGN PIN: retriesLeft rides the result and is attributed to the PIN
// that was presented (the SIGN PIN — the only PIN in this flow).
TEST(KeyActivationFlow, InvalidPinCarriesRetriesForTheSignPin)
{
    Harness h;
    h.credentials.activateSigningKeyResult = LibreSCRS::Plugin::PINResult{
        .retriesLeft = 2, .blocked = false, .outcome = LibreSCRS::Plugin::PINResultOutcome::InvalidPin};

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::InvalidPin);
    ASSERT_TRUE(result.retriesLeft.has_value());
    EXPECT_EQ(*result.retriesLeft, 2);
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_FALSE(*result.keyActivated);
}

// (5) VERIFY succeeded but the card-side ACTIVATE failed: the KeyActivationFailed
// outcome is preserved verbatim (its wire mapping is a later task's job),
// keyActivated == false, and the pinActivated continuation state (set when this
// activation chained off a transport-PIN bring-up) is carried through unchanged.
TEST(KeyActivationFlow, KeyActivationFailedPreservesOutcomeAndCarriesPinActivated)
{
    Harness h;
    h.pinActivated = true; // this activation continues a just-completed transport-PIN bring-up
    h.credentials.activateSigningKeyResult =
        LibreSCRS::Plugin::PINResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::KeyActivationFailed};

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::KeyActivationFailed);
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_FALSE(*result.keyActivated);
    ASSERT_TRUE(result.pinActivated.has_value());
    EXPECT_TRUE(*result.pinActivated);
}

// (6) The user dismissed the SIGN PIN dialog: UserCancelled, and the seam is
// never touched (no card-side retry budget is spent on a cancel).
TEST(KeyActivationFlow, PromptCancelledSkipsTheSeam)
{
    Harness h;
    h.prompter.pinResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::UserCancelled);
    EXPECT_FALSE(calledSeam(h.credentials)) << "a cancelled prompt must not reach the seam";
}

// (7) A non-CardRemoved session-OPEN failure never reached the card: the outcome
// is the non-invalidating, non-card Unspecified (SAME as PinChangeFlow), and the
// snapshot + read caches are PRESERVED.
TEST(KeyActivationFlow, NonCardRemovedOpenFailurePreservesCachesAndYieldsUnspecified)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    h.seedCaches();
    ASSERT_TRUE(h.snapshotPresent());
    ASSERT_TRUE(h.readPresent());

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::Unspecified) << "a pre-seam open failure is non-card Unspecified";
    EXPECT_TRUE(h.snapshotPresent()) << "no card contact: the snapshot must be preserved";
    EXPECT_TRUE(h.readPresent()) << "no card contact: the read cache must be preserved";
    EXPECT_FALSE(calledSeam(h.credentials)) << "the seam was never reached";
}

// (8) A card pulled mid-activateSigningKey: the seam WAS reached (reachedCard),
// but the session is dead afterward -> CardRemoved, and the stale snapshot + read
// caches ARE dropped (a possibly-partial activation must not serve a stale view).
TEST(KeyActivationFlow, MidOpCardRemovalYieldsCardRemovedAndInvalidatesCaches)
{
    Harness h;
    h.deadSession = true;
    // The seam "returns" Ok, but the dead session must override it to CardRemoved.
    h.credentials.activateSigningKeyResult =
        LibreSCRS::Plugin::PINResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok};
    h.seedCaches();
    ASSERT_TRUE(h.snapshotPresent());
    ASSERT_TRUE(h.readPresent());

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::CardRemoved)
        << "a card pulled mid-activation is transport loss, not a plugin error";
    EXPECT_TRUE(calledSeam(h.credentials)) << "the seam was reached before the loss (reachedCard)";
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_FALSE(*result.keyActivated) << "a mid-op removal cannot be reported as an activation";
    EXPECT_FALSE(h.snapshotPresent()) << "a possibly-partial activation drops the stale snapshot";
    EXPECT_FALSE(h.readPresent()) << "reached-card invalidation drops the read cache too";
}

// Two-candidate rig where the LISTING plugin differs from the first mutation-
// capable candidate: the record was resolved from a snapshot bound to the
// listing plugin, so the activation must be routed to IT first — the
// priority-first candidate would otherwise intercept the mutation (its
// InvalidPin answer is final under first-non-Unsupported-wins routing and
// would burn a SIGN-PIN retry on the wrong plugin). Drives the REAL
// LmCredentialManager over stub plugins carrying the signing capability set
// (PKI + PinManagement).
TEST(KeyActivationFlow, ActivationRoutesToTheSnapshotListingPluginFirst)
{
    constexpr auto signingCaps =
        LibreSCRS::Plugin::CardCapabilities::PKI | LibreSCRS::Plugin::CardCapabilities::PinManagement;
    Harness h;
    auto recFirst = std::make_shared<PinOpsRecorder>();
    auto first = std::make_shared<PinStubPlugin>("first-in-priority", recFirst, signingCaps);
    first->mutationResult = [] {
        LibreSCRS::Plugin::PINResult r;
        r.outcome = LibreSCRS::Plugin::PINResultOutcome::InvalidPin;
        r.retriesLeft = 1;
        return r;
    }();
    auto recListing = std::make_shared<PinOpsRecorder>();
    auto listing = std::make_shared<PinStubPlugin>("listing-plugin", recListing, signingCaps);
    listing->mutationResult = [] {
        LibreSCRS::Plugin::PINResult r;
        r.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok;
        return r;
    }();
    h.candidates = {first, listing};
    h.listPluginId = "listing-plugin";
    LmCredentialManager realSeam;
    h.seamOverride = &realSeam;

    const auto result = h.run();

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    ASSERT_TRUE(result.keyActivated.has_value());
    EXPECT_TRUE(*result.keyActivated);
    EXPECT_EQ(recListing->signKeyCalls, 1) << "the plugin that produced the listing answers the activation";
    EXPECT_EQ(recFirst->signKeyCalls, 0)
        << "another candidate must not intercept a mutation for a card it listed nothing for";
}
