// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of the PIN-management flow (first cut) and its entry
// validation. Every seam is a Fake; the flow runs synchronously on the test
// thread. The credential seam (FakeCredentialManager) and the multi-secret
// prompter seam (FakePrompter) are the shared tests/fakes doubles, seeded per
// case; no real card, bus, or prompter is involved. Covers:
//  - validatePinManageRequest: unknown verb / activateKey-combination / unknown
//    or absent (null-snapshot) credential.
//  - runPinManage change: prompt -> record-label + both secrets reach changePIN
//    -> PINResult maps to CredentialOpResult (incl. retriesLeft / blocked);
//    user-cancel short-circuits to UserCancelled with NO seam call; a card gone
//    at session acquisition maps to CardRemoved.
//  - runPinManage unblock / activate_pin: Unsupported WITHOUT prompting.
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/OperationPhase.h> // OperationPhase (phase-sequence assertions)
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h> // seed the read cache for residency assertions

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include "fakes/FakeCredentialManager.h"
#include "fakes/FakePrompter.h"
#include "fakes/PinStubPlugin.h"
#include <LibreSCRS/Agent/operations/LmSeams.h> // real routing seam for the listing-plugin-first rigs

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith,
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

class RecordingPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t phase) noexcept override
    {
        phases.push_back(phase);
    }
    std::vector<std::uint32_t> phases;
};

// A single-record snapshot: a changeable, non-unblockable UserPIN with 4..8
// length bounds, addressed by id "user:0x01".
CredentialSnapshot makeSnapshot()
{
    CredentialRecord r;
    r.id = "user:0x01";
    r.label = "UserPIN";
    r.kind = "user";
    r.state = "operational";
    r.retriesLeft = 3;
    r.minLength = 4;
    r.maxLength = 8;
    r.canChange = true;
    r.unblockable = false;
    r.activatable = false;
    CredentialSnapshot s;
    s.records.push_back(std::move(r));
    s.version = 1;
    return s;
}

LibreSCRS::Plugin::PINResult pinResult(LibreSCRS::Plugin::PINResultOutcome outcome,
                                       std::optional<int> retriesLeft = std::nullopt, bool blocked = false)
{
    LibreSCRS::Plugin::PINResult r;
    r.outcome = outcome;
    r.retriesLeft = retriesLeft;
    r.blocked = blocked;
    return r;
}

CardReadSnapshot makeReadSnapshotFixture()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    return snap;
}

struct Harness
{
    // Set BEFORE deps() to drive an acquire failure; the holder is built lazily.
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    // Set BEFORE deps() to pre-acquire the held session and mark it dead, so the
    // mutation flow observes card removal (isDead()) AFTER the seam returns.
    bool deadSession = false;
    // Resolved candidate plugin list the holder hands the flow (empty for the
    // Fake-seam cases; the listing-plugin-first rigs seed stub plugins here).
    CandidateList candidates;
    std::unique_ptr<CardSessionHolder> holder;
    FakeCredentialManager credentialManager;
    // When set, deps() binds THIS seam instead of `credentialManager` (the
    // REAL LmCredentialManager for the routing rigs).
    CredentialManager* seamOverride = nullptr;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    LibreSCRS::Agent::CredentialSnapshotCache snapshotCache;
    LibreSCRS::Agent::CardReadCache cardReadCache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    CredentialSnapshot snapshot{makeSnapshot()};
    std::string cardKey = "card-A";
    std::string requester = "test-client";

    // Seed BOTH invalidatable caches for this card so a residency assertion can
    // check they are dropped (reached-card) or preserved (no card contact).
    void seedCaches()
    {
        snapshotCache.put(cardKey, makeSnapshot());
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

    PinManageFlowDeps deps()
    {
        holder = makeHolder(failWith, candidates);
        if (deadSession) {
            auto acq = holder->acquire();
            if (acq) {
                acq->session->markDead();
            }
        }
        return PinManageFlowDeps{
            .holder = *holder,
            .credentialManager = seamOverride != nullptr ? *seamOverride : credentialManager,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .snapshotCache = snapshotCache,
            .cardReadCache = cardReadCache,
            .phaseSink = phaseSink,
            .snapshot = &snapshot,
            .cardKey = cardKey,
            .requester = requester,
            .reader = "FakeReader",
            .artifact = "",
            .token = source.token(),
        };
    }
};

PinManageRequest changeReq()
{
    return PinManageRequest{.cardKey = "card-A", .pinId = "user:0x01", .verb = "change", .activateKey = false};
}

} // namespace

// --- validatePinManageRequest ----------------------------------------------

TEST(ValidatePinManage, UnknownVerbRejected)
{
    const auto snap = makeSnapshot();
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "frobnicate", .activateKey = false};
    const auto v = validatePinManageRequest(r, &snap);
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), EntryError::UnknownVerb);
}

TEST(ValidatePinManage, ActivateKeyWithNonActivateVerbRejected)
{
    const auto snap = makeSnapshot();
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "change", .activateKey = true};
    const auto v = validatePinManageRequest(r, &snap);
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), EntryError::InvalidCombination);
}

TEST(ValidatePinManage, UnknownPinIdRejected)
{
    const auto snap = makeSnapshot();
    PinManageRequest r{.cardKey = "card-A", .pinId = "sign:0x92", .verb = "change", .activateKey = false};
    const auto v = validatePinManageRequest(r, &snap);
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), EntryError::UnknownCredential);
}

TEST(ValidatePinManage, NullSnapshotRejected)
{
    // A client that never ran ListCredentials: no implicit list is run; the
    // call is rejected at entry.
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "change", .activateKey = false};
    const auto v = validatePinManageRequest(r, nullptr);
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), EntryError::UnknownCredential);
}

TEST(ValidatePinManage, ValidChangeAccepted)
{
    const auto snap = makeSnapshot();
    EXPECT_TRUE(validatePinManageRequest(changeReq(), &snap).has_value());
}

// Two DISTINCT ids sharing one label (a dual-applet card exposing the same PIN
// role twice): the ids disambiguate on the wire, but the seam addresses the
// card by LABEL — so a mutation against either record would make the plugin
// guess which PIN the user meant. Entry validation must reject it.
TEST(ValidatePinManage, AmbiguousLabelRejected)
{
    auto snap = makeSnapshot();
    CredentialRecord twin = snap.records[0];
    twin.id = "user:0x01:1"; // disambiguated id, SAME label
    snap.records[0].id = "user:0x01:0";
    snap.records.push_back(std::move(twin));

    for (const char* pinId : {"user:0x01:0", "user:0x01:1"}) {
        PinManageRequest r{.cardKey = "card-A", .pinId = pinId, .verb = "change", .activateKey = false};
        const auto v = validatePinManageRequest(r, &snap);
        ASSERT_FALSE(v.has_value()) << "pinId " << pinId << " addresses a non-unique label";
        EXPECT_EQ(v.error(), EntryError::AmbiguousCredential);
    }
}

// The uniqueness rule keys on the ADDRESSED record's label only: a snapshot
// that also carries an unrelated colliding pair must not poison a mutation
// addressing a uniquely-labelled record.
TEST(ValidatePinManage, UniqueLabelStillAcceptedNextToAnUnrelatedCollision)
{
    auto snap = makeSnapshot(); // "UserPIN", unique
    CredentialRecord a;
    a.id = "puk:0x04:0";
    a.label = "PUK";
    a.kind = "puk";
    CredentialRecord b = a;
    b.id = "puk:0x04:1";
    snap.records.push_back(std::move(a));
    snap.records.push_back(std::move(b));

    EXPECT_TRUE(validatePinManageRequest(changeReq(), &snap).has_value())
        << "an unrelated label collision must not reject a uniquely-labelled record";
}

TEST(ValidatePinManage, ActivatePinWithActivateKeyAccepted)
{
    const auto snap = makeSnapshot();
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "activate_pin", .activateKey = true};
    EXPECT_TRUE(validatePinManageRequest(r, &snap).has_value());
}

// --- runPinManage: change --------------------------------------------------

TEST(RunPinManageChange, HappyPathPromptsAndDrivesSeamWithRecordLabel)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    EXPECT_EQ(result.retriesLeft, 3);

    ASSERT_EQ(h.prompter.calls.size(), 1u);
    EXPECT_EQ(h.prompter.calls[0], FakePrompter::Kind::PinChange) << "the current+new PIN are collected in one modal";

    ASSERT_EQ(h.credentialManager.calls.size(), 1u);
    EXPECT_EQ(h.credentialManager.calls[0], FakeCredentialManager::Call::ChangePin);
    EXPECT_EQ(h.credentialManager.lastPinLabel, "UserPIN") << "the addressed record's label selects the PIN";
    EXPECT_TRUE(h.credentialManager.lastOldPin == LibreSCRS::Secure::String{"1111"});
    EXPECT_TRUE(h.credentialManager.lastNewPin == LibreSCRS::Secure::String{"2222"});
}

TEST(RunPinManageChange, WrongOldPinPropagatesRetriesLeft)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"0000"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::InvalidPin, 2);

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::InvalidPin);
    EXPECT_EQ(result.retriesLeft, 2) << "retriesLeft describes the presented (old) PIN";
    EXPECT_FALSE(result.blocked);
}

TEST(RunPinManageChange, BlockedOutcomeCarriesBlockedFlag)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"0000"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Blocked, 0, /*blocked=*/true);

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Blocked);
    EXPECT_TRUE(result.blocked);
    EXPECT_EQ(result.retriesLeft, 0);
}

TEST(RunPinManageChange, UserCancelYieldsUserCancelledAndNoSeamCall)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::UserCancelled);
    EXPECT_TRUE(h.credentialManager.calls.empty()) << "a cancelled prompt never touches the card";
    ASSERT_EQ(h.prompter.calls.size(), 1u);
    EXPECT_EQ(h.prompter.calls[0], FakePrompter::Kind::PinChange) << "the prompt was attempted";
}

// A BROKEN/ABSENT prompter (PromptStatus::Error) is NOT a user cancel: it maps
// to MissingFields — the same vocabulary KeyActivationFlow uses for an
// undelivered secret — which the wire maps to ErrorCode::PrompterError. Only a
// genuine user dismissal may finish Cancelled.
TEST(RunPinManageChange, PrompterErrorYieldsMissingFieldsNotUserCancelled)
{
    Harness h;
    h.prompter.pinChangeResult =
        PinChangePromptResult{PromptStatus::Error, std::nullopt, std::nullopt, "prompter gone"};
    h.seedCaches();

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::MissingFields)
        << "a dead prompter surfaces as PrompterError on the wire, never as a user cancel";
    EXPECT_TRUE(h.credentialManager.calls.empty()) << "an undelivered secret never touches the card";
    EXPECT_TRUE(h.snapshotPresent()) << "no card contact: the snapshot must be preserved";
    EXPECT_TRUE(h.readPresent());
}

// An Ok status whose secrets are nevertheless absent is the same undelivered-
// secret condition (transport/decode fault inside the prompter client): also
// MissingFields, not a cancel.
TEST(RunPinManageChange, OkStatusWithoutSecretsYieldsMissingFields)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, std::nullopt, std::nullopt, ""};

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::MissingFields);
    EXPECT_TRUE(h.credentialManager.calls.empty());
}

TEST(RunPinManageChange, CardGoneAtAcquisitionMapsToCardRemoved)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    // Seed an Ok prompt result to prove the card-removed classification wins
    // regardless of what the prompter would have returned.
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::CardRemoved);
    EXPECT_TRUE(h.credentialManager.calls.empty()) << "the mutation never reached the seam";
    EXPECT_TRUE(h.prompter.calls.empty()) << "no secret is collected once the card is gone";
}

// The change modal must go through the single agent-wide prompt slot: while
// another operation holds that slot, the change prompt must QUEUE (not fire),
// then run once the slot frees. Proves runPinManage wraps deps.prompter in a
// gated SerializingPrompter rather than calling the raw prompter directly.
TEST(RunPinManageChange, ChangePromptSerializesBehindHeldSlot)
{
    using namespace std::chrono_literals;
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);

    // Occupy the single agent-wide prompt slot from another "operation".
    LibreSCRS::CancelSource hogSource;
    std::mutex m;
    std::condition_variable cv;
    bool slotHeld = false;
    bool releaseSlot = false;
    std::thread slotHog([&] {
        h.serializer.serialize(
            hogSource.token(),
            [&]() -> PromptResult {
                {
                    std::lock_guard lk(m);
                    slotHeld = true;
                }
                cv.notify_all();
                std::unique_lock lk(m);
                cv.wait(lk, [&] { return releaseSlot; });
                return PromptResult{PromptStatus::Ok, std::nullopt, ""};
            },
            [] { return PromptResult{PromptStatus::Cancelled, std::nullopt, ""}; });
    });
    {
        std::unique_lock lk(m);
        ASSERT_TRUE(cv.wait_for(lk, 2s, [&] { return slotHeld; })) << "the hog must hold the slot";
    }

    auto d = h.deps();
    std::atomic<bool> flowDone{false};
    CredentialOpResult result;
    std::thread flowT([&] {
        result = runPinManage(d, changeReq());
        flowDone = true;
    });

    // While the slot is held, the change flow must block at the gated prompt and
    // must NOT have completed — the change modal is queued, not stacked.
    std::this_thread::sleep_for(200ms);
    EXPECT_FALSE(flowDone.load()) << "the change flow must queue behind the held prompt slot, not fire immediately";

    // Release the slot; the flow then acquires it and drives the change to completion.
    {
        std::lock_guard lk(m);
        releaseSlot = true;
    }
    cv.notify_all();
    flowT.join();
    slotHog.join();

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    ASSERT_EQ(h.prompter.calls.size(), 1u);
    EXPECT_EQ(h.prompter.calls[0], FakePrompter::Kind::PinChange) << "the change prompt fired once the slot freed";
}

// The change modal must NAME what it acts on: the pin_label (the addressed
// record's role label) and the card_label (the card/token identity the flow
// carries — the human reader name), while the TITLE stays empty so the
// prompter renders its own localized action title ("Change PIN"), never a
// record label masquerading as the window title.
TEST(RunPinManageChange, ChangePromptCarriesCardAndPinLabelsAndLeavesTitleToThePrompter)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);

    auto d = h.deps();
    static_cast<void>(runPinManage(d, changeReq()));

    ASSERT_EQ(h.prompter.calls.size(), 1u);
    const auto& opts = h.prompter.lastChangePromptOptions;
    EXPECT_EQ(opts.pinLabel, "UserPIN") << "the PIN role label rides its own option, not the title";
    EXPECT_EQ(opts.cardLabel, "FakeReader") << "the card/token identity rides card_label";
    EXPECT_TRUE(opts.title.empty()) << "the prompter owns the localized 'Change PIN' action title";
    EXPECT_EQ(opts.minLength, 4u);
    EXPECT_EQ(opts.maxLength, 8u);
}

// --- runPinManage: snapshot-bound mutation routing ---------------------------

// Two-candidate rig where the LISTING plugin differs from the first mutation-
// capable candidate: the snapshot is bound to the listing plugin's identity,
// so the change must be routed to IT first — the priority-first candidate
// would otherwise intercept the mutation (its InvalidPin answer is final under
// first-non-Unsupported-wins routing and would burn a retry on the wrong
// plugin). Drives the REAL LmCredentialManager over stub plugins.
TEST(RunPinManageChange, MutationRoutesToTheSnapshotListingPluginFirst)
{
    Harness h;
    auto recFirst = std::make_shared<PinOpsRecorder>();
    auto first = std::make_shared<PinStubPlugin>("first-in-priority", recFirst);
    first->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::InvalidPin, 1);
    auto recListing = std::make_shared<PinOpsRecorder>();
    auto listing = std::make_shared<PinStubPlugin>("listing-plugin", recListing);
    listing->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    h.candidates = {first, listing};
    h.snapshot.listPluginId = "listing-plugin";
    LmCredentialManager realSeam;
    h.seamOverride = &realSeam;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    EXPECT_EQ(recListing->changeCalls, 1) << "the plugin that produced the listing answers the mutation";
    EXPECT_EQ(recFirst->changeCalls, 0)
        << "another candidate must not intercept a mutation for a card it listed nothing for";
}

// Control: with no snapshot binding (empty listPluginId — e.g. a legacy cached
// snapshot) the plain priority order routes, pinning that the prioritisation
// is snapshot-driven and not a hardcoded reorder.
TEST(RunPinManageChange, WithoutSnapshotBindingPriorityOrderRoutes)
{
    Harness h;
    auto recFirst = std::make_shared<PinOpsRecorder>();
    auto first = std::make_shared<PinStubPlugin>("first-in-priority", recFirst);
    first->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    auto recSecond = std::make_shared<PinOpsRecorder>();
    auto second = std::make_shared<PinStubPlugin>("second-in-priority", recSecond);
    second->mutationResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    h.candidates = {first, second};
    h.snapshot.listPluginId.clear();
    LmCredentialManager realSeam;
    h.seamOverride = &realSeam;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    EXPECT_EQ(recFirst->changeCalls, 1);
    EXPECT_EQ(recSecond->changeCalls, 0);
}

// --- runPinManage: cache invalidation is card-reach ground truth ------------

// A non-CardRemoved session-OPEN failure never reached the card: the snapshot +
// read caches must be PRESERVED and the outcome is the non-invalidating,
// non-card Unspecified (unified with KeyActivationFlow), NOT PluginError.
TEST(RunPinManageChange, NonCardRemovedOpenFailurePreservesCachesAndYieldsUnspecified)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    h.seedCaches();
    ASSERT_TRUE(h.snapshotPresent());
    ASSERT_TRUE(h.readPresent());

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Unspecified) << "a pre-seam open failure is non-card Unspecified";
    EXPECT_TRUE(h.snapshotPresent()) << "no card contact: the snapshot must be preserved";
    EXPECT_TRUE(h.readPresent()) << "no card contact: the read cache must be preserved";
    EXPECT_TRUE(h.credentialManager.calls.empty()) << "the seam was never reached";
    EXPECT_TRUE(h.prompter.calls.empty()) << "no secret is collected on an open failure";
    EXPECT_TRUE(h.phaseSink.phases.empty()) << "an open failure precedes the AwaitingConsent phase";
}

// A card pulled mid-changePIN: the seam WAS reached (reachedCard), but the
// session is dead afterward -> CardRemoved, and because the change may have
// partially applied the stale snapshot + read caches ARE dropped.
TEST(RunPinManageChange, MidOpCardRemovalYieldsCardRemovedAndInvalidatesCaches)
{
    Harness h;
    h.deadSession = true;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    // The seam "returns" a value, but the dead session must override it to CardRemoved.
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    h.seedCaches();
    ASSERT_TRUE(h.snapshotPresent());
    ASSERT_TRUE(h.readPresent());

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::CardRemoved)
        << "a card pulled mid-changePIN is transport loss, not a plugin error";
    EXPECT_FALSE(h.credentialManager.calls.empty()) << "the seam was reached before the loss (reachedCard)";
    EXPECT_FALSE(h.snapshotPresent()) << "a possibly-partial change drops the stale snapshot";
    EXPECT_FALSE(h.readPresent()) << "reached-card invalidation drops the read cache too";
}

// Happy path boundary: a completed change reached the card -> both caches drop,
// and the recorded phase sequence is exactly AwaitingConsent then Authenticating.
TEST(RunPinManageChange, HappyPathInvalidatesCachesAndRecordsPhaseSequence)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);
    h.seedCaches();

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    EXPECT_FALSE(h.snapshotPresent()) << "a completed change reached the card: snapshot dropped";
    EXPECT_FALSE(h.readPresent()) << "a completed change reached the card: read cache dropped";
    ASSERT_EQ(h.phaseSink.phases.size(), 2u);
    EXPECT_EQ(h.phaseSink.phases[0], static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
    EXPECT_EQ(h.phaseSink.phases[1], static_cast<std::uint32_t>(OperationPhase::Authenticating));
}

// Cancel boundary: a prompter-only cancel never reached the card -> both caches
// preserved, and the flow stops at AwaitingConsent (never enters Authenticating).
TEST(RunPinManageChange, UserCancelPreservesCachesAndStopsAtConsentPhase)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};
    h.seedCaches();

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::UserCancelled);
    EXPECT_TRUE(h.snapshotPresent()) << "a prompter-only cancel must not invalidate the snapshot";
    EXPECT_TRUE(h.readPresent()) << "a prompter-only cancel must not invalidate the read cache";
    ASSERT_EQ(h.phaseSink.phases.size(), 1u) << "cancel stops at AwaitingConsent, before Authenticating";
    EXPECT_EQ(h.phaseSink.phases[0], static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
}

// --- runPinManage: capability gate (not verb-only) --------------------------

// The change short-circuit must gate on the record's OWN canChange capability,
// BEFORE prompting (prompt-before-capability, mirroring KeyActivationFlow). A
// non-canChange record answers Unsupported without ever raising a dialog — even
// with unblockable/activatable set, which must not influence the change path.
TEST(RunPinManageChange, NonCanChangeRecordIsUnsupportedWithoutPrompting)
{
    Harness h;
    h.snapshot.records[0].canChange = false;
    h.snapshot.records[0].unblockable = true; // flags ON: proves capability-aware, not verb-only
    h.snapshot.records[0].activatable = true;
    // Seed an Ok prompt + seam to prove NEITHER is reached.
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_TRUE(h.prompter.calls.empty()) << "change on a non-canChange record must NOT prompt";
    EXPECT_TRUE(h.credentialManager.calls.empty()) << "change on a non-canChange record must NOT reach the seam";
    EXPECT_TRUE(h.phaseSink.phases.empty()) << "the capability gate precedes the AwaitingConsent phase";
}

// A canChange record still prompts and drives the seam (the gate does not block a
// capable change) — pins that the new gate is a capability test, not a verb test.
TEST(RunPinManageChange, CanChangeRecordStillPromptsAndDrivesSeam)
{
    Harness h; // makeSnapshot()'s record has canChange = true
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentialManager.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::Ok, 3);

    auto d = h.deps();
    const auto result = runPinManage(d, changeReq());

    EXPECT_EQ(result.outcome, CredentialOutcome::Ok);
    ASSERT_EQ(h.prompter.calls.size(), 1u);
    EXPECT_EQ(h.credentialManager.calls.size(), 1u);
}

// The unblock verb gates on the record's OWN unblockable capability before any
// prompt: an un-unblockable record answers Unsupported without prompting.
TEST(RunPinManageUnblock, NonUnblockableRecordIsUnsupportedWithoutPrompting)
{
    Harness h;
    h.snapshot.records[0].unblockable = false;
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "unblock", .activateKey = false};

    auto d = h.deps();
    const auto result = runPinManage(d, r);

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_TRUE(h.prompter.calls.empty()) << "unblock gates on !unblockable before prompting";
    EXPECT_TRUE(h.credentialManager.calls.empty());
}

// The activate_pin verb gates on the record's OWN activatable capability before
// any prompt: a non-activatable record answers Unsupported without prompting.
TEST(RunPinManageActivatePin, NonActivatableRecordIsUnsupportedWithoutPrompting)
{
    Harness h;
    h.snapshot.records[0].activatable = false;
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "activate_pin", .activateKey = true};

    auto d = h.deps();
    const auto result = runPinManage(d, r);

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_TRUE(h.prompter.calls.empty()) << "activate_pin gates on !activatable before prompting";
    EXPECT_TRUE(h.credentialManager.calls.empty());
}

// --- runPinManage: non-change verbs (first-cut short-circuit) ---------------

TEST(RunPinManageUnblock, ShortCircuitsUnsupportedWithoutPrompting)
{
    Harness h;
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "unblock", .activateKey = false};

    auto d = h.deps();
    const auto result = runPinManage(d, r);

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_TRUE(h.prompter.calls.empty()) << "unblock must never prompt in this cut";
    EXPECT_TRUE(h.credentialManager.calls.empty()) << "unblock must never reach the seam in this cut";
}

TEST(RunPinManageActivatePin, ShortCircuitsUnsupportedWithoutPrompting)
{
    Harness h;
    PinManageRequest r{.cardKey = "card-A", .pinId = "user:0x01", .verb = "activate_pin", .activateKey = true};

    auto d = h.deps();
    const auto result = runPinManage(d, r);

    EXPECT_EQ(result.outcome, CredentialOutcome::Unsupported);
    EXPECT_TRUE(h.prompter.calls.empty());
    EXPECT_TRUE(h.credentialManager.calls.empty());
}
