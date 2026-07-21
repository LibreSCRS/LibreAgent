// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of CredentialListFlow. Every seam is a Fake; the flow runs
// synchronously on the test thread. The FakeCredentialManager returns canned
// PinStatusEntry fixtures so the open/install-provider prelude + the
// map/disambiguate/snapshot tail are exercised without a real card. The
// agent-side mapping table (toCredentialRecord) is unit-tested separately in
// CredentialRecordTest; here we assert the flow assembles a CredentialSnapshot
// out of it, applies id disambiguation, and classifies the empty-result cases.
#include "fakes/FakeCredentialManager.h"
#include "fakes/FakePrompter.h"
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/CredentialListFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith)
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

// Seam double that mimics a PACE plugin's getPINList: it self-activates the
// secure channel on the SAME held session, which invokes the flow-installed
// credential provider on a secret-cache miss (a detached session resolves the
// secret BEFORE any card I/O reaches the wire). An activation failure yields
// an empty list — exactly the production plugin behaviour the empty-result
// classification in the flow has to disambiguate.
class ChannelActivatingCredentialManager final : public CredentialManager
{
public:
    std::vector<LibreSCRS::Plugin::PinStatusEntry> entries;

    [[nodiscard]] CredentialListing list(LibreSCRS::SmartCard::CardSession& session, const CandidateList&) override
    {
        const LibreSCRS::SmartCard::SmProtocolRequest req =
            LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can};
        auto holder = session.activateChannelWithSm(LibreSCRS::SmartCard::AppletAid{0xA0, 0x00, 0x00, 0x02, 0x47}, req,
                                                    LibreSCRS::CancelToken{});
        if (!holder) {
            return {};
        }
        return {entries, "pace-applet"};
    }
    [[nodiscard]] LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                         std::string_view, const LibreSCRS::Secure::String&,
                                                         const LibreSCRS::Secure::String&) override
    {
        return {.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    }
    [[nodiscard]] LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&,
                                                                    const CandidateList&, std::string_view,
                                                                    const LibreSCRS::Secure::String&,
                                                                    const LibreSCRS::Secure::String&) override
    {
        return {.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    }
    [[nodiscard]] LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&,
                                                                  const CandidateList&,
                                                                  const LibreSCRS::Secure::String&) override
    {
        return {.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    }
};

class RecordingPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t phase) noexcept override
    {
        phases.push_back(phase);
    }
    std::vector<std::uint32_t> phases;
};

LibreSCRS::Plugin::PinStatusEntry makeEntry(std::string label, LibreSCRS::Plugin::PinKind kind, std::uint8_t ref,
                                            std::optional<int> retries)
{
    LibreSCRS::Plugin::PinStatusEntry e;
    e.label = std::move(label);
    e.kind = kind;
    e.reference = ref;
    e.retriesLeft = retries;
    e.retriesMax = retries;
    e.canChange = true;
    e.state = LibreSCRS::Plugin::PinState::Operational;
    return e;
}

// A dual-applet eID-shaped fixture: a user PIN, a signature PIN, a PUK, and a
// second user PIN that shares the user PIN's card-native reference (a second
// applet exposing the same reference). The colliding pair forces id
// disambiguation.
std::vector<LibreSCRS::Plugin::PinStatusEntry> makeDualAppletEntries()
{
    using LibreSCRS::Plugin::PinKind;
    return {
        makeEntry("User PIN", PinKind::UserPin, 0x01, 3),
        makeEntry("Signature PIN", PinKind::SignPin, 0x92, 3),
        makeEntry("PUK", PinKind::Puk, 0x04, std::nullopt),
        makeEntry("User PIN (alt applet)", PinKind::UserPin, 0x01, 2),
    };
}

struct Harness
{
    // Set BEFORE make() to drive an acquire failure (mirrors CertReadFlowTest);
    // the holder is built lazily in make().
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    // Set BEFORE make() to pre-acquire the held session and mark it dead so the
    // flow observes card removal (isDead()) after the list returns.
    bool deadSession = false;
    std::unique_ptr<CardSessionHolder> holder;
    FakeCredentialManager credentials;
    // When set, make() binds THIS seam instead of `credentials` (the
    // channel-activating double for the provider-path cases).
    CredentialManager* seamOverride = nullptr;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    LibreSCRS::Agent::CredentialSnapshotCache snapshotCache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    std::string requester = "test-client";

    Harness()
    {
        credentials.listResult = makeDualAppletEntries();
    }

    CredentialListFlow make()
    {
        holder = makeHolder(failWith);
        if (deadSession) {
            auto acq = holder->acquire();
            if (acq) {
                acq->session->markDead();
            }
        }
        return CredentialListFlow{CredentialListFlowDeps{
            .holder = *holder,
            .credentials = seamOverride != nullptr ? *seamOverride : credentials,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .snapshotCache = snapshotCache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .requester = requester,
            .artifact = "credentials",
            .token = source.token(),
        }};
    }
};

} // namespace

TEST(CredentialListFlow, HappyPathMapsEntriesAndDisambiguatesIds)
{
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Ok);
    EXPECT_EQ(result.code, ErrorCode::None);
    ASSERT_EQ(result.snapshot.records.size(), 4u);

    // The two user-PIN entries share the bare id "user:0x01"; disambiguation
    // suffixes each colliding member with its zero-based occurrence index in
    // list order. The distinct entries keep their bare ids.
    EXPECT_EQ(result.snapshot.records[0].id, "user:0x01:0");
    EXPECT_EQ(result.snapshot.records[1].id, "sign:0x92");
    EXPECT_EQ(result.snapshot.records[2].id, "puk:0x04");
    EXPECT_EQ(result.snapshot.records[3].id, "user:0x01:1");

    // Field carry-over from the mapper.
    EXPECT_EQ(result.snapshot.records[0].label, "User PIN");
    EXPECT_EQ(result.snapshot.records[0].kind, "user");
    EXPECT_EQ(result.snapshot.records[0].retriesLeft, std::optional<int>{3});
    EXPECT_TRUE(result.snapshot.records[0].canChange);
    EXPECT_EQ(result.snapshot.records[1].kind, "sign");
    EXPECT_EQ(result.snapshot.records[2].kind, "puk");

    // Cache handoff: a successful list hands the snapshot to the per-card cache, which
    // stamps it with the next monotonic version (1 for this fixture's first put).
    // The returned snapshot carries that stamp, and the cache holds the same
    // snapshot under the card key at the same version.
    EXPECT_EQ(result.snapshot.version, 1u);
    auto cached = h.snapshotCache.get("card-A");
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->version, result.snapshot.version);
    EXPECT_EQ(cached->records.size(), result.snapshot.records.size());
}

// The produced snapshot must be BOUND to the candidate whose non-empty
// getPINList won the listing (CredentialListing::pluginId): the returned copy
// and the cached copy both carry it, so a later mutation resolves its routing
// preference from the same snapshot it resolves the addressed record from.
TEST(CredentialListFlow, SnapshotIsBoundToTheListingPluginIdentity)
{
    Harness h;
    h.credentials.listPluginId = "plugin-b";
    auto result = h.make().run();
    ASSERT_EQ(result.outcome, CredentialListFlow::Outcome::Ok);
    EXPECT_EQ(result.snapshot.listPluginId, "plugin-b");
    auto cached = h.snapshotCache.get("card-A");
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->listPluginId, "plugin-b") << "the cached snapshot carries the same binding";
}

TEST(CredentialListFlow, PreAuthPathInstallsCredentialProvider)
{
    // A pre-auth (PACE) card activates its secure channel inside getPINList and
    // invokes the installed read credential provider on a cache miss (CAN-once
    // semantics ride the shared session held by the CardSessionHolder). The flow
    // installs that provider on the held session exactly like the cert read.
    Harness h;
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Ok);
    auto acq = h.holder->acquire();
    ASSERT_TRUE(acq.has_value());
    EXPECT_TRUE(acq->session->hasCredentialProvider())
        << "the flow installs a credential provider on the held session (reset to a stateless no-op on exit)";
}

TEST(CredentialListFlow, EmptyListYieldsEmptyValidSnapshot)
{
    Harness h;
    h.credentials.listResult = {}; // a live card advertising no PIN credentials
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Ok) << "an empty list is a valid snapshot, not an error";
    EXPECT_EQ(result.code, ErrorCode::None);
    EXPECT_TRUE(result.snapshot.records.empty());
}

TEST(CredentialListFlow, OpenFailureMapsToErrorLikeCertFlow)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CommunicationError);
}

TEST(CredentialListFlow, TransportLossDuringListMapsToCardRemoved)
{
    // The card is yanked while getPINList runs: the seam swallows the candidate
    // throw and returns an empty list, but the session is marked dead. The flow
    // distinguishes this from a genuinely empty card and maps it through the
    // channel-activation error taxonomy to CardRemoved.
    Harness h;
    h.deadSession = true;
    h.credentials.listResult = {};
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CardRemoved);
}

// The card was pulled mid-list but the seam still handed back entries (its
// snapshot predates the removal): the flow must NOT report Ok for a removed
// card and must NOT re-create a snapshot under the dead cardKey (the removal
// hook already fired for it). Mirrors the mutation flows' unconditional
// isDead() classification.
TEST(CredentialListFlow, DeadSessionAfterEntriesMapsToCardRemovedAndCachesNothing)
{
    Harness h;
    h.deadSession = true; // non-empty listResult stays seeded by the harness
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::CardRemoved);
    EXPECT_FALSE(h.snapshotCache.get("card-A").has_value())
        << "a dead session must never re-create a snapshot the removal hook just dropped";
}

// A user-cancelled CAN prompt inside getPINList: the plugin's channel
// activation aborts, the seam hands back an empty list, and the ONLY signal is
// the cancel flag the flow-installed provider raised. The flow must finish
// Cancelled — never Ok-with-empty-snapshot — and must not cache the snapshot.
// This drives the REAL provider the flow installed (the seam double activates
// the channel on the held session, which resolves the secret via the provider
// before any card I/O).
TEST(CredentialListFlow, CanPromptCancelDuringListFinishesCancelledAndCachesNothing)
{
    Harness h;
    ChannelActivatingCredentialManager seam;
    seam.entries = makeDualAppletEntries();
    h.seamOverride = &seam;
    h.prompter.canResult = PromptResult{PromptStatus::Cancelled, std::nullopt, ""};

    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Cancelled)
        << "a user-dismissed CAN prompt is a cancellation, not a valid empty listing";
    EXPECT_EQ(result.code, ErrorCode::None);
    EXPECT_TRUE(result.snapshot.records.empty());
    EXPECT_FALSE(h.snapshotCache.get("card-A").has_value()) << "a cancelled list must never be cached";
}

// Control for the same rig: a BROKEN prompter (Error, not cancel) during the
// in-list channel activation keeps mapping to PrompterError — proving the two
// provider signals stay distinct end-to-end.
TEST(CredentialListFlow, CanPromptFailureDuringListMapsToPrompterError)
{
    Harness h;
    ChannelActivatingCredentialManager seam;
    seam.entries = makeDualAppletEntries();
    h.seamOverride = &seam;
    h.prompter.canResult = PromptResult{PromptStatus::Error, std::nullopt, "prompter gone"};

    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::PrompterError);
    EXPECT_FALSE(h.snapshotCache.get("card-A").has_value());
}

TEST(CredentialListFlow, CancelTokenPreEmpts)
{
    Harness h;
    h.source.requestCancel();
    auto result = h.make().run();
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Cancelled);
    EXPECT_EQ(result.code, ErrorCode::None);
}

// A field the wire record cannot represent (an out-of-range length bound) makes
// toCredentialRecord throw the runtime-exception family. The flow must CATCH it
// and finish Error — not let the throw escape the operation.
TEST(CredentialListFlow, OversizedLengthFieldFinishesErrorNotEscape)
{
    Harness h;
    auto bad = makeEntry("User PIN", LibreSCRS::Plugin::PinKind::UserPin, 0x01, 3);
    bad.maxLength = std::numeric_limits<std::size_t>::max(); // beyond the wire's int range
    h.credentials.listResult = {bad};

    CredentialListFlow::Result result;
    ASSERT_NO_THROW(result = h.make().run()) << "the mapper throw must be caught inside the flow, not escape the op";
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::ParseError);
    EXPECT_TRUE(result.snapshot.records.empty());
}

// Placeholder-bearing guidance is the OTHER unrepresentable-data case (previously
// a std::logic_error, now the same runtime family): the single catch handles it
// too, so the op finishes Error rather than crashing/escaping.
TEST(CredentialListFlow, PlaceholderGuidanceFieldFinishesErrorNotEscape)
{
    Harness h;
    auto bad = makeEntry("Signature PIN", LibreSCRS::Plugin::PinKind::SignPin, 0x92, 3);
    bad.blockedGuidance = LibreSCRS::LocalizedText{
        .key = "core.pin.blockedRetryLater",
        .defaultText = "Try again in {minutes} minutes.",
        .placeholders = {{.name = "minutes", .value = std::int64_t{5}}},
    };
    h.credentials.listResult = {bad};

    CredentialListFlow::Result result;
    ASSERT_NO_THROW(result = h.make().run()) << "the mapper throw must be caught inside the flow, not escape the op";
    EXPECT_EQ(result.outcome, CredentialListFlow::Outcome::Error);
    EXPECT_EQ(result.code, ErrorCode::ParseError);
}
