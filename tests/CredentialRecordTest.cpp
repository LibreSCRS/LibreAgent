// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Wire-record mapping table for the credential lifecycle types: one test per
// mapping rule (enum token tables, id synthesis + collision disambiguation,
// checked length narrowing, guidance key/fallback split + placeholders guard,
// outcome superset) plus defaults for the snapshot/result/entry-error types.
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

using LibreSCRS::LocalizedText;
using LibreSCRS::Agent::CredentialOpResult;
using LibreSCRS::Agent::CredentialOutcome;
using LibreSCRS::Agent::CredentialRecord;
using LibreSCRS::Agent::CredentialSnapshot;
using LibreSCRS::Agent::disambiguateCredentialIds;
using LibreSCRS::Agent::EntryError;
using LibreSCRS::Agent::toCredentialOutcome;
using LibreSCRS::Agent::toCredentialRecord;
using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinRecovery;
using LibreSCRS::Plugin::PINResultOutcome;
using LibreSCRS::Plugin::PinState;
using LibreSCRS::Plugin::PinStatusEntry;
using LibreSCRS::Plugin::UnblockStyle;

namespace {

PinStatusEntry entryWith(PinKind kind, std::uint8_t reference)
{
    PinStatusEntry e;
    e.label = "Test PIN";
    e.kind = kind;
    e.reference = reference;
    return e;
}

} // namespace

// --- enum -> wire string token tables (every member, exhaustively) ----------

TEST(CredentialRecordMap, KindTokens)
{
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::Unknown, 0x00)).kind, "unknown");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::UserPin, 0x00)).kind, "user");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::SignPin, 0x00)).kind, "sign");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::Puk, 0x00)).kind, "puk");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::Can, 0x00)).kind, "can");
}

TEST(CredentialRecordMap, StateTokens)
{
    auto stateToken = [](PinState state) {
        auto e = entryWith(PinKind::UserPin, 0x01);
        e.state = state;
        return toCredentialRecord(e).state;
    };
    EXPECT_EQ(stateToken(PinState::Unknown), "unknown");
    EXPECT_EQ(stateToken(PinState::Transport), "transport");
    EXPECT_EQ(stateToken(PinState::Operational), "operational");
    EXPECT_EQ(stateToken(PinState::NeedsChange), "needsChange");
    EXPECT_EQ(stateToken(PinState::Blocked), "blocked");
}

TEST(CredentialRecordMap, UnblockStyleTokens)
{
    auto styleToken = [](UnblockStyle style) {
        auto e = entryWith(PinKind::UserPin, 0x01);
        e.unblockStyle = style;
        return toCredentialRecord(e).unblockStyle;
    };
    EXPECT_EQ(styleToken(UnblockStyle::Unknown), "unknown");
    EXPECT_EQ(styleToken(UnblockStyle::ResetOnly), "resetOnly");
    EXPECT_EQ(styleToken(UnblockStyle::SetsNewPin), "setsNewPin");
    EXPECT_EQ(styleToken(UnblockStyle::UnblockAndChange), "unblockAndChange");
}

TEST(CredentialRecordMap, RecoveryTokens)
{
    auto recoveryToken = [](PinRecovery recovery) {
        auto e = entryWith(PinKind::UserPin, 0x01);
        e.recovery = recovery;
        return toCredentialRecord(e).recovery;
    };
    EXPECT_EQ(recoveryToken(PinRecovery::Unknown), "unknown");
    EXPECT_EQ(recoveryToken(PinRecovery::HolderViaPuk), "holderViaPuk");
    EXPECT_EQ(recoveryToken(PinRecovery::IssuerProcess), "issuerProcess");
    EXPECT_EQ(recoveryToken(PinRecovery::None), "none");
}

// --- outcome superset -------------------------------------------------------

TEST(CredentialOutcomeMap, AllNineLmMembersMapToSameNamedMember)
{
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::Unspecified), CredentialOutcome::Unspecified);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::Ok), CredentialOutcome::Ok);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::UserCancelled), CredentialOutcome::UserCancelled);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::MissingFields), CredentialOutcome::MissingFields);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::InvalidPin), CredentialOutcome::InvalidPin);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::Blocked), CredentialOutcome::Blocked);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::PluginError), CredentialOutcome::PluginError);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::Unsupported), CredentialOutcome::Unsupported);
    EXPECT_EQ(toCredentialOutcome(PINResultOutcome::KeyActivationFailed), CredentialOutcome::KeyActivationFailed);
}

TEST(CredentialOutcomeMap, CardRemovedIsAgentAssignedTail)
{
    // CardRemoved sits after the LM range as the agent-assigned transport-loss
    // member; no LM outcome may ever map onto it (the mapping above is the
    // proof for the current nine — this pins the tail position itself).
    EXPECT_EQ(static_cast<int>(CredentialOutcome::CardRemoved),
              static_cast<int>(CredentialOutcome::KeyActivationFailed) + 1);
}

// --- id synthesis -----------------------------------------------------------

TEST(CredentialRecordMap, IdSynthesisIsKindColonHexReference)
{
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::SignPin, 0x92)).id, "sign:0x92");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::UserPin, 0x01)).id, "user:0x01");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::Unknown, 0x00)).id, "unknown:0x00");
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::Can, 0xAB)).id, "can:0xab"); // lowercase hex, zero-padded
    EXPECT_EQ(toCredentialRecord(entryWith(PinKind::Puk, 0x04)).id, "puk:0x04");
}

TEST(CredentialRecordMap, IdIsStableForEqualInputs)
{
    const auto a = toCredentialRecord(entryWith(PinKind::SignPin, 0x92));
    const auto b = toCredentialRecord(entryWith(PinKind::SignPin, 0x92));
    EXPECT_EQ(a.id, b.id);
    EXPECT_EQ(a, b); // whole-record equality: the mapping is pure
}

TEST(CredentialRecordMap, CollidingIdsGetDeterministicListOrderSuffixes)
{
    const std::vector<CredentialRecord> mapped{
        toCredentialRecord(entryWith(PinKind::Unknown, 0x00)),
        toCredentialRecord(entryWith(PinKind::SignPin, 0x92)),
        toCredentialRecord(entryWith(PinKind::Unknown, 0x00)),
        toCredentialRecord(entryWith(PinKind::Unknown, 0x00)),
    };

    auto records = mapped;
    disambiguateCredentialIds(records);
    // EVERY member of the colliding group is suffixed, zero-based, list order.
    EXPECT_EQ(records[0].id, "unknown:0x00:0");
    EXPECT_EQ(records[2].id, "unknown:0x00:1");
    EXPECT_EQ(records[3].id, "unknown:0x00:2");
    // Non-colliding ids stay bare.
    EXPECT_EQ(records[1].id, "sign:0x92");

    // Determinism: same input order -> same ids.
    auto again = mapped;
    disambiguateCredentialIds(again);
    for (std::size_t i = 0; i < records.size(); ++i)
        EXPECT_EQ(again[i].id, records[i].id) << "index " << i;
}

TEST(CredentialRecordMap, NoCollisionLeavesEveryIdBare)
{
    std::vector<CredentialRecord> records{
        toCredentialRecord(entryWith(PinKind::UserPin, 0x01)),
        toCredentialRecord(entryWith(PinKind::SignPin, 0x92)),
    };
    disambiguateCredentialIds(records);
    EXPECT_EQ(records[0].id, "user:0x01");
    EXPECT_EQ(records[1].id, "sign:0x92");
}

// --- initialized/blocked deliberately not represented -----------------------

TEST(CredentialRecordMap, InitializedAndBlockedCrossOnlyViaState)
{
    auto a = entryWith(PinKind::UserPin, 0x01);
    a.initialized = true;
    a.blocked = false;
    auto b = a;
    b.initialized = false;
    b.blocked = true;
    // The mapper reads neither flag: lifecycle crosses only through `state`
    // (safe — LM keeps the invariant state==Blocked <=> blocked).
    EXPECT_EQ(toCredentialRecord(a), toCredentialRecord(b));

    auto c = a;
    c.blocked = true;
    c.state = PinState::Blocked;
    EXPECT_EQ(toCredentialRecord(c).state, "blocked");
}

// --- checked min/max length narrowing ---------------------------------------

TEST(CredentialRecordMap, LengthBoundsNarrowCheckedFromSizeT)
{
    auto e = entryWith(PinKind::UserPin, 0x01);
    e.minLength = std::size_t{4};
    e.maxLength = std::size_t{8};
    const auto r = toCredentialRecord(e);
    EXPECT_EQ(r.minLength, std::optional<int>{4});
    EXPECT_EQ(r.maxLength, std::optional<int>{8});

    // Unknown stays unknown.
    const auto bare = toCredentialRecord(entryWith(PinKind::UserPin, 0x01));
    EXPECT_FALSE(bare.minLength.has_value());
    EXPECT_FALSE(bare.maxLength.has_value());

    // The full int range narrows exactly.
    e.maxLength = static_cast<std::size_t>(std::numeric_limits<int>::max());
    EXPECT_EQ(toCredentialRecord(e).maxLength, std::optional<int>{std::numeric_limits<int>::max()});
}

TEST(CredentialRecordMap, LengthBeyondIntRangeFailsLoudly)
{
    auto e = entryWith(PinKind::UserPin, 0x01);
    e.maxLength = static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1u;
    EXPECT_THROW(static_cast<void>(toCredentialRecord(e)), std::overflow_error);

    auto f = entryWith(PinKind::UserPin, 0x01);
    f.minLength = std::numeric_limits<std::size_t>::max();
    EXPECT_THROW(static_cast<void>(toCredentialRecord(f)), std::overflow_error);
}

// --- guidance split + placeholders guard ------------------------------------

TEST(CredentialRecordMap, GuidanceSplitsIntoKeyAndFallbackVerbatim)
{
    auto e = entryWith(PinKind::SignPin, 0x92);
    e.blockedGuidance =
        LocalizedText{.key = "core.pin.blockedContactIssuer", .defaultText = "Contact the issuer to recover this PIN."};
    e.keyActivationGuidance = LocalizedText{.key = "core.pin.keyActivationIssuerOnly",
                                            .defaultText = "The signing key must be activated by the issuer."};
    const auto r = toCredentialRecord(e);
    EXPECT_EQ(r.blockedGuidanceKey, "core.pin.blockedContactIssuer");
    EXPECT_EQ(r.blockedGuidanceFallback, "Contact the issuer to recover this PIN.");
    EXPECT_EQ(r.keyActivationGuidanceKey, "core.pin.keyActivationIssuerOnly");
    EXPECT_EQ(r.keyActivationGuidanceFallback, "The signing key must be activated by the issuer.");
}

TEST(CredentialRecordMap, AbsentGuidanceStaysDisengaged)
{
    const auto r = toCredentialRecord(entryWith(PinKind::SignPin, 0x92));
    EXPECT_FALSE(r.blockedGuidanceKey.has_value());
    EXPECT_FALSE(r.blockedGuidanceFallback.has_value());
    EXPECT_FALSE(r.keyActivationGuidanceKey.has_value());
    EXPECT_FALSE(r.keyActivationGuidanceFallback.has_value());
}

TEST(CredentialRecordMap, PlaceholderBearingGuidanceIsRejectedLoudly)
{
    const LocalizedText withPlaceholder{
        .key = "core.pin.blockedRetryLater",
        .defaultText = "Try again in {minutes} minutes.",
        .placeholders = {{.name = "minutes", .value = std::int64_t{5}}},
    };

    // Both unrepresentable-plugin-data conditions (placeholder guidance and an
    // out-of-range length) throw the SAME runtime-exception family, so a single
    // catch(const std::runtime_error&) in the list flow catches either.
    auto viaBlocked = entryWith(PinKind::UserPin, 0x01);
    viaBlocked.blockedGuidance = withPlaceholder;
    EXPECT_THROW(static_cast<void>(toCredentialRecord(viaBlocked)), std::runtime_error);

    auto viaKeyActivation = entryWith(PinKind::SignPin, 0x92);
    viaKeyActivation.keyActivationGuidance = withPlaceholder;
    EXPECT_THROW(static_cast<void>(toCredentialRecord(viaKeyActivation)), std::runtime_error);
}

// --- full scalar field carry-over -------------------------------------------

TEST(CredentialRecordMap, FullyPopulatedEntryMapsFieldForField)
{
    PinStatusEntry e;
    e.label = "Signature PIN";
    e.reference = 0x92;
    e.kind = PinKind::SignPin;
    e.state = PinState::Operational;
    e.retriesLeft = 3;
    e.retriesMax = 5;
    e.usesLeft = 7;
    e.usesMax = 20;
    e.unblocksLeft = 2;
    e.minLength = std::size_t{6};
    e.maxLength = std::size_t{12};
    e.canChange = true;
    e.unblockable = true;
    e.unblockStyle = UnblockStyle::SetsNewPin;
    e.activatable = true;
    e.keyActivationPending = true;
    e.keyActivatable = true;
    e.recovery = PinRecovery::HolderViaPuk;
    e.probeSafe = true;

    const auto r = toCredentialRecord(e);
    EXPECT_EQ(r.id, "sign:0x92");
    EXPECT_EQ(r.label, "Signature PIN");
    EXPECT_EQ(r.kind, "sign");
    EXPECT_EQ(r.state, "operational");
    EXPECT_EQ(r.retriesLeft, std::optional<int>{3});
    EXPECT_EQ(r.retriesMax, std::optional<int>{5});
    EXPECT_EQ(r.usesLeft, std::optional<int>{7});
    EXPECT_EQ(r.usesMax, std::optional<int>{20});
    EXPECT_EQ(r.unblocksLeft, std::optional<int>{2});
    EXPECT_EQ(r.minLength, std::optional<int>{6});
    EXPECT_EQ(r.maxLength, std::optional<int>{12});
    EXPECT_TRUE(r.canChange);
    EXPECT_TRUE(r.unblockable);
    EXPECT_EQ(r.unblockStyle, "setsNewPin");
    EXPECT_TRUE(r.activatable);
    EXPECT_TRUE(r.keyActivationPending);
    EXPECT_TRUE(r.keyActivatable);
    EXPECT_EQ(r.recovery, "holderViaPuk");
    EXPECT_TRUE(r.probeSafe);
}

// --- snapshot / mutation result / entry-error vocabulary --------------------

TEST(CredentialTypes, SnapshotDefaults)
{
    const CredentialSnapshot snapshot;
    EXPECT_TRUE(snapshot.records.empty());
    EXPECT_EQ(snapshot.version, 0u);
}

TEST(CredentialTypes, OpResultDefaults)
{
    const CredentialOpResult result;
    EXPECT_EQ(result.outcome, CredentialOutcome::Unspecified);
    EXPECT_FALSE(result.retriesLeft.has_value());
    EXPECT_FALSE(result.blocked);
    EXPECT_FALSE(result.pinActivated.has_value());
    EXPECT_FALSE(result.keyActivated.has_value());
}

TEST(CredentialTypes, EntryErrorVocabularyIsClosed)
{
    // Compile-level pin of the closed five-member vocabulary.
    constexpr std::array vocabulary{EntryError::UnknownVerb, EntryError::UnknownOption, EntryError::UnknownCredential,
                                    EntryError::InvalidCombination, EntryError::AmbiguousCredential};
    EXPECT_EQ(vocabulary.size(), 5u);
}
