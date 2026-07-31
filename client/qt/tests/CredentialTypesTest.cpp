// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/AgentClient/CredentialTypes.h>

#include <QVariantMap>

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

TEST(CredentialTypes, RecordParsesFullRecord)
{
    QVariantMap m;
    m[QStringLiteral("id")] = QStringLiteral("user:0x86");
    m[QStringLiteral("label")] = QStringLiteral("User PIN");
    m[QStringLiteral("kind")] = QStringLiteral("user");
    m[QStringLiteral("state")] = QStringLiteral("operational");
    m[QStringLiteral("retries_left")] = 3;
    m[QStringLiteral("retries_max")] = 3;
    m[QStringLiteral("can_change")] = true;
    m[QStringLiteral("unblockable")] = true;
    m[QStringLiteral("unblock_style")] = QStringLiteral("unblockAndChange");
    m[QStringLiteral("activatable")] = false;
    m[QStringLiteral("key_activation_pending")] = false;
    m[QStringLiteral("key_activatable")] = false;
    m[QStringLiteral("recovery")] = QStringLiteral("holderViaPuk");
    m[QStringLiteral("probe_safe")] = true;
    const CredentialRecord r = CredentialRecord::fromVariantMap(m);
    EXPECT_EQ(r.id, QStringLiteral("user:0x86"));
    EXPECT_EQ(r.kind, CredentialKind::User);
    EXPECT_EQ(r.state, CredentialState::Operational);
    ASSERT_TRUE(r.retriesLeft.has_value());
    EXPECT_EQ(*r.retriesLeft, 3);
    EXPECT_TRUE(r.canChange);
    EXPECT_TRUE(r.unblockable);
    EXPECT_EQ(r.unblockStyle, UnblockStyle::UnblockAndChange);
    EXPECT_EQ(r.recovery, RecoveryPath::HolderViaPuk);
    EXPECT_TRUE(r.extra.isEmpty()); // every key above is a consumed, typed key
}

TEST(CredentialTypes, OmittedIntsStayNullopt)
{
    QVariantMap m;
    m[QStringLiteral("id")] = QStringLiteral("puk:0x93");
    m[QStringLiteral("kind")] = QStringLiteral("puk");
    m[QStringLiteral("state")] = QStringLiteral("operational");
    m[QStringLiteral("can_change")] = false;
    m[QStringLiteral("unblockable")] = false;
    m[QStringLiteral("activatable")] = false;
    m[QStringLiteral("key_activation_pending")] = false;
    m[QStringLiteral("key_activatable")] = false;
    m[QStringLiteral("probe_safe")] = false;
    const CredentialRecord r = CredentialRecord::fromVariantMap(m);
    EXPECT_FALSE(r.retriesLeft.has_value());
    EXPECT_FALSE(r.usesLeft.has_value());
    EXPECT_FALSE(r.usesMax.has_value());
    EXPECT_EQ(r.kind, CredentialKind::Puk);
    EXPECT_EQ(r.unblockStyle, UnblockStyle::Unknown); // absent token → Unknown
}

TEST(CredentialTypes, UnknownTokensAreSafe)
{
    QVariantMap m;
    m[QStringLiteral("kind")] = QStringLiteral("wat");
    m[QStringLiteral("state")] = QStringLiteral("nope");
    m[QStringLiteral("recovery")] = QStringLiteral("??");
    const CredentialRecord r = CredentialRecord::fromVariantMap(m);
    EXPECT_EQ(r.kind, CredentialKind::Unknown);
    EXPECT_EQ(r.state, CredentialState::Unknown);
    EXPECT_EQ(r.recovery, RecoveryPath::Unknown);
}

TEST(CredentialTypes, PinResultParses)
{
    QVariantMap m;
    m[QStringLiteral("outcome")] = QStringLiteral("invalidPin");
    m[QStringLiteral("retries_left")] = 2;
    m[QStringLiteral("blocked")] = false;
    const PinResult r = PinResult::fromVariantMap(m);
    EXPECT_EQ(r.outcome, CredentialOutcome::InvalidPin);
    ASSERT_TRUE(r.retriesLeft.has_value());
    EXPECT_EQ(*r.retriesLeft, 2);
    EXPECT_FALSE(r.blocked);
    EXPECT_FALSE(r.pinActivated.has_value()); // omitted → nullopt
}

// Wire-key drift guard: the snake_case key strings below are the VERBATIM
// record/result key set of the frozen credential wire contract — both wires
// carry the same spellings, and this client mirrors them by hand, so the
// production demarshaller and ordinary self-consistent fixtures could drift
// TOGETHER; this fixture freezes the contract spelling. Every key carries a
// non-default value and every demarshaled field must come back non-default —
// a client-side key rename (e.g. reading "retriesLeft" where the agent emits
// "retries_left") fails loudly here while passing every self-consistent test.
// Keep byte-identical to the contract.
TEST(CredentialTypes, ContractVerbatimRecordKeySetDemarshalsEveryFieldNonDefault)
{
    const QVariantMap wire{
        {QStringLiteral("id"), QStringLiteral("user:0x86")},
        {QStringLiteral("label"), QStringLiteral("User PIN")},
        {QStringLiteral("kind"), QStringLiteral("user")},
        {QStringLiteral("state"), QStringLiteral("operational")},
        {QStringLiteral("retries_left"), 3},
        {QStringLiteral("retries_max"), 5},
        {QStringLiteral("uses_left"), 28},
        {QStringLiteral("uses_max"), 40},
        {QStringLiteral("unblocks_left"), 19},
        {QStringLiteral("min_length"), 4},
        {QStringLiteral("max_length"), 8},
        {QStringLiteral("can_change"), true},
        {QStringLiteral("unblockable"), true},
        {QStringLiteral("unblock_style"), QStringLiteral("setsNewPin")},
        {QStringLiteral("activatable"), true},
        {QStringLiteral("key_activation_pending"), true},
        {QStringLiteral("key_activatable"), true},
        {QStringLiteral("recovery"), QStringLiteral("holderViaPuk")},
        {QStringLiteral("probe_safe"), true},
        {QStringLiteral("blocked_guidance_key"), QStringLiteral("librescrs.pin.blocked.issuer")},
        {QStringLiteral("blocked_guidance_fallback"), QStringLiteral("Contact the issuer.")},
        {QStringLiteral("key_activation_guidance_key"), QStringLiteral("librescrs.pin.keyActivation.issuer")},
        {QStringLiteral("key_activation_guidance_fallback"), QStringLiteral("The issuer activates the key.")},
    };
    const CredentialRecord r = CredentialRecord::fromVariantMap(wire);
    EXPECT_EQ(r.id, QStringLiteral("user:0x86"));
    EXPECT_EQ(r.label, QStringLiteral("User PIN"));
    EXPECT_EQ(r.kind, CredentialKind::User);
    EXPECT_EQ(r.state, CredentialState::Operational);
    ASSERT_TRUE(r.retriesLeft && r.retriesMax && r.usesLeft && r.usesMax && r.unblocksLeft && r.minLength &&
                r.maxLength);
    EXPECT_EQ(*r.retriesLeft, 3);
    EXPECT_EQ(*r.retriesMax, 5);
    EXPECT_EQ(*r.usesLeft, 28);
    EXPECT_EQ(*r.usesMax, 40);
    EXPECT_EQ(*r.unblocksLeft, 19);
    EXPECT_EQ(*r.minLength, 4);
    EXPECT_EQ(*r.maxLength, 8);
    EXPECT_TRUE(r.canChange);
    EXPECT_TRUE(r.unblockable);
    EXPECT_EQ(r.unblockStyle, UnblockStyle::SetsNewPin);
    EXPECT_TRUE(r.activatable);
    EXPECT_TRUE(r.keyActivationPending);
    EXPECT_TRUE(r.keyActivatable);
    EXPECT_EQ(r.recovery, RecoveryPath::HolderViaPuk);
    EXPECT_TRUE(r.probeSafe);
    ASSERT_TRUE(r.blockedGuidanceKey && r.blockedGuidanceFallback);
    EXPECT_EQ(*r.blockedGuidanceKey, QStringLiteral("librescrs.pin.blocked.issuer"));
    EXPECT_EQ(*r.blockedGuidanceFallback, QStringLiteral("Contact the issuer."));
    ASSERT_TRUE(r.keyActivationGuidanceKey && r.keyActivationGuidanceFallback);
    EXPECT_EQ(*r.keyActivationGuidanceKey, QStringLiteral("librescrs.pin.keyActivation.issuer"));
    EXPECT_EQ(*r.keyActivationGuidanceFallback, QStringLiteral("The issuer activates the key."));
    EXPECT_TRUE(r.extra.isEmpty()); // the full consumed key set leaves no leftovers
}

// The result half of the guard above: the uniform mutation-result key set,
// contract-verbatim, every field non-default. Its own case rather than more
// keys in the record fixture, because the two maps travel on different wire
// messages and can drift independently.
TEST(CredentialTypes, ContractVerbatimResultKeySetDemarshalsEveryFieldNonDefault)
{
    const QVariantMap wire{
        {QStringLiteral("outcome"), QStringLiteral("invalidPin")},
        {QStringLiteral("retries_left"), 2},
        {QStringLiteral("blocked"), true},
        {QStringLiteral("pin_activated"), true},
        {QStringLiteral("key_activated"), true},
    };
    const PinResult r = PinResult::fromVariantMap(wire);
    EXPECT_EQ(r.outcome, CredentialOutcome::InvalidPin);
    ASSERT_TRUE(r.retriesLeft.has_value());
    EXPECT_EQ(*r.retriesLeft, 2);
    EXPECT_TRUE(r.blocked);
    ASSERT_TRUE(r.pinActivated.has_value());
    EXPECT_TRUE(*r.pinActivated);
    ASSERT_TRUE(r.keyActivated.has_value());
    EXPECT_TRUE(*r.keyActivated);
    EXPECT_TRUE(r.extra.isEmpty()); // the full consumed key set leaves no leftovers
}

// A partial bring-up: the PIN was activated but the signing key behind it was
// not. The two flags are INDEPENDENT, and the failing one arrives as an
// explicit false rather than as an absent key — so a demarshaller that only
// populated an optional bool when the wire says true would report the key
// activation as "not reported" instead of "reported failed", and this is the
// case that separates those.
TEST(CredentialTypes, PinResultBringUpPartial)
{
    QVariantMap m;
    m[QStringLiteral("outcome")] = QStringLiteral("keyActivationFailed");
    m[QStringLiteral("blocked")] = false;
    m[QStringLiteral("pin_activated")] = true;
    m[QStringLiteral("key_activated")] = false;
    const PinResult r = PinResult::fromVariantMap(m);
    EXPECT_EQ(r.outcome, CredentialOutcome::KeyActivationFailed);
    ASSERT_TRUE(r.pinActivated.has_value());
    EXPECT_TRUE(*r.pinActivated);
    ASSERT_TRUE(r.keyActivated.has_value());
    EXPECT_FALSE(*r.keyActivated);
}

// Append-only wire growth: keys this client build does not know must reach
// the consumer via the `extra` pass-through, never be dropped.
TEST(CredentialTypes, UnknownKeysPassThroughExtra)
{
    QVariantMap m;
    m[QStringLiteral("id")] = QStringLiteral("user:0x86");
    m[QStringLiteral("kind")] = QStringLiteral("user");
    m[QStringLiteral("some_future_counter")] = 7;
    const CredentialRecord r = CredentialRecord::fromVariantMap(m);
    EXPECT_EQ(r.extra.size(), 1);
    EXPECT_EQ(r.extra.value(QStringLiteral("some_future_counter")).toInt(), 7);

    QVariantMap p;
    p[QStringLiteral("outcome")] = QStringLiteral("ok");
    p[QStringLiteral("some_future_flag")] = true;
    const PinResult pr = PinResult::fromVariantMap(p);
    EXPECT_EQ(pr.outcome, CredentialOutcome::Ok);
    EXPECT_EQ(pr.extra.size(), 1);
    EXPECT_TRUE(pr.extra.value(QStringLiteral("some_future_flag")).toBool());
}
