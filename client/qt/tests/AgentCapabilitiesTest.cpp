// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentCapabilities.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

TEST(AgentCapabilities, UiStateGroupings)
{
    EXPECT_EQ(uiStateFor(Cap::IdentityData | Cap::Pki), UiState::Hybrid);
    EXPECT_EQ(uiStateFor(Cap::IdentityData), UiState::IdentityOnly);
    EXPECT_EQ(uiStateFor(Cap::Pki | Cap::PinManagement), UiState::PkiOnly);
    EXPECT_EQ(uiStateFor(0u), UiState::None);
}

TEST(AgentCapabilities, AncillaryOnlyCapabilitiesHaveNoSurface)
{
    // EmrtdCrypto / PinManagement on their own create no consumer surface.
    EXPECT_EQ(uiStateFor(Cap::EmrtdCrypto), UiState::None);
    EXPECT_EQ(uiStateFor(Cap::PinManagement), UiState::None);
    EXPECT_EQ(uiStateFor(Cap::EmrtdCrypto | Cap::PinManagement), UiState::None);
}

TEST(AgentCapabilities, IdentityWithEmrtdCollapsesToIdentityOnly)
{
    EXPECT_EQ(uiStateFor(Cap::IdentityData | Cap::EmrtdCrypto), UiState::IdentityOnly);
}

TEST(AgentCapabilities, AllCapabilitiesAreHybrid)
{
    const auto everything = Cap::Pki | Cap::IdentityData | Cap::EmrtdCrypto | Cap::PinManagement;
    EXPECT_EQ(uiStateFor(everything), UiState::Hybrid);
}

TEST(AgentCapabilities, HasFlag)
{
    EXPECT_TRUE(has(Cap::EmrtdCrypto | Cap::Pki, Cap::EmrtdCrypto));
    EXPECT_TRUE(has(Cap::EmrtdCrypto | Cap::Pki, Cap::Pki));
    EXPECT_FALSE(has(Cap::EmrtdCrypto | Cap::Pki, Cap::IdentityData));
    EXPECT_FALSE(has(Cap::None, Cap::Pki));
}

TEST(AgentCapabilities, BitValuesMirrorTheWireContract)
{
    // Hand-checked against the wire contract's capability-bit group (itself
    // anchored to the middleware CardCapabilities enum agent-side).
    EXPECT_EQ(Cap::Pki, 1u << 0);
    EXPECT_EQ(Cap::IdentityData, 1u << 1);
    EXPECT_EQ(Cap::EmrtdCrypto, 1u << 2);
    EXPECT_EQ(Cap::PinManagement, 1u << 3);
}

// resolveCardState owns the not-present / pre-auth-latch / None->Error logic
// each surface would otherwise re-implement. Covers every capability row
// crossed with the three PreReadAuth values, plus the not-present and
// identity-already-read latch-clear cases.

TEST(AgentCapabilities, ResolveCardStateNotPresentIsNoCard)
{
    // Capabilities / preAuth are irrelevant when no card is present.
    EXPECT_EQ(resolveCardState(Cap::IdentityData | Cap::Pki, PreReadAuth::None, false, false), UiState::NoCard);
    EXPECT_EQ(resolveCardState(Cap::Pki, PreReadAuth::Can, false, true), UiState::NoCard);
    EXPECT_EQ(resolveCardState(0u, PreReadAuth::Mrz, false, false), UiState::NoCard);
}

TEST(AgentCapabilities, ResolveCardStatePreAuthLatch)
{
    // A pre-read unlock is required and identity has not been read yet ->
    // PreAuthRequired, regardless of the capability grouping.
    EXPECT_EQ(resolveCardState(Cap::IdentityData, PreReadAuth::Can, true, false), UiState::PreAuthRequired);
    EXPECT_EQ(resolveCardState(Cap::IdentityData | Cap::Pki, PreReadAuth::Mrz, true, false), UiState::PreAuthRequired);

    // Once identity has been read the latch clears and we fall through to the
    // coarse grouping.
    EXPECT_EQ(resolveCardState(Cap::IdentityData, PreReadAuth::Can, true, true), UiState::IdentityOnly);
    EXPECT_EQ(resolveCardState(Cap::IdentityData | Cap::Pki, PreReadAuth::Mrz, true, true), UiState::Hybrid);
}

TEST(AgentCapabilities, ResolveCardStateGroupingWhenNoPreAuth)
{
    // present, PreReadAuth::None -> the uiStateFor grouping (identityRead is
    // irrelevant without a pre-auth latch).
    EXPECT_EQ(resolveCardState(Cap::IdentityData | Cap::Pki, PreReadAuth::None, true, false), UiState::Hybrid);
    EXPECT_EQ(resolveCardState(Cap::IdentityData, PreReadAuth::None, true, false), UiState::IdentityOnly);
    EXPECT_EQ(resolveCardState(Cap::Pki, PreReadAuth::None, true, false), UiState::PkiOnly);
    EXPECT_EQ(resolveCardState(Cap::IdentityData | Cap::EmrtdCrypto, PreReadAuth::None, true, false),
              UiState::IdentityOnly);
}

TEST(AgentCapabilities, ResolveCardStateEmptyIsUnknownAncillaryIsError)
{
    // Empty capability set on a present card = no plugin matched -> UnknownCard
    // (a calm, distinct state). Ancillary-only sets (Emrtd/PinManagement without
    // IdentityData or PKI) have no user surface and remain Error.
    EXPECT_EQ(resolveCardState(0u, PreReadAuth::None, true, false), UiState::UnknownCard);
    EXPECT_EQ(resolveCardState(Cap::EmrtdCrypto, PreReadAuth::None, true, false), UiState::Error);
    EXPECT_EQ(resolveCardState(Cap::PinManagement, PreReadAuth::None, true, false), UiState::Error);
    EXPECT_EQ(resolveCardState(Cap::EmrtdCrypto | Cap::PinManagement, PreReadAuth::None, true, true), UiState::Error);
}

// ---- token vocabulary (new in the lift: the public API speaks tokens) ---------

TEST(AgentCapabilityTokens, KnownBitsUseContractNames)
{
    EXPECT_EQ(capabilityTokens(Cap::Pki), QStringList{QStringLiteral("Pki")});
    EXPECT_EQ(capabilityTokens(Cap::IdentityData | Cap::Pki),
              (QStringList{QStringLiteral("Pki"), QStringLiteral("IdentityData")}));
    EXPECT_EQ(capabilityTokens(Cap::Pki | Cap::IdentityData | Cap::EmrtdCrypto | Cap::PinManagement),
              (QStringList{QStringLiteral("Pki"), QStringLiteral("IdentityData"), QStringLiteral("EmrtdCrypto"),
                           QStringLiteral("PinManagement")}));
    EXPECT_TRUE(capabilityTokens(Cap::None).isEmpty());
}

TEST(AgentCapabilityTokens, RoundTripsEveryKnownCombination)
{
    for (std::uint32_t caps = 0; caps < 16u; ++caps) {
        EXPECT_EQ(capabilityBits(capabilityTokens(caps)), caps) << "caps=" << caps;
    }
}

TEST(AgentCapabilityTokens, UnknownBitsRoundTripAsNumberedTokens)
{
    // A future appended capability must survive token conversion instead of
    // being silently dropped.
    const std::uint32_t futureBit = 1u << 7;
    const QStringList tokens = capabilityTokens(Cap::Pki | futureBit);
    EXPECT_EQ(tokens, (QStringList{QStringLiteral("Pki"), QStringLiteral("bit7")}));
    EXPECT_EQ(capabilityBits(tokens), Cap::Pki | futureBit);
}

TEST(AgentCapabilityTokens, UnrecognizedTokensAreIgnored)
{
    EXPECT_EQ(capabilityBits(QStringList{QStringLiteral("Pki"), QStringLiteral("SomethingNew")}), Cap::Pki);
    EXPECT_EQ(capabilityBits(QStringList{QStringLiteral("bitXYZ")}), Cap::None);
    EXPECT_EQ(capabilityBits(QStringList{QStringLiteral("bit99")}), Cap::None); // out of range
}

TEST(AgentCapabilityTokens, PreReadAuthTokenDecode)
{
    EXPECT_EQ(preReadAuthFromToken(u"None"), PreReadAuth::None);
    EXPECT_EQ(preReadAuthFromToken(u"Mrz"), PreReadAuth::Mrz);
    EXPECT_EQ(preReadAuthFromToken(u"Can"), PreReadAuth::Can);
    // Lenient parse: anything unrecognized (including a future method) is None.
    EXPECT_EQ(preReadAuthFromToken(u"SomethingFuture"), PreReadAuth::None);
    EXPECT_EQ(preReadAuthFromToken(u""), PreReadAuth::None);
}
