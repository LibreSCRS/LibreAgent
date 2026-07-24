// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Round-trip (enum -> token -> enum) coverage for every SignatureFormat/
// SignatureLevel/Packaging/PinVerb value, the exact token strings pinned
// against the CDDL/agent-side vocabulary (see TokenMap.h's doc comment for
// the authoritative sources), and unknown-token -> nullopt for each family.
//
// TokenMap.cpp is compiled directly into this test binary (see
// client/qt/tests/CMakeLists.txt) rather than linked from the
// LibreAgentClientQt shared library: TokenMap is a hidden-visibility
// internal TU by design (CXX_VISIBILITY_PRESET hidden, no export macro on
// any of its functions), so its symbols are not part of the library's
// dynamic symbol table for an external test executable to link against.
#include "../src/TokenMap.h"

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::detail;

// ---- SignatureFormat ---------------------------------------------------

TEST(TokenMap, SignatureFormatTokensMatchTheWireVocabulary)
{
    // LibreSCRS::Agent::Operations::SignatureParams::isKnownFormat's closed set.
    EXPECT_EQ(toToken(SignatureFormat::PAdES), "pades");
    EXPECT_EQ(toToken(SignatureFormat::CAdES), "cades");
    EXPECT_EQ(toToken(SignatureFormat::XAdES), "xades");
    EXPECT_EQ(toToken(SignatureFormat::JAdES), "jades");
    EXPECT_EQ(toToken(SignatureFormat::ASiCe), "asice");
}

TEST(TokenMap, SignatureFormatRoundTripsEveryValue)
{
    for (const auto value : {SignatureFormat::PAdES, SignatureFormat::CAdES, SignatureFormat::XAdES,
                             SignatureFormat::JAdES, SignatureFormat::ASiCe}) {
        const std::string_view token = toToken(value);
        ASSERT_FALSE(token.empty());
        const std::optional<SignatureFormat> back = signatureFormatFromToken(token);
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(*back, value);
    }
}

TEST(TokenMap, SignatureFormatUnknownTokenIsNullopt)
{
    EXPECT_EQ(signatureFormatFromToken("PAdES"), std::nullopt); // wrong case
    EXPECT_EQ(signatureFormatFromToken("pdf"), std::nullopt);
    EXPECT_EQ(signatureFormatFromToken("asics"), std::nullopt); // ASiC-S: out of scope
    EXPECT_EQ(signatureFormatFromToken(""), std::nullopt);
}

// ---- SignatureLevel -----------------------------------------------------

TEST(TokenMap, SignatureLevelTokensMatchTheWireVocabulary)
{
    // SignatureParams::isKnownLevel's closed set / kImplementedSignLevels.
    EXPECT_EQ(toToken(SignatureLevel::BB), "b-b");
    EXPECT_EQ(toToken(SignatureLevel::BT), "b-t");
    EXPECT_EQ(toToken(SignatureLevel::BLT), "b-lt");
    EXPECT_EQ(toToken(SignatureLevel::BLTA), "b-lta");
}

TEST(TokenMap, SignatureLevelRoundTripsEveryValue)
{
    for (const auto value : {SignatureLevel::BB, SignatureLevel::BT, SignatureLevel::BLT, SignatureLevel::BLTA}) {
        const std::string_view token = toToken(value);
        ASSERT_FALSE(token.empty());
        const std::optional<SignatureLevel> back = signatureLevelFromToken(token);
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(*back, value);
    }
}

TEST(TokenMap, SignatureLevelUnknownTokenIsNullopt)
{
    EXPECT_EQ(signatureLevelFromToken("BB"), std::nullopt); // wrong case
    EXPECT_EQ(signatureLevelFromToken("bb"), std::nullopt); // missing the hyphen
    EXPECT_EQ(signatureLevelFromToken("b-lta-plus"), std::nullopt);
    EXPECT_EQ(signatureLevelFromToken(""), std::nullopt);
}

// ---- Packaging -----------------------------------------------------------

TEST(TokenMap, PackagingTokensMatchTheWireVocabulary)
{
    // SignatureParams::isKnownPackaging accepts enveloped/detached today;
    // Enveloping is forward-declared (see SignOptions.h) with no agent-side
    // acceptance yet, but its token still follows the same lowercase
    // full-word convention as its two siblings.
    EXPECT_EQ(toToken(Packaging::Enveloped), "enveloped");
    EXPECT_EQ(toToken(Packaging::Enveloping), "enveloping");
    EXPECT_EQ(toToken(Packaging::Detached), "detached");
}

TEST(TokenMap, PackagingRoundTripsEveryValueIncludingEnveloping)
{
    for (const auto value : {Packaging::Enveloped, Packaging::Enveloping, Packaging::Detached}) {
        const std::string_view token = toToken(value);
        ASSERT_FALSE(token.empty());
        const std::optional<Packaging> back = packagingFromToken(token);
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(*back, value);
    }
}

TEST(TokenMap, PackagingUnknownTokenIsNullopt)
{
    EXPECT_EQ(packagingFromToken("Enveloped"), std::nullopt); // wrong case
    EXPECT_EQ(packagingFromToken("wrapped"), std::nullopt);
    EXPECT_EQ(packagingFromToken(""), std::nullopt);
}

// ---- PinVerb ---------------------------------------------------------------

TEST(TokenMap, PinVerbTokensMatchTheCddlCredVerbGroup)
{
    // wire/librescrs-agent.cddl: cred-verb = "change" / "unblock" / "activate_pin"
    EXPECT_EQ(toToken(PinVerb::Change), "change");
    EXPECT_EQ(toToken(PinVerb::Unblock), "unblock");
    EXPECT_EQ(toToken(PinVerb::ActivatePin), "activate_pin");
}

TEST(TokenMap, PinVerbRoundTripsEveryValue)
{
    for (const auto value : {PinVerb::Change, PinVerb::Unblock, PinVerb::ActivatePin}) {
        const std::string_view token = toToken(value);
        ASSERT_FALSE(token.empty());
        const std::optional<PinVerb> back = pinVerbFromToken(token);
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(*back, value);
    }
}

TEST(TokenMap, PinVerbUnknownTokenIsNullopt)
{
    EXPECT_EQ(pinVerbFromToken("Change"), std::nullopt);      // wrong case
    EXPECT_EQ(pinVerbFromToken("activatePin"), std::nullopt); // camelCase, not the wire's snake_case
    EXPECT_EQ(pinVerbFromToken("reset"), std::nullopt);
    EXPECT_EQ(pinVerbFromToken(""), std::nullopt);
}
