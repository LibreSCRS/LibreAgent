// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Cross-implementation parity oracle: proves the agent-side entry points every
// platform daemon calls through for Manager1.LayoutVisualSignature /
// GetAppearanceFont (LibreSCRS::Agent::Operations::layoutVisualSignature /
// appearanceFontBytes, LmSeams.h) agree EXACTLY with a direct call into LM's
// own LibreSCRS::Signing::layoutVisualSignature / embeddedAppearanceFontData
// -- both directly, and after a full wire encode/decode round trip through
// the SAME Messages.h / ClientCodec.h codec a real client uses. This is the
// "layout via client == direct LM call" cross-check; it is core-gated (links LibreAgent::Core, which
// links LM) rather than living in the client/qt test tree, which never links
// LM at all -- the client integration/parity suites script FIXED values into
// their LM-free fakes instead of a real LM call.
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/util/Sha256Hex.h>
#include <LibreSCRS/Agent/wire/ClientCodec.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Signing/VisualSignatureLayout.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

namespace Op = LibreSCRS::Agent::Operations;
namespace Wire = LibreSCRS::Agent::Wire;
namespace Sign = LibreSCRS::Signing;

// Encode an agent-computed VisualLayoutResult into a wire reply, then decode
// it back through the SAME client-role codec a real AgentClient uses
// (ClientCodec.h's parseReply) -- the round trip a real client observes.
Wire::LayoutReply roundTripThroughWire(const Op::VisualLayoutResult& agentResult)
{
    Wire::LayoutReply wireIn;
    wireIn.fontSize = agentResult.fontSize;
    wireIn.lineHeight = agentResult.lineHeight;
    wireIn.lines = agentResult.lines;
    wireIn.clipped = agentResult.clipped;

    const std::vector<std::uint8_t> bytes = Wire::makeReply(1, wireIn).encode();
    const auto decoded = Wire::parseReply(bytes, {});
    EXPECT_TRUE(decoded.has_value());
    const auto* layout = std::get_if<Wire::LayoutReply>(&decoded->reply);
    EXPECT_NE(layout, nullptr);
    return layout != nullptr ? *layout : Wire::LayoutReply{};
}

// One fixture: text + box, asserting the agent seam / direct LM call / full
// wire round trip all agree exactly.
void expectMatchesLm(std::string_view text, double x, double y, double width, double height)
{
    const Sign::Rect lmRect{static_cast<int>(x), static_cast<int>(y), static_cast<int>(width),
                            static_cast<int>(height)};
    const Sign::VisualSignatureLayout lmDirect = Sign::layoutVisualSignature(text, lmRect);

    const Op::VisualLayoutResult agentResult = Op::layoutVisualSignature(text, Op::LayoutBox{x, y, width, height});
    EXPECT_FLOAT_EQ(agentResult.fontSize, lmDirect.fontSize);
    EXPECT_FLOAT_EQ(agentResult.lineHeight, lmDirect.lineHeight);
    ASSERT_EQ(agentResult.lines.size(), lmDirect.lines.size());
    for (std::size_t i = 0; i < agentResult.lines.size(); ++i) {
        EXPECT_EQ(agentResult.lines[i], lmDirect.lines[i]);
    }
    EXPECT_EQ(agentResult.clipped, lmDirect.clipped);

    // Now prove the SAME values arrive after a full wire round trip -- the
    // shape a real client actually observes.
    const Wire::LayoutReply wireOut = roundTripThroughWire(agentResult);
    EXPECT_DOUBLE_EQ(wireOut.fontSize, static_cast<double>(lmDirect.fontSize));
    EXPECT_DOUBLE_EQ(wireOut.lineHeight, static_cast<double>(lmDirect.lineHeight));
    ASSERT_EQ(wireOut.lines.size(), lmDirect.lines.size());
    for (std::size_t i = 0; i < wireOut.lines.size(); ++i) {
        EXPECT_EQ(wireOut.lines[i], lmDirect.lines[i]);
    }
    EXPECT_EQ(wireOut.clipped, lmDirect.clipped);
}

} // namespace

// 5 fixture texts (incl. Serbian Cyrillic UTF-8), mirroring LibreMiddleware's
// own visual_signature_layout_test.cpp fixtures rather than inventing new
// ones (kDefaultBox = {0,0,200,50} there).
TEST(VisualLayoutService, MatchesLmDirectlyForEnglishTwoLineText)
{
    expectMatchesLm("Signed by\nJohn Doe", 0.0, 0.0, 200.0, 50.0);
}

TEST(VisualLayoutService, MatchesLmDirectlyForSerbianCyrillicText)
{
    // UTF-8 Serbian Cyrillic -- the wire's `text: tstr` carries this verbatim
    // (CDDL tstr is UTF-8); both the LM call and the wire round trip must
    // preserve it byte-exactly.
    expectMatchesLm("Потписао\nНемања", 0.0, 0.0, 200.0, 50.0);
}

TEST(VisualLayoutService, MatchesLmDirectlyForMixedLatinCyrillicText)
{
    expectMatchesLm("Latin Кириллица mixed", 10.5, 20.25, 150.0, 60.0);
}

TEST(VisualLayoutService, MatchesLmDirectlyForRealisticMultilineTemplate)
{
    expectMatchesLm("Digitally signed by NEMANJA HIRŠL\nDate: 2026-05-08 14:23:45", 0.0, 0.0, 220.0, 70.0);
}

// The tiny-box floor case: a box far too small to fit even the floor font
// size -- clipped MUST be true, and (the field's whole reason to ride the
// wire) that must survive the full encode/decode round trip identically to
// the direct LM call.
TEST(VisualLayoutService, TinyBoxFloorCaseArrivesClippedThroughTheFullWireRoundTrip)
{
    const Sign::VisualSignatureLayout lmDirect = Sign::layoutVisualSignature("Hello World", Sign::Rect{0, 0, 4, 50});
    ASSERT_TRUE(lmDirect.clipped) << "the LM fixture itself must be a genuinely clipped case";

    const Op::VisualLayoutResult agentResult =
        Op::layoutVisualSignature("Hello World", Op::LayoutBox{0.0, 0.0, 4.0, 50.0});
    EXPECT_TRUE(agentResult.clipped);
    EXPECT_FLOAT_EQ(agentResult.fontSize, lmDirect.fontSize);

    const Wire::LayoutReply wireOut = roundTripThroughWire(agentResult);
    EXPECT_TRUE(wireOut.clipped) << "clipped==true must arrive client-side -- the field's whole reason to ride "
                                    "the wire (see the CDDL `layout` arm's own comment)";
}

// Geometry gate: SignatureParams::isValidLayoutRect is the entry check every
// daemon runs BEFORE calling Operations::layoutVisualSignature (see LmSeams.h's
// declaration comment) -- SignatureParamsTest.cpp already covers the
// predicate itself in full; this just pins that a validated box really does
// reach LM unchanged (no silent narrowing surprises for the common case).
TEST(VisualLayoutService, ValidatedBoxNarrowsToLmRectExactly)
{
    const Op::VisualLayoutResult agentResult =
        Op::layoutVisualSignature("Signed by\nJohn Doe", Op::LayoutBox{0.0, 0.0, 200.0, 50.0});
    const Sign::VisualSignatureLayout lmDirect =
        Sign::layoutVisualSignature("Signed by\nJohn Doe", Sign::Rect{0, 0, 200, 50});
    EXPECT_FLOAT_EQ(agentResult.fontSize, lmDirect.fontSize);
    EXPECT_EQ(agentResult.clipped, lmDirect.clipped);
}

// Font content-hash: Operations::appearanceFontBytes() (the byte-vector copy
// every daemon seals into its reply fd) must be byte-identical to LM's own
// embeddedAppearanceFontData() span -- proven via a SHA-256 content hash
// (the same "fd content-hash == LM span hash" the brief calls for; the
// memfd-sealing mechanics themselves are daemon-specific and covered by each
// platform repo's own integration tests, not here).
TEST(VisualLayoutService, AppearanceFontContentHashMatchesLmSpanExactly)
{
    const std::span<const std::byte> lmSpan = Sign::embeddedAppearanceFontData();
    ASSERT_FALSE(lmSpan.empty());
    std::vector<std::uint8_t> lmBytes(lmSpan.size());
    for (std::size_t i = 0; i < lmSpan.size(); ++i) {
        lmBytes[i] = static_cast<std::uint8_t>(lmSpan[i]);
    }

    const std::vector<std::uint8_t> agentBytes = Op::appearanceFontBytes();
    ASSERT_EQ(agentBytes.size(), lmBytes.size());
    EXPECT_EQ(agentBytes, lmBytes);
    EXPECT_EQ(LibreSCRS::Agent::sha256Hex(agentBytes), LibreSCRS::Agent::sha256Hex(lmBytes))
        << "the bytes every daemon seals into its GetAppearanceFont reply fd must content-hash identically to "
           "LM's own embedded span";

    // Deterministic across repeated calls (LM's own contract for the span).
    const std::vector<std::uint8_t> agentBytesAgain = Op::appearanceFontBytes();
    EXPECT_EQ(agentBytes, agentBytesAgain);
}
