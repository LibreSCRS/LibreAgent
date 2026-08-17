// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Deterministic, engine-free unit coverage for buildSigningRequest -- the pure
// SignParams -> LM SigningRequest assembly LmSigner::sign drives. No live card
// session, no signing engine, no plugin candidates: this exercises exactly the
// translation of a per-request tsaUrl / visual / displayName into LM's
// SigningRequest::Builder::tsaOverride / visualParams / documentName, which is
// otherwise only observable deep inside a real sign (requiring a working
// PKCS#11 module).
#include "../src/operations/LmSigningRequestBuilder.h"

#include <LibreSCRS/Signing/TsaProvider.h>

#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent::Operations;
namespace sign = LibreSCRS::Signing;

namespace {

SignParams baseParams()
{
    SignParams p;
    p.certId = "deadbeef";
    p.inputDocument = {0x01};
    p.format = "pades";
    p.level = "b-t";
    p.packaging = "enveloped";
    return p;
}

} // namespace

TEST(LmSigningRequestBuilder, NoTsaUrlInstallsNoOverride)
{
    const SignParams params = baseParams();
    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_T,
                                       sign::PackagingMode::Enveloped, {}, false);
    EXPECT_FALSE(request.hasTsaOverride());
    EXPECT_FALSE(static_cast<bool>(request.tsaOverride()));
}

TEST(LmSigningRequestBuilder, TsaUrlInstallsAPerRequestOverrideCarryingTheUrl)
{
    SignParams params = baseParams();
    params.tsaUrl = "https://tsa.example.com/ts";
    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_T,
                                       sign::PackagingMode::Enveloped, {}, false);
    ASSERT_TRUE(request.hasTsaOverride());
    sign::TsaContext ctx;
    const auto tsaRequest = request.tsaOverride()(ctx);
    EXPECT_EQ(tsaRequest.url, "https://tsa.example.com/ts");
}

TEST(LmSigningRequestBuilder, NoVisualLeavesVisualParamsEmpty)
{
    const SignParams params = baseParams();
    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_T,
                                       sign::PackagingMode::Enveloped, {}, false);
    EXPECT_FALSE(request.visualParams().has_value());
}

TEST(LmSigningRequestBuilder, VisualMapsFieldForFieldOntoLmVisualSignatureParams)
{
    SignParams params = baseParams();
    VisualParams visual;
    visual.page = 2;
    visual.x = 10.6F;
    visual.y = 20.4F;
    visual.width = 150.0F;
    visual.height = 60.0F;
    visual.text = "Signed by {cn}";
    params.visual = visual;

    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_T,
                                       sign::PackagingMode::Enveloped, {}, false);
    ASSERT_TRUE(request.visualParams().has_value());
    const auto vp = *request.visualParams();
    EXPECT_EQ(vp.pageIndex(), 2);
    EXPECT_EQ(vp.x(), 11); // 10.6 rounds to 11
    EXPECT_EQ(vp.y(), 20); // 20.4 rounds to 20
    EXPECT_EQ(vp.width(), 150);
    EXPECT_EQ(vp.height(), 60);
    EXPECT_EQ(vp.textTemplate(), "Signed by {cn}");
}

TEST(LmSigningRequestBuilder, VisualOnNonPadesThrowsInvalidArgument)
{
    SignParams params = baseParams();
    params.format = "cades";
    VisualParams visual;
    visual.width = 100.0F;
    visual.height = 50.0F;
    params.visual = visual;

    EXPECT_THROW(
        {
            auto req = buildSigningRequest(params, sign::SignatureFormat::Cades, sign::SignatureLevel::B_T,
                                           sign::PackagingMode::Detached, {}, false);
            (void)req;
        },
        std::invalid_argument);
}

TEST(LmSigningRequestBuilder, ReasonLocationDisplayNameAndAllowExpiredThreadThrough)
{
    SignParams params = baseParams();
    params.reason = "why";
    params.location = "Belgrade";
    params.displayName = "Doc.pdf";

    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_B,
                                       sign::PackagingMode::Enveloped, {0xAB, 0xCD}, /*allowExpiredCert=*/true);
    EXPECT_EQ(request.reason(), "why");
    EXPECT_EQ(request.location(), "Belgrade");
    EXPECT_TRUE(request.allowExpiredCert());
    EXPECT_EQ(request.format(), sign::SignatureFormat::Pades);
    EXPECT_EQ(request.level(), sign::SignatureLevel::B_B);
    EXPECT_EQ(request.packaging(), sign::PackagingMode::Enveloped);
    EXPECT_EQ(request.keyId(), (std::vector<std::uint8_t>{0xAB, 0xCD}));
    // The display name rides LM's documentName API -- NOT a name-hint abuse of
    // inputFile. inputFile stays EMPTY: this is the buffer-sign path, where
    // nothing is ever opened, so no code here has any business setting a path.
    EXPECT_EQ(request.documentName(), "Doc.pdf");
    EXPECT_TRUE(request.inputFile().empty());
}

TEST(LmSigningRequestBuilder, EmptyDisplayNameLeavesDocumentNameUnset)
{
    const SignParams params = baseParams(); // displayName defaults empty
    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_T,
                                       sign::PackagingMode::Enveloped, {}, false);
    EXPECT_TRUE(request.documentName().empty());
    EXPECT_TRUE(request.inputFile().empty());
}

TEST(LmSigningRequestBuilder, DisplayNameIsForwardedVerbatimWithoutASecondSanitisationLayer)
{
    // LM owns the name policy (it strips path components on the way to the
    // engine and treats degenerate results as unset), so the agent must NOT
    // pre-chew the value: what the caller supplied is what the request carries.
    SignParams params = baseParams();
    params.displayName = "../etc/Doc.pdf";

    auto request = buildSigningRequest(params, sign::SignatureFormat::Pades, sign::SignatureLevel::B_T,
                                       sign::PackagingMode::Enveloped, {}, false);
    EXPECT_EQ(request.documentName(), "../etc/Doc.pdf");
    EXPECT_TRUE(request.inputFile().empty());
}
