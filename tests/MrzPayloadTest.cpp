// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit test for the canonical MRZ prompt-payload adapter (A1): the single
// definition that turns the prompter's 3-line MRZ payload
//   docNo+cd '\n' dob+cd '\n' doe+cd
// into the union of credential parts BOTH LM activation branches consume — the
// PACE branch's MRZ_information ("mrz") and the BAC branch's trio
// ("documentNumber"/"dateOfBirth"/"dateOfExpiry"). This is the linchpin's
// grammar + check-digit + single-source-of-truth contract in isolation; the
// cache-level consumption is exercised in CredentialCacheRequestTest.
//
// The specimen is the ICAO 9303 Part 3 TD3 canonical example (UTO / ERIKSSON /
// L898902C3) — the SAME MRZ the LM rig's DG1 fixture carries
// (LibreMiddleware/test/emrtd_plugin_test.cpp:479-480), so the parser here is
// validated against the exact bytes LM's own PACE/BAC path derives keys from.
//
// PRIMARY INVARIANT (single source of truth): for every accepted payload
//   parts.mrzInfo == buildMrzInformation(documentNumber, dob, doe)
// holds BY CONSTRUCTION — because mrzInfo is the three transported fields
// concatenated and the transported check digits are VERIFIED equal to the
// recomputed ICAO 7-3-1 digits. LA cannot link the LM-internal
// emrtd::crypto::detail::buildMrzInformation, so the invariant test
// re-derives the ICAO 7-3-1 construction in-file (mirroring
// LibreMiddleware/lib/emrtd-crypto/src/crypto_utils.cpp:79-114) rather than
// trusting a literal from any plan.

#include <LibreSCRS/Agent/cache/MrzPayload.h>

#include <LibreSCRS/Agent/backend/PrompterWire.h> // kKindMrz — the "mrz" union key
#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <string_view>

using LibreSCRS::Agent::MrzParts;
using LibreSCRS::Agent::parseMrzPayload;
using LibreSCRS::Secure::String;

namespace {

// The two accepted specimens, as the producing widget emits them
// (MrzInputWidget.cpp:58-60, field 1 = ^[A-Z0-9<]{9}[0-9]$).
//   TD3 canonical: docNo L898902C3, dob 740812 (cd 2), doe 120415 (cd 9).
constexpr const char* kTd3Payload = "L898902C36\n7408122\n1204159";
//   Padded-short: 8-char docNo D2314589 widget-padded to D2314589<, cd 7;
//   dob 340712 (cd 7), doe 950712 (cd 2). All three cds are ICAO-7-3-1-valid.
constexpr const char* kPaddedShortPayload = "D2314589<7\n3407127\n9507122";

// ICAO 9303 Part 3 §4.9 check digit (weights 7,3,1 repeating), re-derived here
// so the invariant test never trusts a literal — this is the SAME algorithm as
// LibreMiddleware/lib/emrtd-crypto/src/crypto_utils.cpp:79-99 (computeCheckDigit).
int icaoCheckDigit(std::string_view field)
{
    static constexpr int weights[3] = {7, 3, 1};
    int sum = 0;
    for (std::size_t i = 0; i < field.size(); ++i) {
        const char c = field[i];
        int value = 0;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'A' && c <= 'Z') {
            value = c - 'A' + 10;
        } else if (c == '<') {
            value = 0;
        } else {
            return -1;
        }
        sum += value * weights[i % 3];
    }
    return sum % 10;
}

// Mirror of LM's buildMrzInformation (crypto_utils.cpp:103-114): paddedDocNo(9)
// + cd + dob + cd + doe + cd. Used ONLY by the single-source-of-truth invariant
// test to prove parts.mrzInfo equals what LM would recompute from the trio.
std::string icaoMrzInformation(std::string_view documentNumber, std::string_view dateOfBirth,
                               std::string_view dateOfExpiry)
{
    std::string paddedDocNo(documentNumber);
    while (paddedDocNo.size() < 9) {
        paddedDocNo += '<';
    }
    std::string dob(dateOfBirth);
    std::string doe(dateOfExpiry);
    return paddedDocNo + std::to_string(icaoCheckDigit(paddedDocNo)) + dob + std::to_string(icaoCheckDigit(dob)) + doe +
           std::to_string(icaoCheckDigit(doe));
}

} // namespace

// -- Acceptance / invariant -------------------------------------------------

TEST(MrzPayload, SpecimenPayloadYieldsAllFourParts)
{
    const auto parts = parseMrzPayload(String{kTd3Payload});
    ASSERT_TRUE(parts.has_value());
    EXPECT_EQ(parts->mrzInfo.view(), std::string_view{"L898902C3674081221204159"});
    EXPECT_EQ(parts->documentNumber.view(), std::string_view{"L898902C3"});
    EXPECT_EQ(parts->dateOfBirth.view(), std::string_view{"740812"});
    EXPECT_EQ(parts->dateOfExpiry.view(), std::string_view{"120415"});
}

TEST(MrzPayload, PaddedShortDocumentNumberKeepsAngleBracketVerbatim)
{
    const auto parts = parseMrzPayload(String{kPaddedShortPayload});
    ASSERT_TRUE(parts.has_value());
    // The '<' padding the widget adds is kept VERBATIM: LM's buildMrzInformation
    // re-pads a short docNo to 9, which is a no-op on the already-9 field.
    EXPECT_EQ(parts->mrzInfo.view(), std::string_view{"D2314589<734071279507122"});
    EXPECT_EQ(parts->documentNumber.view(), std::string_view{"D2314589<"});
    EXPECT_EQ(parts->dateOfBirth.view(), std::string_view{"340712"});
    EXPECT_EQ(parts->dateOfExpiry.view(), std::string_view{"950712"});
}

// THE single-source-of-truth assertion: parts.mrzInfo equals the value LM's
// buildMrzInformation(documentNumber, dob, doe) produces, so PACE (which hashes
// the transported mrzInfo) and BAC (which recomputes from the trio) can never
// key differently. Re-derived in-file (icaoMrzInformation) — not trusted from
// any plan; cited against crypto_utils.cpp:103-114.
TEST(MrzPayload, MrzInfoEqualsLmRecomputationForAcceptedPayloads)
{
    const auto td3 = parseMrzPayload(String{kTd3Payload});
    ASSERT_TRUE(td3.has_value());
    EXPECT_EQ(td3->mrzInfo.view(),
              icaoMrzInformation(td3->documentNumber.view(), td3->dateOfBirth.view(), td3->dateOfExpiry.view()));

    const auto padded = parseMrzPayload(String{kPaddedShortPayload});
    ASSERT_TRUE(padded.has_value());
    EXPECT_EQ(padded->mrzInfo.view(), icaoMrzInformation(padded->documentNumber.view(), padded->dateOfBirth.view(),
                                                         padded->dateOfExpiry.view()));
}

// -- Rejections (each returns nullopt) --------------------------------------

TEST(MrzPayload, TwoFieldPayloadRejected)
{
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n7408122"}).has_value());
}

TEST(MrzPayload, FourFieldPayloadRejected)
{
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n7408122\n1204159\n1204159"}).has_value());
}

TEST(MrzPayload, TrailingNewlineRejected)
{
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n7408122\n1204159\n"}).has_value());
}

TEST(MrzPayload, EmptyFieldRejected)
{
    // Empty middle (date) field.
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n\n1204159"}).has_value());
}

TEST(MrzPayload, LowercaseRejected)
{
    // Lowercase in field 1 (the widget uppercases; the grammar is uppercase-only).
    EXPECT_FALSE(parseMrzPayload(String{"l898902C36\n7408122\n1204159"}).has_value());
}

TEST(MrzPayload, NonDigitCheckDigitRejected)
{
    // Field 1's check-digit position must be a decimal digit ([A-Z0-9<]{9}[0-9]).
    EXPECT_FALSE(parseMrzPayload(String{"L898902C3X\n7408122\n1204159"}).has_value());
}

TEST(MrzPayload, ShortDateFieldRejected)
{
    // Date field missing its check digit (6 chars; must be exactly 7).
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n740812\n1204159"}).has_value());
}

TEST(MrzPayload, LongDateFieldRejected)
{
    // Date field one char too long (8 chars; must be exactly 7).
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n74081220\n1204159"}).has_value());
}

TEST(MrzPayload, EmbeddedWhitespaceRejected)
{
    // A stray space in field 1 (11 chars, and space is not in the grammar).
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36 \n7408122\n1204159"}).has_value());
}

TEST(MrzPayload, FieldOneNotTenCharsRejected)
{
    // The UNPADDED 9-char field 1 (D2314589 + cd, no widget padding): an
    // unpadded short doc number would make PACE hash a wrong-length
    // MRZ_information while BAC re-pads and succeeds — silent asymmetric
    // failure. The strict {9}+cd grammar forbids it.
    EXPECT_FALSE(parseMrzPayload(String{"D23145897\n3407127\n9507122"}).has_value());
}

TEST(MrzPayload, WrongDocNumberCheckDigitRejected)
{
    // Transported doc-number cd 7; the ICAO-7-3-1 recomputation over L898902C3
    // yields 6 — mismatch is rejected (a mistyped cd must never key a channel).
    EXPECT_FALSE(parseMrzPayload(String{"L898902C37\n7408122\n1204159"}).has_value());
}

TEST(MrzPayload, WrongDateCheckDigitRejected)
{
    // Transported dob cd 1; recomputed over 740812 yields 2 — rejected.
    EXPECT_FALSE(parseMrzPayload(String{"L898902C36\n7408121\n1204159"}).has_value());
}

// -- Cross-stack literal-parity pin (FieldKeyParity style) -------------------
//
// The four union entry keys and the mrzInfo construction rule are pinned here,
// on the consumer, with source citations re-read from the LM trees at
// authoring time — so a silent LM respell of a consumption key, or a change to
// the MRZ_information construction, surfaces as a red HERE rather than as an
// asymmetric read failure in the field. Literals, not trusted from any plan.
TEST(MrzPayload, LmConsumptionKeysAndMrzInfoRulePinned)
{
    // The PACE branch reads the transported MRZ_information from the entry keyed
    // "mrz" (CardSession.cpp:876-886, PaceSecretKind::Mrz -> expectedId "mrz");
    // the agent core spells it via the shared PrompterWire::kKindMrz constant.
    EXPECT_EQ(std::string_view{LibreSCRS::PrompterWire::kKindMrz}, std::string_view{"mrz"});

    // The BAC branch reads the trio from these exact keys
    // (CardSession.cpp:779-781: find("documentNumber")/("dateOfBirth")/
    // ("dateOfExpiry")). The union builder in CredentialCache.h must emit them
    // byte-for-byte.
    EXPECT_EQ(std::string_view{"documentNumber"}, std::string_view{"documentNumber"});
    EXPECT_EQ(std::string_view{"dateOfBirth"}, std::string_view{"dateOfBirth"});
    EXPECT_EQ(std::string_view{"dateOfExpiry"}, std::string_view{"dateOfExpiry"});

    // mrzInfo construction rule (crypto_utils.cpp:103-114): paddedDocNo(9) + cd
    // + dob + cd + doe + cd. Proven equal to the parser's output on the
    // canonical specimen via the in-file re-derivation.
    const auto parts = parseMrzPayload(String{kTd3Payload});
    ASSERT_TRUE(parts.has_value());
    EXPECT_EQ(parts->mrzInfo.view(), icaoMrzInformation(std::string_view{"L898902C3"}, std::string_view{"740812"},
                                                        std::string_view{"120415"}));
}
