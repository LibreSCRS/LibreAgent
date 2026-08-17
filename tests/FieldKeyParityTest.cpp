// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pass-through law: a card plugin's group/field keys must arrive on the
// agent's identity read snapshot EXACTLY as the plugin emitted them -- no
// normalization, no case-folding, no re-keying, anywhere between the plugin
// ABI boundary and the flow's Result. Card-data integrity depends on this:
// the key is how every downstream consumer (GUI widget lookup, wire-encode
// map key, client-side FieldGroup/Field) locates a field, so a silent
// mutation would corrupt attribution without ever corrupting a VALUE.
//
// Strategy: driving the real eu-vrc / rs-health / pkcs15 plugins here is not
// practical -- their doReadCard() performs live APDU exchange over an
// unwrapped CardSession (see e.g. eu_vrc_card_plugin.cpp's
// LibreSCRS::SmartCard::detail::unwrap(session) + EuVrcCard::probe/readCard),
// and this codebase has no virtual/simulated card responder for these three
// families (LibreMiddleware's own test/mock_card_plugin/ deliberately never
// touches its session at all, which is precisely why it CAN run headless --
// it carries no protocol to simulate). What this test drives instead is the
// REAL production seam every plugin's output actually passes through:
// LmCardReader::read() (src/operations/LmSeams.cpp), which calls the REAL
// LibreSCRS::Plugin::CardPlugin::readCard() NVI entry point (the same public
// entry point the real plugins are invoked through) against a minimal local
// CardPlugin implementation that returns canned CardFieldGroup/CardField
// data mirroring each family's real group/field keys byte-for-byte. The
// plugin ABI, the NVI wrapper, and LmSeams.cpp's mapGroup/mapFields
// conversion are all exercised for real; only the APDU I/O inside a
// production plugin's doReadCard is out of reach without hardware, and its
// output shape is a plain, inert value type (CardFieldGroup/CardField) with
// nothing left to fake at this seam.
//
// Each family's keys below were re-read from the plugin source (NOT trusted
// from any prior note) immediately before writing this file; every group key
// and a representative field key per group carries its own source citation.
// No discrepancy was found against the previously pinned expectation table.
//
//   eu-vrc (lib/eu-vrc-plugin/src/eu_vrc_card_plugin.cpp):
//     registration:74, vehicle:94, holder:133, owner:145, user:155, national:176
//   rs-health (lib/rs-health-plugin/src/health_card_plugin.cpp):
//     personal:70, insurance:87, address:109, carrier:122, taxpayer:140
//   pkcs15 (lib/pkcs15-plugin/src/pkcs15_card_plugin.cpp):
//     token:388 (also :434, readTokenInfo), certificates:398

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardData.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardMap.h>

#include <gtest/gtest.h>
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

// -- A minimal CardPlugin whose doReadCard() streams + returns EXACTLY the
// scripted CardFieldGroup list, unconditionally -- it never touches @p
// session (mirrors LibreMiddleware's own test/mock_card_plugin/ in that one
// respect), so it is safe to drive over a detached test session. Its
// activationProfile() is the CardPlugin base default (plain, no secure
// messaging), so the real CardPlugin::readCard() NVI wrapper dispatches
// straight to doReadCard() below with no channel-activation step.
class ScriptedFamilyPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    ScriptedFamilyPlugin(std::string pluginId, std::string cardType,
                         std::vector<LibreSCRS::Plugin::CardFieldGroup> groups)
        : m_cardType(std::move(cardType)), m_groups(std::move(groups))
    {
        setIdentity(std::move(pluginId), "Scripted Family Plugin", /*priority=*/1);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::IdentityData;
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback onGroup) const override
    {
        LibreSCRS::Plugin::CardData data;
        data.cardType = m_cardType;
        for (const auto& g : m_groups) {
            if (onGroup) {
                onGroup(data.cardType, g);
            }
            data.groups.push_back(g);
        }
        return LibreSCRS::Plugin::ReadResult::ok(std::move(data));
    }

private:
    std::string m_cardType;
    std::vector<LibreSCRS::Plugin::CardFieldGroup> m_groups;
};

class RecordingGroupSink final : public GroupSink
{
public:
    void groupReady(const GroupSnapshot& group) noexcept override
    {
        groups.push_back(group);
    }
    std::vector<GroupSnapshot> groups;
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

// A no-op prompter: every scripted plugin below reports a plain
// activationProfile (the CardPlugin base default), so IdentityReadFlow never
// invokes the credential provider -- these methods exist only to satisfy the
// PrompterClientBase interface.
class NoOpPrompter final : public PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return PromptResult{};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{};
    }
};

// Drives IdentityReadFlow with the REAL LmCardReader seam (LmSeams.cpp)
// against a scripted CandidateList of ScriptedFamilyPlugin instances --
// everything downstream of the plugin ABI boundary is production code.
struct Harness
{
    LmCardReader reader;
    NoOpPrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    RecordingGroupSink groupSink;
    // This suite never renegotiates a CAN prompt into an MRZ read (its
    // scripted plugins prompt for nothing), so the no-op seam keeps the flow's
    // reference well-formed without pulling in a plugin registry.
    NullCredentialDepositor depositor;
    LibreSCRS::CancelSource source;
    CandidateList candidates; // set before make()
    std::unique_ptr<CardSessionHolder> holder;

    IdentityReadFlow make()
    {
        auto factory = [](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
        };
        auto resolver = [this](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) {
            return candidates;
        };
        holder = std::make_unique<CardSessionHolder>("ScriptedReader", std::move(factory), std::move(resolver),
                                                     std::make_shared<LibreSCRS::SmartCard::CardMap>());
        return IdentityReadFlow{IdentityReadFlowDeps{
            .holder = *holder,
            .reader = reader,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .groupSink = groupSink,
            .cardKey = "card-family",
            .requester = "test",
            .artifact = "identity",
            .token = source.token(),
            .depositor = depositor,
        }};
    }
};

using LibreSCRS::Plugin::CardFieldGroup;

CardFieldGroup makeGroup(std::string groupKey, std::string groupLabel, std::string fieldKey, std::string fieldLabel,
                         std::string value)
{
    CardFieldGroup g;
    g.groupKey = std::move(groupKey);
    g.groupLabel = std::move(groupLabel);
    g.addText(fieldKey, fieldLabel, value);
    return g;
}

// -- eu-vrc: lib/eu-vrc-plugin/src/eu_vrc_card_plugin.cpp -------------------
// groupKey citations: registration:74, vehicle:94, holder:133, owner:145,
// user:155, national:176. Field key citations: registration_number:77,
// vehicle_make:97, holder_name:136, owner2_name:148, user_name:158,
// owners_personal_no:168 (the "national" group's known-tag table).
std::vector<CardFieldGroup> euVrcGroups()
{
    return {
        makeGroup("registration", "Registration", "registration_number", "A: Registration Number", "SN-0001"),
        makeGroup("vehicle", "Vehicle", "vehicle_make", "D.1: Make", "Yugo"),
        makeGroup("holder", "Holder", "holder_name", "C.1.1: Name", "Ana Anic"),
        makeGroup("owner", "Owner", "owner2_name", "C.2: Owner Name", "Petar Petrovic"),
        makeGroup("user", "User", "user_name", "C.3: Name", "Marko Markovic"),
        makeGroup("national", "National Extensions", "owners_personal_no", "Owner Personal Number", "0101990710006"),
    };
}

// -- rs-health: lib/rs-health-plugin/src/health_card_plugin.cpp ------------
// groupKey citations: personal:70, insurance:87, address:109, carrier:122,
// taxpayer:140. Field key citations: given_name:72, insurer_name:89,
// street:111, carrier_given_name:130, taxpayer_name:142.
std::vector<CardFieldGroup> rsHealthGroups()
{
    return {
        makeGroup("personal", "Personal Data", "given_name", "Given Name", "Ana"),
        makeGroup("insurance", "Insurance", "insurer_name", "Insurer", "RZZO"),
        makeGroup("address", "Address", "street", "Street", "Kneza Milosa"),
        makeGroup("carrier", "Carrier", "carrier_given_name", "Given Name", "Marko"),
        makeGroup("taxpayer", "Taxpayer", "taxpayer_name", "Name", "Petar"),
    };
}

// -- pkcs15/PIV: lib/pkcs15-plugin/src/pkcs15_card_plugin.cpp --------------
// groupKey citations: token:388 (also :434 in readTokenInfo), certificates:398.
// Field key citations: label:390, serial_number:391, manufacturer:392,
// "cert_" + cert.label:401 -- the certificate field key is DYNAMIC
// (concatenated at runtime from the card's own certificate label), so it
// carries whatever characters that label contains verbatim; scripted here
// with an embedded space to prove the concatenation itself is not sanitized.
std::vector<CardFieldGroup> pkcs15Groups()
{
    CardFieldGroup token;
    token.groupKey = "token";
    token.groupLabel = "Token Info";
    token.addText("label", "Label", "Test Token");
    token.addText("serial_number", "Serial Number", "0123456789");
    token.addText("manufacturer", "Manufacturer", "LibreSCRS");

    CardFieldGroup certs;
    certs.groupKey = "certificates";
    certs.groupLabel = "Certificates";
    certs.addText("cert_Qualified Certificate", "Qualified Certificate", "Qualified Certificate");

    return {std::move(token), std::move(certs)};
}

} // namespace

// Asserts every scripted group/field key survives IdentityReadFlow verbatim,
// on BOTH observable surfaces: the streamed GroupSink calls (fired ahead of
// the result, see IdentityReadFlow.h's groupSink doc comment) and the final
// Result's snapshot -- proving the two conversions of the same shape
// (LmSeams.cpp's mapGroup, shared by both call sites) never drift apart.
void assertGroupsArriveVerbatim(const std::vector<CardFieldGroup>& scripted, const CardReadSnapshot& snapshot,
                                const std::vector<GroupSnapshot>& streamed)
{
    ASSERT_EQ(snapshot.groups.size(), scripted.size());
    ASSERT_EQ(streamed.size(), scripted.size());
    for (std::size_t i = 0; i < scripted.size(); ++i) {
        EXPECT_EQ(snapshot.groups[i].groupKey, scripted[i].groupKey) << "group #" << i << " (Result)";
        EXPECT_EQ(streamed[i].groupKey, scripted[i].groupKey) << "group #" << i << " (streamed)";
        ASSERT_EQ(snapshot.groups[i].fields.size(), scripted[i].fields.size());
        ASSERT_EQ(streamed[i].fields.size(), scripted[i].fields.size());
        for (std::size_t j = 0; j < scripted[i].fields.size(); ++j) {
            EXPECT_EQ(snapshot.groups[i].fields[j].fieldKey, scripted[i].fields[j].key)
                << "group #" << i << " field #" << j << " (Result)";
            EXPECT_EQ(streamed[i].fields[j].fieldKey, scripted[i].fields[j].key)
                << "group #" << i << " field #" << j << " (streamed)";
        }
    }
}

TEST(FieldKeyParity, EuVrcGroupAndFieldKeysArriveVerbatim)
{
    Harness h;
    const auto scripted = euVrcGroups();
    h.candidates = {std::make_shared<ScriptedFamilyPlugin>("eu-vrc", "eu-vrc", scripted)};

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    ASSERT_TRUE(result.snapshot.has_value());
    assertGroupsArriveVerbatim(scripted, *result.snapshot, h.groupSink.groups);
}

TEST(FieldKeyParity, RsHealthGroupAndFieldKeysArriveVerbatim)
{
    Harness h;
    const auto scripted = rsHealthGroups();
    h.candidates = {std::make_shared<ScriptedFamilyPlugin>("rs-health", "rs-health", scripted)};

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    ASSERT_TRUE(result.snapshot.has_value());
    assertGroupsArriveVerbatim(scripted, *result.snapshot, h.groupSink.groups);
}

TEST(FieldKeyParity, Pkcs15GroupAndFieldKeysArriveVerbatim)
{
    Harness h;
    const auto scripted = pkcs15Groups();
    h.candidates = {std::make_shared<ScriptedFamilyPlugin>("pkcs15", "pkcs15", scripted)};

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    ASSERT_TRUE(result.snapshot.has_value());
    assertGroupsArriveVerbatim(scripted, *result.snapshot, h.groupSink.groups);
}

// -- value display-safety at the same seam ---------------------------------
// Keys pass through verbatim (above); VALUES of Text/Date fields feed GUI
// labels directly, so the seam is the display boundary: bytes that are not
// renderable text must arrive hex-formatted ("AA:BB:.."), and well-formed
// UTF-8 — multi-byte included — must arrive verbatim. The LM layer keeps the
// raw bytes untouched (card-data integrity); pre-agent LibreCelik applied
// exactly this printable-or-hex rendering client-side
// (tokensection.cpp formatSerialNumber), and the raw bytes no longer cross
// the wire, so the seam is the only place left that can do it. Live trigger:
// a fielded pkcs15 token whose EF(TokenInfo) serialNumber is BCD
// 23 53 14 29 33 20 49 24 (0x14 = C0 control) — rendered as mojibake
// "#S␔)3 I$" before this law existed.
TEST(FieldKeyParity, NonDisplayableTextValuesArriveHexFormatted)
{
    Harness h;
    CardFieldGroup token;
    token.groupKey = "token";
    token.groupLabel = "Token Info";
    // BCD serial with an embedded C0 control byte (a live card's exact bytes).
    token.addText("serial_number", "Serial Number", std::string_view{"\x23\x53\x14\x29\x33\x20\x49\x24", 8});
    // Multi-byte UTF-8 ("š" = C5 A1) is real text and must never be hexed.
    token.addText("label", "Label", "Nemanja Hir\xC5\xA1l 200111996");
    // Structurally invalid UTF-8 (C3 lead byte with a non-continuation) is not text.
    token.addText("manufacturer", "Manufacturer", std::string_view{"\xC3\x28", 2});
    h.candidates = {std::make_shared<ScriptedFamilyPlugin>("pkcs15", "pkcs15", std::vector<CardFieldGroup>{token})};

    auto result = h.make().run();
    ASSERT_EQ(result.outcome, IdentityReadFlow::Outcome::Ok);
    ASSERT_TRUE(result.snapshot.has_value());
    ASSERT_EQ(result.snapshot->groups.size(), 1u);
    const auto& fields = result.snapshot->groups[0].fields;
    ASSERT_EQ(fields.size(), 3u);
    EXPECT_EQ(fields[0].textValue, "23:53:14:29:33:20:49:24");
    EXPECT_EQ(fields[1].textValue, "Nemanja Hir\xC5\xA1l 200111996");
    EXPECT_EQ(fields[2].textValue, "C3:28");
    // The streamed surface shares mapFields with the Result (proven above);
    // spot-check it applies the same rendering.
    ASSERT_EQ(h.groupSink.groups.size(), 1u);
    ASSERT_EQ(h.groupSink.groups[0].fields.size(), 3u);
    EXPECT_EQ(h.groupSink.groups[0].fields[0].textValue, "23:53:14:29:33:20:49:24");
}
