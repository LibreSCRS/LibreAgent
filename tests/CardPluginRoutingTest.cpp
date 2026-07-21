// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace LibreSCRS::Agent::Operations;
using Cap = LibreSCRS::Plugin::CardCapabilities;

namespace {
// Minimal CardPlugin stub that only declares capabilities + an id.
class StubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    StubPlugin(std::string id, Cap caps) : m_caps(caps)
    {
        setIdentity(std::move(id), "stub", 0);
    }
    Cap capabilities() const override
    {
        return m_caps;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    Cap m_caps;
};
std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> mk(std::string id, Cap c)
{
    return std::make_shared<StubPlugin>(std::move(id), c);
}
} // namespace

TEST(CardPluginRouting, FiltersByCapabilityInOrder)
{
    // Capability sets mirror the real plugin manifests: pkcs15 is pure
    // PKI+PinManagement (its readCard has no identity path), identity
    // comes from the dedicated identity plugins (rs-eid, emrtd).
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> cands{
        mk("rs-eid", Cap::IdentityData),
        mk("emrtd", Cap::IdentityData | Cap::EmrtdCrypto),
        mk("pkcs15", Cap::PKI | Cap::PinManagement),
    };
    auto ids = identityCandidates(cands);
    ASSERT_EQ(ids.size(), 2u);
    EXPECT_EQ(ids.front()->pluginId(), "rs-eid");
    EXPECT_EQ(ids.back()->pluginId(), "emrtd");
    auto pki = pkiCandidates(cands);
    ASSERT_EQ(pki.size(), 1u);
    EXPECT_EQ(pki.front()->pluginId(), "pkcs15");
    auto sign = signingCandidates(cands);
    ASSERT_EQ(sign.size(), 1u);
    EXPECT_EQ(sign.front()->pluginId(), "pkcs15");
}

TEST(CardPluginRouting, UnionCapabilities)
{
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> cands{
        mk("rs-eid", Cap::IdentityData), mk("opensc", Cap::PKI | Cap::PinManagement)};
    EXPECT_EQ(unionCapabilities(cands), static_cast<std::uint32_t>(Cap::IdentityData | Cap::PKI | Cap::PinManagement));
}

TEST(CardPluginRouting, PrioritizeCandidateMovesTheMatchToTheFrontStably)
{
    CandidateList cands{mk("a", Cap::PinManagement), mk("b", Cap::PinManagement), mk("c", Cap::PinManagement)};
    auto out = prioritizeCandidate(cands, "b");
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0]->pluginId(), "b") << "the listing plugin answers a mutation first";
    EXPECT_EQ(out[1]->pluginId(), "a") << "the rest keep their relative priority order";
    EXPECT_EQ(out[2]->pluginId(), "c");
}

TEST(CardPluginRouting, PrioritizeCandidateEmptyOrUnknownIdKeepsPriorityOrder)
{
    CandidateList cands{mk("a", Cap::PinManagement), mk("b", Cap::PinManagement)};
    auto keptEmpty = prioritizeCandidate(cands, "");
    ASSERT_EQ(keptEmpty.size(), 2u);
    EXPECT_EQ(keptEmpty[0]->pluginId(), "a");
    auto keptUnknown = prioritizeCandidate(cands, "not-present");
    ASSERT_EQ(keptUnknown.size(), 2u);
    EXPECT_EQ(keptUnknown[0]->pluginId(), "a");
}

TEST(CardPluginRouting, PrioritizeCandidateSkipsNullEntries)
{
    CandidateList cands{nullptr, mk("a", Cap::PinManagement), mk("b", Cap::PinManagement)};
    auto out = prioritizeCandidate(cands, "b");
    ASSERT_EQ(out.size(), 3u);
    ASSERT_NE(out[0], nullptr);
    EXPECT_EQ(out[0]->pluginId(), "b");
}
