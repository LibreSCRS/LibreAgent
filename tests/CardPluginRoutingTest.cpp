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
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> cands{
        mk("emrtd", Cap::IdentityData | Cap::EmrtdCrypto),
        mk("pkcs15", Cap::PKI | Cap::PinManagement | Cap::IdentityData),
    };
    auto ids = identityCandidates(cands);
    ASSERT_EQ(ids.size(), 2u);
    EXPECT_EQ(ids.front()->pluginId(), "emrtd");
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
