// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;

namespace {

using Cap = LibreSCRS::Plugin::CardCapabilities;

// Minimal CardPlugin stub that only declares capabilities + an id (mirrors the
// per-file stubs used elsewhere in the agent test suite).
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

// ATR-only resolver: PresenceModel publishes Card1.Capabilities from
// resolvePlugin, which opens no CardSession. No transient session-opening seam
// remains for the monitor thread to reach on insert.
class FakeResolver : public CapabilityResolver
{
public:
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> atr) const noexcept override
    {
        if (atr.empty()) {
            return nullptr;
        }
        return std::make_shared<StubPlugin>("stub", static_cast<Cap>(0x3u));
    }
};

// Locate the single card carrying @p id in the registry snapshot (nullptr if
// none). The opaque counter is per-process monotonic, so ids never repeat.
const CardState* findCard(const ObjectRegistry& reg, ObjectId id)
{
    for (const auto& c : reg.cards()) {
        if (c.id == id) {
            return &c;
        }
    }
    return nullptr;
}

} // namespace

TEST(PresenceModel, ReaderAddedCreatesReaderObject)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);

    model.onReaderAdded("Acme CL 0");

    ASSERT_EQ(reg.readers().size(), 1u);
    EXPECT_EQ(reg.readers()[0].name, "Acme CL 0");
    EXPECT_FALSE(reg.readers()[0].hasCard);
    EXPECT_EQ(model.readerIdFor("Acme CL 0"), ObjectId{1});
}

TEST(PresenceModel, CardInsertedCreatesCardObjectWithCapabilities)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("Acme CL 0");

    const std::vector<std::uint8_t> atr{0x3B, 0x01};
    model.onCardInserted("Acme CL 0", atr);

    ASSERT_EQ(reg.cards().size(), 1u);
    EXPECT_EQ(reg.cards()[0].capabilities, 0x3u);
    EXPECT_EQ(reg.cards()[0].reader, reg.readers()[0].id);
    EXPECT_EQ(model.cardIdFor("Acme CL 0"), ObjectId{2});
}

TEST(PresenceModel, CardCapabilitiesResolvedFromAtrWithoutOpeningSession)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("Acme CL 0");

    model.onCardInserted("Acme CL 0", {0x3B, 0x01});

    ASSERT_EQ(reg.cards().size(), 1u);
    EXPECT_EQ(reg.cards()[0].capabilities, 0x3u) << "capabilities must be published from the ATR-only union on insert";
}

TEST(PresenceModel, CardRemovedDropsCardObjectButKeepsReader)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("Acme CL 0");
    model.onCardInserted("Acme CL 0", {0x3B, 0x01});

    model.onCardRemoved("Acme CL 0");

    EXPECT_EQ(reg.readers().size(), 1u);
    EXPECT_TRUE(reg.cards().empty());
}

TEST(PresenceModel, UnresolvableCardStillCreatesCardWithNoneCapabilities)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("Acme CL 0");

    model.onCardInserted("Acme CL 0", {}); // empty ATR -> resolver returns nullptr

    ASSERT_EQ(reg.cards().size(), 1u);
    EXPECT_EQ(reg.cards()[0].capabilities, 0u);
}

TEST(PresenceModel, ReaderAddedTwiceIsIdempotent)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);

    model.onReaderAdded("R0");
    model.onReaderAdded("R0");

    EXPECT_EQ(reg.readers().size(), 1u) << "second add for the same reader must be a no-op";
}

TEST(PresenceModel, CardInsertedWithoutReaderAutoAddsReader)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);

    model.onCardInserted("R0", {0x3B, 0x01});

    EXPECT_EQ(reg.readers().size(), 1u) << "card insert on an unknown reader must auto-create that reader";
    EXPECT_EQ(reg.cards().size(), 1u);
}

TEST(PresenceModel, CardReinsertedReplacesPreviousCardOnSameReader)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");
    model.onCardInserted("R0", {0x3B, 0x01}); // card id 2
    model.onCardInserted("R0", {0x3B, 0x02}); // a different card swapped in -> id 3

    ASSERT_EQ(reg.cards().size(), 1u) << "a re-insert without an explicit remove must drop the previous card";
    EXPECT_NE(findCard(reg, ObjectId{3}), nullptr) << "the new card should get the next opaque counter, not reuse 2";
    EXPECT_EQ(findCard(reg, ObjectId{2}), nullptr);
}

TEST(PresenceModel, ReaderRemovedDropsItsCardFirst)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");
    model.onCardInserted("R0", {0x3B, 0x01});

    model.onReaderRemoved("R0");

    EXPECT_TRUE(reg.readers().empty()) << "removing a reader must also drop its current card";
    EXPECT_TRUE(reg.cards().empty());
}

TEST(PresenceModel, CardRemovedWithoutInsertIsSilentNoOp)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");

    model.onCardRemoved("R0"); // no card was ever inserted

    EXPECT_EQ(reg.readers().size(), 1u) << "the reader stays; the missing-card remove must be a no-op";
    EXPECT_TRUE(reg.cards().empty());
}

TEST(PresenceModel, OpaqueCountersAreMonotonicAcrossInsertCycles)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");

    model.onCardInserted("R0", {0x3B, 0x01}); // card id 2
    EXPECT_NE(findCard(reg, ObjectId{2}), nullptr);

    model.onCardRemoved("R0");
    model.onCardInserted("R0", {0x3B, 0x02}); // card id 3

    EXPECT_NE(findCard(reg, ObjectId{3}), nullptr)
        << "removed indices are not reused — opaque counter is monotonic per process lifetime";
    EXPECT_EQ(findCard(reg, ObjectId{2}), nullptr);
}

TEST(PresenceModel, CardIdForReturnsCurrentCardId)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");

    EXPECT_EQ(model.cardIdFor("R0"), ObjectId{}) << "no card inserted yet -> invalid id";

    model.onCardInserted("R0", {0x3B, 0x01});
    EXPECT_EQ(model.cardIdFor("R0"), ObjectId{2});

    // A re-insert mints a fresh monotonic id; cardIdFor tracks it.
    model.onCardInserted("R0", {0x3B, 0x02});
    EXPECT_EQ(model.cardIdFor("R0"), ObjectId{3});

    model.onCardRemoved("R0");
    EXPECT_EQ(model.cardIdFor("R0"), ObjectId{}) << "after removal the reader has no current card id";
}

TEST(PresenceModel, CardIdForUnknownReaderIsInvalid)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    EXPECT_EQ(model.cardIdFor("never-seen"), ObjectId{});
}

TEST(PresenceModel, MultipleReadersAndCardsCoexist)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");
    model.onReaderAdded("R1");
    model.onCardInserted("R0", {0x3B, 0x01});
    model.onCardInserted("R1", {0x3B, 0x02});

    EXPECT_EQ(reg.readers().size(), 2u);
    EXPECT_EQ(reg.cards().size(), 2u);
}

// --- Card1.PreReadAuthMethod resolution ----------------------------------

// Pre-read auth needs a live CardSession (CardPlugin::preReadAuth(session)), so
// the monitor thread cannot resolve it on insert without opening one. Card1 is
// published with the pending "None" token synchronously; the per-reader worker
// resolves and republishes the real method on its held session.
TEST(PresenceModel, CardPublishesPendingNonePreReadAuthMethodOnInsert)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");

    model.onCardInserted("R0", {0x3B, 0x01});

    ASSERT_EQ(reg.cards().size(), 1u);
    EXPECT_EQ(reg.cards()[0].preReadAuth, LibreSCRS::Auth::PreReadAuthMethod::None)
        << "pre-read auth is resolved later on the held session, not on insert";
}

TEST(PresenceModel, UnresolvableCardReportsNonePreReadAuthMethod)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");

    model.onCardInserted("R0", {}); // empty ATR -> no plugin match

    ASSERT_EQ(reg.cards().size(), 1u);
    EXPECT_EQ(reg.cards()[0].preReadAuth, LibreSCRS::Auth::PreReadAuthMethod::None)
        << "an unmatched card must default to the no-unlock vocabulary token";
}

// --- Reader1.HasCard/Card live presence ----------------------------------

TEST(PresenceModel, ReaderHasCardFlipsTrueOnInsert)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");

    ASSERT_EQ(reg.readers().size(), 1u);
    EXPECT_FALSE(reg.readers()[0].hasCard);
    EXPECT_FALSE(reg.readers()[0].card.valid());

    model.onCardInserted("R0", {0x3B, 0x01});

    ASSERT_EQ(reg.readers().size(), 1u);
    ASSERT_EQ(reg.cards().size(), 1u);
    EXPECT_TRUE(reg.readers()[0].hasCard) << "HasCard must go live to true on card insert";
    EXPECT_EQ(reg.readers()[0].card, reg.cards()[0].id);
}

TEST(PresenceModel, ReaderHasCardFlipsFalseOnRemove)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);
    model.onReaderAdded("R0");
    model.onCardInserted("R0", {0x3B, 0x01});

    model.onCardRemoved("R0");

    ASSERT_EQ(reg.readers().size(), 1u);
    EXPECT_FALSE(reg.readers()[0].hasCard) << "HasCard must go live to false on card remove";
    EXPECT_FALSE(reg.readers()[0].card.valid());
}

TEST(PresenceModel, ReaderPropertyChangeNotifiesChangedObserver)
{
    ObjectRegistry reg;
    FakeResolver res;
    PresenceModel model(reg, res);

    int changeCount = 0;
    ObjectId lastReader;
    bool sawHasCardTrue = false;
    reg.setObservers({}, {}, {}, [&](ObjectId reader, const PropertyDelta& delta) {
        ++changeCount;
        lastReader = reader;
        sawHasCardTrue = delta.hasCard;
    });

    model.onReaderAdded("R0");
    model.onCardInserted("R0", {0x3B, 0x01});

    EXPECT_EQ(changeCount, 1) << "exactly one Reader1 property-change must fire on insert";
    EXPECT_EQ(lastReader, reg.readers()[0].id);
    EXPECT_TRUE(sawHasCardTrue);

    model.onCardRemoved("R0");
    EXPECT_EQ(changeCount, 2) << "a second change must fire on remove";
    EXPECT_FALSE(sawHasCardTrue);
}
