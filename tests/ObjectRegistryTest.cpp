// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <gtest/gtest.h>

using namespace LibreSCRS::Agent;

TEST(ObjectRegistry, EmptyByDefault)
{
    ObjectRegistry r;
    EXPECT_TRUE(r.readers().empty());
    EXPECT_TRUE(r.cards().empty());
    EXPECT_FALSE(r.contains(ObjectId{1}));
}

TEST(ObjectRegistry, AddReaderInsertsAndFiresObserver)
{
    ObjectRegistry r;
    int adds = 0;
    ObjectId lastId;
    r.setObservers(
        [&](const ReaderState& rs) {
            ++adds;
            lastId = rs.id;
        },
        {}, {}, {});

    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R0"});

    EXPECT_EQ(adds, 1);
    EXPECT_EQ(lastId, ObjectId{1});
    ASSERT_EQ(r.readers().size(), 1u);
    EXPECT_TRUE(r.contains(ObjectId{1}));
}

TEST(ObjectRegistry, AddCardInsertsAndFiresObserver)
{
    ObjectRegistry r;
    int adds = 0;
    ObjectId lastId;
    r.setObservers({},
                   [&](const CardState& cs) {
                       ++adds;
                       lastId = cs.id;
                   },
                   {}, {});

    r.addCard(CardState{.id = ObjectId{2}, .reader = ObjectId{1}, .capabilities = 0x3u});

    EXPECT_EQ(adds, 1);
    EXPECT_EQ(lastId, ObjectId{2});
    ASSERT_EQ(r.cards().size(), 1u);
    EXPECT_EQ(r.cards().front().capabilities, 0x3u);
    EXPECT_TRUE(r.contains(ObjectId{2}));
}

TEST(ObjectRegistry, AddDuplicateIdIsNoOp)
{
    ObjectRegistry r;
    int adds = 0;
    r.setObservers([&](const ReaderState&) { ++adds; }, {}, {}, {});

    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R0"});
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R0-different-name"}); // same id

    EXPECT_EQ(adds, 1) << "duplicate-id add must not re-fire";
    ASSERT_EQ(r.readers().size(), 1u);
    // The original value wins (first-writer-wins, not last) — verify name is unchanged.
    EXPECT_EQ(r.readers().front().name, "R0");
}

TEST(ObjectRegistry, RemoveErasesAndFiresObserver)
{
    ObjectRegistry r;
    int removes = 0;
    ObjectId removedId;
    r.setObservers({}, {}, [&](ObjectId id) {
        ++removes;
        removedId = id;
    });

    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R0"});
    r.remove(ObjectId{1});

    EXPECT_EQ(removes, 1);
    EXPECT_EQ(removedId, ObjectId{1});
    EXPECT_TRUE(r.readers().empty());
    EXPECT_FALSE(r.contains(ObjectId{1}));
}

TEST(ObjectRegistry, RemoveSearchesCardsWhenNotAReader)
{
    ObjectRegistry r;
    int removes = 0;
    ObjectId removedId;
    r.setObservers({}, {}, [&](ObjectId id) {
        ++removes;
        removedId = id;
    });

    r.addCard(CardState{.id = ObjectId{2}, .reader = ObjectId{1}});
    r.remove(ObjectId{2});

    EXPECT_EQ(removes, 1);
    EXPECT_EQ(removedId, ObjectId{2});
    EXPECT_TRUE(r.cards().empty());
    EXPECT_FALSE(r.contains(ObjectId{2}));
}

TEST(ObjectRegistry, RemoveMissingIdIsNoOp)
{
    ObjectRegistry r;
    int removes = 0;
    r.setObservers({}, {}, [&](ObjectId) { ++removes; });

    r.remove(ObjectId{99});

    EXPECT_EQ(removes, 0) << "removing a missing id must not fire";
    EXPECT_TRUE(r.readers().empty());
}

TEST(ObjectRegistry, UpdateMutatesReaderAndFiresChangedObserver)
{
    ObjectRegistry r;
    int changes = 0;
    ObjectId changedReader;
    PropertyDelta lastDelta;
    r.setObservers({}, {}, {}, [&](ObjectId reader, const PropertyDelta& d) {
        ++changes;
        changedReader = reader;
        lastDelta = d;
    });

    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R0"});
    r.addCard(CardState{.id = ObjectId{2}, .reader = ObjectId{1}});
    r.update(ObjectId{1}, PropertyDelta{.hasCard = true, .card = ObjectId{2}});

    EXPECT_EQ(changes, 1);
    EXPECT_EQ(changedReader, ObjectId{1});
    EXPECT_TRUE(lastDelta.hasCard);
    EXPECT_EQ(lastDelta.card, ObjectId{2});
    // The stored reader reflects the mutation (a later readers() snapshot is consistent).
    ASSERT_EQ(r.readers().size(), 1u);
    EXPECT_TRUE(r.readers().front().hasCard);
    EXPECT_EQ(r.readers().front().card, ObjectId{2});
}

TEST(ObjectRegistry, UpdateOnUnknownOrInvalidReaderIsNoOp)
{
    ObjectRegistry r;
    int changes = 0;
    r.setObservers({}, {}, {}, [&](ObjectId, const PropertyDelta&) { ++changes; });

    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R0"});
    r.update(ObjectId{}, PropertyDelta{.hasCard = false});  // invalid id
    r.update(ObjectId{9}, PropertyDelta{.hasCard = true});  // unknown reader
    r.update(ObjectId{1}, PropertyDelta{.hasCard = false}); // no-change delta

    EXPECT_EQ(changes, 0) << "invalid/unknown/no-change update must not fire";
    EXPECT_FALSE(r.readers().front().hasCard);
}

TEST(ObjectRegistry, WorksWithoutObservers)
{
    // Default-constructed: no observers set. addReader()/remove() must be safe and
    // produce visible state without crashing on the empty std::function.
    ObjectRegistry r;
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R"});
    EXPECT_TRUE(r.contains(ObjectId{1}));
    r.remove(ObjectId{1});
    EXPECT_FALSE(r.contains(ObjectId{1}));
}

TEST(ObjectRegistry, SetObserversReplacesPreviousHandlers)
{
    ObjectRegistry r;
    int oldAdds = 0;
    int newAdds = 0;
    r.setObservers([&](const ReaderState&) { ++oldAdds; }, {}, {}, {});
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R"});
    EXPECT_EQ(oldAdds, 1);

    // Replace the observer.
    r.setObservers([&](const ReaderState&) { ++newAdds; }, {}, {}, {});
    r.addReader(ReaderState{.id = ObjectId{2}, .name = "R"});

    EXPECT_EQ(oldAdds, 1) << "old observer must not fire after replacement";
    EXPECT_EQ(newAdds, 1);
}

TEST(ObjectRegistry, SetEmptyObserversDetachesSafely)
{
    // This is the exact pattern the transport backend's destructor relies on: detach
    // observers so subsequent registry mutations cannot call back through a
    // dangling `this`.
    ObjectRegistry r;
    int adds = 0;
    int removes = 0;
    r.setObservers([&](const ReaderState&) { ++adds; }, {}, [&](ObjectId) { ++removes; });
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "R"});
    EXPECT_EQ(adds, 1);

    r.setObservers({}, {}, {}); // detach
    r.addReader(ReaderState{.id = ObjectId{2}, .name = "R"});
    r.remove(ObjectId{1});

    EXPECT_EQ(adds, 1) << "detached add observer must not fire";
    EXPECT_EQ(removes, 0) << "detached remove observer must not fire";
    // State still mutates correctly even with no observers.
    EXPECT_TRUE(r.contains(ObjectId{2}));
    EXPECT_FALSE(r.contains(ObjectId{1}));
}

namespace {
const std::string kContactSlot =
    "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00";
const std::string kContactlessSlot =
    "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00";

struct Heard
{
    std::vector<std::string> events; // "add:<id>:<model>:<iface>" / "relabel:..." / "remove:<id>"
};

std::string describe(const char* what, const ReaderState& r)
{
    return std::string(what) + ":" + std::to_string(r.id.value()) + ":" + r.model + ":" +
           std::string(LibreSCRS::Agent::Wire::readerInterfaceToken(r.iface));
}

void listen(ObjectRegistry& r, Heard& heard)
{
    r.setObservers([&](const ReaderState& rs) { heard.events.push_back(describe("add", rs)); }, {},
                   [&](ObjectId id) { heard.events.push_back("remove:" + std::to_string(id.value())); }, {},
                   [&](const ReaderState& rs) { heard.events.push_back(describe("relabel", rs)); });
}
} // namespace

// A reader is published with the label the whole roster gives it -- whatever
// label the caller handed in is not the registry's to keep.
TEST(ObjectRegistry, AReaderIsPublishedWithItsLabel)
{
    ObjectRegistry r;
    Heard heard;
    listen(r, heard);
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "Gemalto PC Twin Reader (69988A87) 02 00", .model = "stale"});
    EXPECT_EQ(heard.events, std::vector<std::string>{"add:1:Gemalto PC Twin:unknown"});
    EXPECT_EQ(r.readers().front().model, "Gemalto PC Twin");
}

// The contact slot is only a contact slot once its contactless twin is there:
// the twin's arrival relabels the reader already published, after the twin
// itself is announced, and its departure relabels it back.
TEST(ObjectRegistry, ATwinArrivingOrLeavingRelabelsTheReaderBesideIt)
{
    ObjectRegistry r;
    Heard heard;
    listen(r, heard);
    r.addReader(ReaderState{.id = ObjectId{1}, .name = kContactSlot});
    r.addReader(ReaderState{.id = ObjectId{2}, .name = kContactlessSlot});
    r.remove(ObjectId{2});
    EXPECT_EQ(heard.events, (std::vector<std::string>{"add:1:OMNIKEY 5422:unknown", "add:2:OMNIKEY 5422:contactless",
                                                      "relabel:1:OMNIKEY 5422:contact", "remove:2",
                                                      "relabel:1:OMNIKEY 5422:unknown"}));
    EXPECT_EQ(r.readers().front().iface, ReaderInterface::Unknown);
}

// A neighbour whose label does not change hears nothing.
TEST(ObjectRegistry, AnUnrelatedArrivalRelabelsNothing)
{
    ObjectRegistry r;
    Heard heard;
    listen(r, heard);
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "Gemalto PC Twin Reader (69988A87) 02 00"});
    r.addReader(ReaderState{.id = ObjectId{2}, .name = kContactlessSlot});
    r.remove(ObjectId{2});
    EXPECT_EQ(heard.events, (std::vector<std::string>{"add:1:Gemalto PC Twin:unknown", "add:2:OMNIKEY 5422:contactless",
                                                      "remove:2"}));
}

// A second reader of the same model makes both labels take a serial suffix.
TEST(ObjectRegistry, ASameModelNeighbourRelabelsTheFirstReader)
{
    ObjectRegistry r;
    Heard heard;
    listen(r, heard);
    r.addReader(ReaderState{.id = ObjectId{1}, .name = "Gemalto PC Twin Reader (AAAA1111) 00 00"});
    r.addReader(ReaderState{.id = ObjectId{2}, .name = "Gemalto PC Twin Reader (BBBB2222) 01 00"});
    EXPECT_EQ(heard.events,
              (std::vector<std::string>{"add:1:Gemalto PC Twin:unknown", "add:2:Gemalto PC Twin (2222):unknown",
                                        "relabel:1:Gemalto PC Twin (1111):unknown"}));
}
