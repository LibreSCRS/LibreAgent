// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the shapes the FakeAgent registers at construction, and the bus names it
// answers to.
//
// The fake marshals the client's OWN wire types rather than a second set of
// mirrors kept beside them -- one desktop host used to carry the second set,
// and the two understandings of one bus surface each had a green suite. What
// this file pins is therefore not a mirror against its twin but a REGISTRATION
// against a hand-transcribed literal, and the difference matters: signature is
// the whole contract and it is invisible to the compiler. Drop a member from a
// wire struct, reorder two, or demarshal a variant `v` as a plain string, and
// everything still builds. The payload simply stops matching any client slot at
// run time, in whichever suite happens to touch that one interface -- possibly
// none of them today.
//
// The asserts are deliberately written against what CONSTRUCTING THE FAKE
// registered, not against a registration performed here, so the pin covers the
// fake's real startup path. The registrations the shared test entry point
// performs are pinned the same way and for the same reason. AgentResultSignature
// covers the same signature strings from the other side -- the registration the
// LIBRARY performs for its own demarshalling -- and neither subsumes the other:
// a fake that stopped registering would leave that one green.
//
// Honest limitation: there is no build edge to the agent's published interface
// XML, so the literals below cannot auto-follow a change made there. A genuine
// drift against the daemon has to be caught where the XML is canonical.

#include "fakes/TestBus.h"

#include <LibreSCRS/AgentClient/OperationPhase.h>

#include <QByteArray>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusReply>
#include <QMetaType>
#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {

/// @brief The D-Bus signature Qt has registered for @p T, or an empty array when
///        the type is not registered at all (which fails every assert below,
///        exactly as a drifted signature does).
template <typename T>
QByteArray registeredSignature()
{
    const char* sig = QDBusMetaType::typeToSignature(QMetaType::fromType<T>());
    return sig ? QByteArray(sig) : QByteArray();
}

bool serviceOwned(QDBusConnection& connection, const QString& name)
{
    QDBusConnectionInterface* iface = connection.interface();
    if (iface == nullptr) {
        return false;
    }
    const QDBusReply<bool> reply = iface->isServiceRegistered(name);
    return reply.isValid() && reply.value();
}

} // namespace

// Identity1: the field tuple is (sssv) — labelKey, labelFallback, type, and the
// value as a variant `v`, NOT a plain string. The group and result maps are
// pinned too, because a client subscribes to the OUTER a{sa{s(sssv)}}.
TEST(FakeAgentWireShape, IdentityShapesMatchAgentXml)
{
    Harness h{FakeAgent::Config{}};
    EXPECT_EQ(registeredSignature<IdentityFieldWire>(), QByteArray("(sssv)"));
    EXPECT_EQ(registeredSignature<IdentityFieldGroupWire>(), QByteArray("a{s(sssv)}"));
    EXPECT_EQ(registeredSignature<IdentityFieldsWire>(), QByteArray("a{sa{s(sssv)}}"));
}

// Certificates1: the field tuple is (ssv) — one member SHORTER than Identity1's,
// with no type string. The entry struct is (s b a{sa{s(ssv)}} u as as u): seven
// members, the display strings riding inside the field map rather than being
// appended to the struct.
TEST(FakeAgentWireShape, CertificateShapesMatchAgentXml)
{
    Harness h{FakeAgent::Config{}};
    EXPECT_EQ(registeredSignature<CertFieldWire>(), QByteArray("(ssv)"));
    EXPECT_EQ(registeredSignature<CertFieldGroupWire>(), QByteArray("a{s(ssv)}"));
    EXPECT_EQ(registeredSignature<CertFieldGroupsWire>(), QByteArray("a{sa{s(ssv)}}"));
    EXPECT_EQ(registeredSignature<CertInfoWire>(), QByteArray("(sba{sa{s(ssv)}}uasasu)"));
    EXPECT_EQ(registeredSignature<CertListWire>(), QByteArray("a(sba{sa{s(ssv)}}uasasu)"));
}

// Photo1 hands out sealed memfds keyed "groupKey:fieldKey", so the value is `h`
// and never a path string; Credentials1 records are aa{sv}; ObjectManager uses
// a{sa{sv}} per object and a{oa{sa{sv}}} for the whole tree.
TEST(FakeAgentWireShape, ContainerShapesMatchAgentXml)
{
    Harness h{FakeAgent::Config{}};
    EXPECT_EQ(registeredSignature<PhotoMapWire>(), QByteArray("a{sh}"));
    EXPECT_EQ(registeredSignature<CredentialRecordsWire>(), QByteArray("aa{sv}"));
    EXPECT_EQ(registeredSignature<FakeInterfaceProps>(), QByteArray("a{sa{sv}}"));
    EXPECT_EQ(registeredSignature<FakeManagedObjects>(), QByteArray("a{oa{sa{sv}}}"));
}

// A registered TYPE is not enough for one of these. QtDBus resolves a slot's
// non-const-reference OUTPUT parameter by looking the type up under the NAME moc
// recorded for it, so Operation.Credentials1.GetResult's trailing `records`
// out-arg is unreachable — the call is answered with an error and a client's
// lost-Result recovery silently returns nothing — unless that exact spelling is
// in the name registry as well.
// This is HALF the guard: it pins that the name is registered. The other half is
// that the slot is spelled with that same name, which the test below pins —
// break only the spelling and this test stays green.
TEST(FakeAgentWireShape, CredentialRecordsResolveUnderTheirSpelledName)
{
    Harness h{FakeAgent::Config{}};
    const QMetaType byName = QMetaType::fromName("LibreSCRS::AgentClient::CredentialRecordsWire");
    EXPECT_TRUE(byName.isValid()) << "the credentials out-arg type must be resolvable by name";
    EXPECT_EQ(byName, QMetaType::fromType<CredentialRecordsWire>());
}

// The other half, and the general form of it. Registration and spelling only
// help if they MATCH, so read the spellings straight out of the adaptors'
// metaobjects — the very strings QtDBus will look up — and require each one to
// resolve. Written as a walk rather than a single assert so that a slot added
// later to an adaptor ALREADY IN THE LIST arrives covered for free.
//
// What the count assert below does and does not do, stated plainly because it is
// easy to over-read: the list it counts is a hand-written enumeration, so an
// adaptor added to FakeAgent.cpp and never listed leaves the count at 15 and this
// test green. It cannot detect that. What it does detect is the LIST changing
// size — it forces whoever edits the list to come here and re-read what the walk
// is for. Keeping the list complete stays a discipline, stated where the list is
// declared; no assert here enforces it.
TEST(FakeAgentWireShape, AdaptorReferenceOutParametersResolveUnderTheirRecordedNames)
{
    Harness h{FakeAgent::Config{}};

    EXPECT_EQ(adaptorMetaObjects().size(), 15)
        << "the adaptor list in FakeAgent.cpp changed size. This counts the list, not the adaptors "
           "that exist, so also check by hand that every adaptor is still in it — then update the "
           "expected number";

    const QList<QByteArray> outParams = adaptorReferenceOutParameterTypes();
    ASSERT_FALSE(outParams.isEmpty()) << "the walk found no reference output parameter at all, so it guards nothing";
    EXPECT_TRUE(outParams.contains(QByteArray("LibreSCRS::AgentClient::CredentialRecordsWire&")))
        << "the credentials records out-arg must keep the fully-qualified spelling its registration uses; the walk "
           "found: "
        << outParams.join(", ").constData();

    for (const QByteArray& recorded : outParams) {
        QByteArray named = recorded;
        named.chop(1); // drop the trailing '&' QtDBus strips before the lookup
        EXPECT_TRUE(QMetaType::fromName(named).isValid())
            << "nothing is registered under the name '" << named.constData()
            << "', so QtDBus matches no slot for the call carrying it";
    }
}

// The shared entry point registers the client's operation-phase enum, which the
// client itself declares no metatype for. Registering it under the type alone is
// not the same as registering it under the name a signal signature spells it
// with, and the two names differ here — the enum is re-exported into the client
// namespace from the one it is declared in — so pin both.
TEST(FakeAgentWireShape, EntryPointRegistersTheOperationPhaseEnum)
{
    const QMetaType phase = QMetaType::fromType<LibreSCRS::AgentClient::OperationPhase>();
    EXPECT_EQ(QMetaType::fromName(phase.name()), phase) << "the enum must be resolvable under its canonical name";
    EXPECT_EQ(QMetaType::fromName("LibreSCRS::AgentClient::OperationPhase"), phase)
        << "and under the spelling the client's own signal signatures use";
}

// The fake answers on a per-test unique name by default. A client that binds
// itself to the agent's real well-known name cannot be pointed at that, so the
// harness can claim the real name alongside — and must give it back on teardown,
// or the next test that asks for it is refused.
TEST(FakeAgentWireShape, WellKnownNameIsClaimedOnRequestAndReleasedOnTeardown)
{
    {
        Harness unique{FakeAgent::Config{}};
        EXPECT_FALSE(unique.claimsWellKnownService());
        EXPECT_TRUE(serviceOwned(unique.client(), unique.service()));
        EXPECT_FALSE(serviceOwned(unique.client(), wellKnownAgentService()))
            << "the default mode must leave the agent's real name unclaimed";
    }
    {
        Harness both{FakeAgent::Config{}, BusNames::UniqueAndWellKnown};
        EXPECT_TRUE(both.claimsWellKnownService());
        EXPECT_TRUE(serviceOwned(both.client(), both.service())) << "the unique name must still be claimed";
        EXPECT_TRUE(serviceOwned(both.client(), wellKnownAgentService()));
    }
    Harness again{FakeAgent::Config{}, BusNames::UniqueAndWellKnown};
    EXPECT_TRUE(serviceOwned(again.client(), wellKnownAgentService()))
        << "teardown must release the well-known name for the next claimant";
}

// Owning the name is not the same as serving on it: prove a real call addressed
// to the well-known name reaches the fake's object tree and comes back.
TEST(FakeAgentWireShape, FakeIsReachableUnderTheWellKnownName)
{
    Harness h{FakeAgent::Config{}, BusNames::UniqueAndWellKnown};
    QDBusMessage call = QDBusMessage::createMethodCall(wellKnownAgentService(), QStringLiteral("/org/librescrs/Agent"),
                                                       QStringLiteral("org.freedesktop.DBus.ObjectManager"),
                                                       QStringLiteral("GetManagedObjects"));
    const QDBusMessage reply = h.client().call(call, QDBus::Block, 4000);
    ASSERT_EQ(reply.type(), QDBusMessage::ReplyMessage)
        << reply.errorName().toStdString() << ": " << reply.errorMessage().toStdString();
    EXPECT_FALSE(reply.arguments().isEmpty());
}
