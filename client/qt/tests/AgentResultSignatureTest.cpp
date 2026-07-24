// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the registered D-Bus signatures of the typed Result payload types to
// the frozen agent XML, independent of any FakeAgent/bus (no dbus-run-session
// needed — QDBusMetaType::typeToSignature works off the registered type alone).
// The agent's org.librescrs.Agent.Operation.Certificates1.Result emits
// a(sba{sa{s(ssv)}}uasasu) and Identity1.Result emits a{sa{s(sssv)}}; if a
// client struct member drifts (e.g. a cert field value silently demarshaled as
// a plain string instead of a variant `v`) the typed Result never demarshals
// against the real agent and signing never proceeds. These asserts catch that
// at build/test time rather than only against a live daemon.
//
// Adapted from the lifted KDE suite of the same name: the wire-shape mirror
// types moved from the KDE client's own headers into this repo's INTERNAL
// dbus/Marshal.h (IdentityFields -> IdentityFieldsWire, CertificateList ->
// CertListWire, PhotoMap -> PhotoMapWire; CredentialRecordsWire kept its name).

#include "dbus/Marshal.h"

#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

// The certificates Result demarshals into CertListWire; its registered
// signature MUST equal the frozen Certificates1.xml `a(sba{sa{s(ssv)}}uasasu)`.
// The field tuple's third member is a variant `v`, NOT a string `s` — emitting
// (sss) here would make the real agent's payload undemarshalable.
TEST(AgentResultSignature, CertificateListMatchesXml)
{
    ensureDBusMetatypes();
    const QByteArray sig = QDBusMetaType::typeToSignature(QMetaType::fromType<CertListWire>());
    EXPECT_EQ(sig, QByteArray("a(sba{sa{s(ssv)}}uasasu)"));
}

// The identity Result demarshals into IdentityFieldsWire; its registered
// signature MUST equal the frozen Identity1.xml `a{sa{s(sssv)}}` — the
// four-member tuple (labelKey, labelFallback, type, variant value).
TEST(AgentResultSignature, IdentityFieldsMatchesXml)
{
    ensureDBusMetatypes();
    const QByteArray sig = QDBusMetaType::typeToSignature(QMetaType::fromType<IdentityFieldsWire>());
    EXPECT_EQ(sig, QByteArray("a{sa{s(sssv)}}"));
}

// pin the ObjectManager wire shapes — the interface-props map a{sa{sv}}
// and the GetManagedObjects map a{oa{sa{sv}}}. A drift here breaks discovery
// demarshalling against the real agent.
TEST(AgentResultSignature, ObjectManagerMapsMatchXml)
{
    ensureDBusMetatypes();
    EXPECT_EQ(QDBusMetaType::typeToSignature(QMetaType::fromType<AgentInterfaceProps>()), QByteArray("a{sa{sv}}"));
    EXPECT_EQ(QDBusMetaType::typeToSignature(QMetaType::fromType<QMap<QDBusObjectPath, AgentInterfaceProps>>()),
              QByteArray("a{oa{sa{sv}}}"));
}

// The GetPhoto Result demarshals into PhotoMapWire; its registered signature
// MUST equal the frozen Photo1.xml `a{sh}` (groupKey:fieldKey -> sealed memfd).
// A drift here (e.g. demarshaling the fd as a plain `s` path) makes the real
// agent's sealed-memfd payload undemarshalable and the photo never arrives.
TEST(AgentResultSignature, PhotoMapMatchesXml)
{
    ensureDBusMetatypes();
    EXPECT_EQ(QDBusMetaType::typeToSignature(QMetaType::fromType<PhotoMapWire>()), QByteArray("a{sh}"));
}

// The ListCredentials records demarshal into CredentialRecordsWire; its
// registered signature MUST equal the frozen Credentials1.xml `aa{sv}`, and the
// per-record/result payload maps must stay a plain `a{sv}` — a drift here makes
// the real agent's credential records undemarshalable.
TEST(AgentResultSignature, CredentialRecordsMatchXml)
{
    ensureDBusMetatypes();
    EXPECT_EQ(QDBusMetaType::typeToSignature(QMetaType::fromType<CredentialRecordsWire>()),
              QByteArray("aa{sv}")); // ListCredentials records
    EXPECT_EQ(QDBusMetaType::typeToSignature(QMetaType::fromType<QVariantMap>()),
              QByteArray("a{sv}")); // result payload
}

// The cert-payload demarshal test lives in AgentCardTest.cpp
// (DemarshalRealShapedCertPayload): a standalone QDBusArgument does not
// round-trip write->read without going through the bus marshaller, so the
// real-shaped-payload demarshal test is bus-backed there, with the FakeAgent
// hand-marshalling the (sba{sa{s(ssv)}}uasasu) struct via a raw signal (NOT
// the client's operator<<).
