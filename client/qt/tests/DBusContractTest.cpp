// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The agent's D-Bus introspection XML (wire/dbus/) is the contract of record
// for the bus; this client is one side of it. Every interface the transport
// names, every member it calls, subscribes to or reads, and every signal
// argument it demarshals must exist in the XML with the signature the
// client's own marshalling produces. An agent-side change to the XML that the
// client does not follow -- or the reverse -- fails here, not on a desk.

#include "dbus/AgentDBus.h"
#include "dbus/Marshal.h"

#include <QDBusMetaType>
#include <QDBusUnixFileDescriptor>
#include <QDir>
#include <QFile>
#include <QMap>
#include <QString>
#include <QVariantMap>
#include <QXmlStreamReader>

#include <gtest/gtest.h>

#include <optional>

using namespace LibreSCRS::AgentClient;

namespace {

enum class Kind { Method, Signal, Property };

struct Member
{
    Kind kind;
    QString signature; ///< in-args (method), args (signal), type (property)
};

/// interface -> "kind:name" -> member, over every XML in the contract dir.
using Contract = QMap<QString, QMap<QString, Member>>;

QString keyOf(Kind kind, const QString& name)
{
    const char* prefix = kind == Kind::Method ? "method:" : kind == Kind::Signal ? "signal:" : "property:";
    return QLatin1String(prefix) + name;
}

Contract loadContract()
{
    Contract contract;
    const QDir dir(QStringLiteral(LIBREAGENT_DBUS_XML_DIR));
    const QStringList files = dir.entryList({QStringLiteral("*.xml")}, QDir::Files);
    EXPECT_FALSE(files.isEmpty()) << LIBREAGENT_DBUS_XML_DIR;
    for (const QString& name : files) {
        QFile file(dir.filePath(name));
        EXPECT_TRUE(file.open(QIODevice::ReadOnly)) << name.toStdString();
        QXmlStreamReader xml(&file);
        QString iface;
        std::optional<Kind> kind;
        QString member;
        QString signature;
        while (!xml.atEnd()) {
            xml.readNext();
            if (xml.isStartElement()) {
                const auto element = xml.name();
                const QString attrName = xml.attributes().value(QStringLiteral("name")).toString();
                if (element == QLatin1String("interface")) {
                    iface = attrName;
                } else if (element == QLatin1String("method") || element == QLatin1String("signal")) {
                    kind = element == QLatin1String("method") ? Kind::Method : Kind::Signal;
                    member = attrName;
                    signature.clear();
                } else if (element == QLatin1String("property")) {
                    contract[iface].insert(
                        keyOf(Kind::Property, attrName),
                        Member{Kind::Property, xml.attributes().value(QStringLiteral("type")).toString()});
                } else if (element == QLatin1String("arg") && kind) {
                    const QString direction = xml.attributes().value(QStringLiteral("direction")).toString();
                    if (*kind == Kind::Signal || direction != QLatin1String("out")) {
                        signature += xml.attributes().value(QStringLiteral("type")).toString();
                    }
                }
            } else if (xml.isEndElement() && kind &&
                       (xml.name() == QLatin1String("method") || xml.name() == QLatin1String("signal"))) {
                contract[iface].insert(keyOf(*kind, member), Member{*kind, signature});
                kind.reset();
            }
        }
        EXPECT_FALSE(xml.hasError()) << name.toStdString() << ": " << xml.errorString().toStdString();
    }
    return contract;
}

template <typename T>
QString sig()
{
    return QString::fromLatin1(QDBusMetaType::typeToSignature(QMetaType::fromType<T>()));
}

class DBusContract : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        ensureDBusMetatypes();
    }
    void expectMember(const char* iface, Kind kind, const char* name, const std::optional<QString>& signature)
    {
        const QString interfaceName = QLatin1String(iface);
        ASSERT_TRUE(contract.contains(interfaceName)) << iface << " is in no contract XML";
        const auto& members = contract.value(interfaceName);
        const auto it = members.constFind(keyOf(kind, QLatin1String(name)));
        ASSERT_NE(it, members.constEnd()) << iface << " has no " << name;
        if (signature) {
            EXPECT_EQ(it->signature, *signature) << iface << "." << name;
        }
    }
    Contract contract = loadContract();
};

TEST_F(DBusContract, EveryInterfaceTheClientNamesIsInTheContract)
{
    for (const char* iface :
         {kManagerIface, kConfigIface, kReaderIface, kCardIface, kPkcs11Iface, kCredentialsIface, kOperationIface,
          kSignIface, kSignBatchIface, kIdentityIface, kCertificatesIface, kPhotoIface, kOperationCredentialsIface}) {
        EXPECT_TRUE(contract.contains(QLatin1String(iface))) << iface;
    }
}

TEST_F(DBusContract, TheSignalsTheClientDemarshalsCarryItsTypes)
{
    expectMember(kOperationIface, Kind::Signal, "Finished", QStringLiteral("uuss"));
    expectMember(kConfigIface, Kind::Signal, "Changed", QStringLiteral("s"));
    expectMember(kManagerIface, Kind::Signal, "Quiesced", QStringLiteral("u"));
    expectMember(kSignIface, Kind::Signal, "Result", sig<QDBusUnixFileDescriptor>() + sig<QVariantMap>());
    expectMember(kSignBatchIface, Kind::Signal, "Result", sig<SignBatchRowsWire>());
    expectMember(kIdentityIface, Kind::Signal, "Result", sig<IdentityFieldsWire>());
    expectMember(kIdentityIface, Kind::Signal, "Group", QStringLiteral("s") + sig<IdentityFieldGroupWire>());
    expectMember(kCertificatesIface, Kind::Signal, "Result", sig<CertListWire>());
    expectMember(kPhotoIface, Kind::Signal, "Result", sig<PhotoMapWire>());
    expectMember(kOperationCredentialsIface, Kind::Signal, "Result", sig<QVariantMap>() + sig<CredentialRecordsWire>());
}

TEST_F(DBusContract, TheMembersTheClientCallsAndReadsExist)
{
    for (const char* method : {"ReadIdentity", "GetPhoto", "ReadCertificates", "ReadTokenInfo", "Sign", "SignBatch"}) {
        expectMember(kCardIface, Kind::Method, method, std::nullopt);
    }
    for (const char* method : {"ListCredentials", "ManagePin", "ActivateSigningKey"}) {
        expectMember(kCredentialsIface, Kind::Method, method, std::nullopt);
    }
    for (const char* method : {"SetValue", "Reset", "ImportCscaMasterList"}) {
        expectMember(kConfigIface, Kind::Method, method, std::nullopt);
    }
    expectMember(kManagerIface, Kind::Method, "LayoutVisualSignature", QStringLiteral("sdddd"));
    expectMember(kManagerIface, Kind::Method, "GetAppearanceFont", QString());
    expectMember(kManagerIface, Kind::Property, "Features", QStringLiteral("as"));
    expectMember(kManagerIface, Kind::Property, "Version", QStringLiteral("s"));
    // Every Reader1 property AgentReader reads, the label included.
    expectMember(kReaderIface, Kind::Property, "Name", QStringLiteral("s"));
    expectMember(kReaderIface, Kind::Property, "HasCard", QStringLiteral("b"));
    expectMember(kReaderIface, Kind::Property, "Card", QStringLiteral("o"));
    expectMember(kReaderIface, Kind::Property, "Model", QStringLiteral("s"));
    expectMember(kReaderIface, Kind::Property, "Interface", QStringLiteral("s"));
    expectMember(kPkcs11Iface, Kind::Method, "CertDer", QStringLiteral("os"));
    expectMember(kOperationIface, Kind::Method, "Cancel", QString());
    for (const char* property : {"Completed", "Status", "ErrorCode", "Phase", "Progress"}) {
        expectMember(kOperationIface, Kind::Property, property, std::nullopt);
    }
    for (const char* typed :
         {kSignIface, kSignBatchIface, kIdentityIface, kCertificatesIface, kPhotoIface, kOperationCredentialsIface}) {
        expectMember(typed, Kind::Method, "GetResult", QString());
    }
}

} // namespace
