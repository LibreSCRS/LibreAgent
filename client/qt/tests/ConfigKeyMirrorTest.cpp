// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Drift guard: ConfigKeys.h's hand-written isSettableConfigKey() mirror,
// checked against the published `settable-config-key` vocabulary in
// wire/wire-vocabulary.json -- the same manifest the CDDL grammar itself is
// checked against (tests/wire/WireContractGuardTest.cpp).
//
// This mirror had no guard of its own. Both Linux desktop applications build
// the same LibreAgent::ClientQt library and share this header, and the only
// test-tree callers of isSettableConfigKey() are the fakes
// (fakes/FakeAgent.cpp, fakes/FakeSocketAgent.cpp), which reject a key using
// that SAME function -- so a mirror that drifts drags the fake along with
// it, and the integration suites built on those fakes stay green regardless.
// This test compares the mirror against the manifest instead of against
// itself.
//
// Checked in BOTH directions on purpose: "every published key is accepted"
// alone misses a SURPLUS in the mirror -- a key this header accepts that the
// manifest never published -- and a surplus is exactly the failure mode the
// fakes above cannot notice, since they only ever probe with real published
// keys.

#include "ConfigKeys.h"

#include <QFile>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

namespace {

// The `settable-config-key` entries out of the committed manifest. The path
// is wired in by CMake (LIBRESCRS_AGENT_WIRE_VOCABULARY_JSON), so this reads
// the real source-tree file -- a copy in the test tree would be a fourth
// mirror, and the one nobody refreshes.
QSet<QString> settableKeysFromManifest()
{
    QFile file(QStringLiteral(LIBRESCRS_AGENT_WIRE_VOCABULARY_JSON));
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    const QJsonObject root = QJsonDocument::fromJson(file.readAll()).object();
    const QJsonObject vocabularies = root.value(QStringLiteral("vocabularies")).toObject();
    const QJsonObject settableConfigKey = vocabularies.value(QStringLiteral("settable-config-key")).toObject();
    const QJsonArray entries = settableConfigKey.value(QStringLiteral("entries")).toArray();

    QSet<QString> keys;
    for (const QJsonValue& entry : entries) {
        keys.insert(entry.toString());
    }
    return keys;
}

// Every key spelling this build NAMES: the settable six plus the read-only
// four, referenced by symbol rather than retyped as string literals, so a
// renamed constant fails this TU to compile instead of silently dropping out
// of the probe set. isSettableConfigKey() has no key spelling to accept
// besides these ten, so a surplus can only ever be one of them wrongly
// admitted -- this is the candidate pool the surplus direction probes.
QSet<QString> allKeysThisBuildNames()
{
    return {
        QString(kConfigDefaultLevel), QString(kConfigDefaultReason), QString(kConfigDefaultLocation),
        QString(kConfigTsaUrls),      QString(kConfigTslSources),    QString(kConfigCscaSources),
        QString(kConfigLastTsaUrl),   QString(kConfigTslCacheDir),   QString(kConfigAiaCacheDir),
        QString(kConfigPluginDir),
    };
}

/// Every key ConfigKeys.h spells, read from the header itself.
///
/// allKeysThisBuildNames() above is hand-written, and a hand-written probe list
/// is the same species of artefact as the mirror it probes: add a constant to
/// the header, forget this list, and the surplus direction quietly stops
/// looking at the new key while still reporting green. Reading the header
/// measures the artefact instead of a copy of it.
///
/// Sets *readable so an unreadable header fails the test rather than passing as
/// "nothing to check" -- the three-state trap an empty result would otherwise
/// hide.
QSet<QString> keysSpelledInTheHeader(bool* readable)
{
    *readable = false;
    QFile header(QStringLiteral(LIBRESCRS_AGENT_CONFIG_KEYS_HEADER));
    if (!header.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }
    *readable = true;

    // The header declares every key in exactly one form:
    //   inline constexpr QLatin1StringView kConfigSomething{"Something"};
    // A form that stops matching empties the result, which the test asserts
    // against, so this fails loudly rather than passing vacuously.
    // A raw string literal here confuses clang-format, which breaks it mid-token,
    // so the pattern is spelled with escapes instead.
    static const QRegularExpression decl(QStringLiteral("kConfig\\w*\\{\"([^\"]+)\"\\}"));

    QSet<QString> found;
    const QString text = QString::fromUtf8(header.readAll());
    auto matches = decl.globalMatch(text);
    while (matches.hasNext()) {
        found.insert(matches.next().captured(1));
    }
    return found;
}

QString joinSorted(const QSet<QString>& keys)
{
    QStringList list(keys.begin(), keys.end());
    list.sort();
    return list.join(QStringLiteral(", "));
}

} // namespace

TEST(ConfigKeyMirrorTest, TheProbeListNamesEveryKeyTheHeaderSpells)
{
    // Guards the guard. The bidirectional test below can only find a surplus
    // among the keys allKeysThisBuildNames() hands it, so a constant added to
    // ConfigKeys.h and forgotten there would go unexamined while everything
    // stayed green -- a smaller copy of the drift this file was written for.
    bool readable = false;
    const QSet<QString> spelled = keysSpelledInTheHeader(&readable);
    ASSERT_TRUE(readable) << "could not read the header at " << LIBRESCRS_AGENT_CONFIG_KEYS_HEADER;
    ASSERT_FALSE(spelled.isEmpty()) << "the header parsed to no keys at all, so the pattern no longer "
                                       "matches how ConfigKeys.h declares them";

    const QSet<QString> probed = allKeysThisBuildNames();
    EXPECT_EQ(joinSorted(spelled - probed), QString()) << "ConfigKeys.h spells a key the probe list does not name";
    EXPECT_EQ(joinSorted(probed - spelled), QString()) << "the probe list names a key ConfigKeys.h does not spell";
}

TEST(ConfigKeyMirrorTest, MatchesThePublishedVocabularyInBothDirections)
{
    const QSet<QString> published = settableKeysFromManifest();
    ASSERT_FALSE(published.isEmpty())
        << "could not read `vocabularies.settable-config-key.entries` from " LIBRESCRS_AGENT_WIRE_VOCABULARY_JSON;

    QSet<QString> mirrored;
    for (const QString& k : allKeysThisBuildNames()) {
        if (isSettableConfigKey(k)) {
            mirrored.insert(k);
        }
    }

    const QSet<QString> missingFromMirror = published - mirrored;
    const QSet<QString> surplusInMirror = mirrored - published;

    EXPECT_TRUE(missingFromMirror.isEmpty()) << "the manifest names a settable key this mirror does not accept: "
                                             << joinSorted(missingFromMirror).toStdString();
    EXPECT_TRUE(surplusInMirror.isEmpty())
        << "this mirror accepts a key the manifest does not publish: " << joinSorted(surplusInMirror).toStdString();
}
