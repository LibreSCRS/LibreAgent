// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

using LibreSCRS::Agent::Config::ConfigStore;
using LibreSCRS::Agent::Config::CscaAnchorState;
using LibreSCRS::Agent::Config::CscaSource;
using LibreSCRS::Agent::Config::Mutability;
using LibreSCRS::Agent::Config::TslSource;

namespace {

// Each test gets a fresh temp dir (config file + cache root live under it).
class ConfigStoreTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static std::atomic<unsigned> counter{0};
        m_dir = std::filesystem::temp_directory_path() /
                ("librescrs-cfgtest-" + std::to_string(counter.fetch_add(1)) + "-" +
                 ::testing::UnitTest::GetInstance()->current_test_info()->name());
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        m_configFile = m_dir / "agent.conf";
        m_cacheRoot = m_dir / "cache";
    }
    void TearDown() override
    {
        std::filesystem::remove_all(m_dir);
    }

    void writeConfig(const std::string& contents) const
    {
        std::ofstream out(m_configFile, std::ios::trunc);
        out << contents;
    }

    [[nodiscard]] std::string readConfig() const
    {
        std::ifstream in(m_configFile, std::ios::binary);
        return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_configFile;
    std::filesystem::path m_cacheRoot;
};

// The first-run seed the ctor writes, mirrored from the table in
// ConfigStore.cpp. eager is false for EVERY trusted-list source: a fresh
// installation must not open an outbound connection at startup — the lists are
// fetched lazily, on the first signature that needs them.
const std::vector<std::string> kSeededTsaUrls{
    "https://timestamp.sectigo.com",
    "https://timestamp.digicert.com",
    "https://ts.ssl.com",
};
const std::vector<TslSource> kSeededTslSources{
    TslSource{"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false, false},
    TslSource{"https://ec.europa.eu/tools/lotl/eu-lotl.xml", true, false},
};

TEST_F(ConfigStoreTest, DefaultsWhenNoFile)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.defaultLevel(), "b-b");
    // The two list keys are the exception: with no file on disk they are seeded
    // rather than left empty (see FirstRunSeedIsWrittenToDiskAndSurvivesReload).
    EXPECT_EQ(cfg.tsaUrls(), kSeededTsaUrls);
    EXPECT_EQ(cfg.tslSources(), kSeededTslSources);
    EXPECT_TRUE(cfg.lastTsaUrl().empty());
    EXPECT_TRUE(cfg.pluginDir().empty());
    EXPECT_EQ(cfg.tslCacheDir(), (m_cacheRoot / "tsl").string()); // TSL = Trusted Service List, not "tls"
    EXPECT_EQ(cfg.aiaCacheDir(), (m_cacheRoot / "aia").string());
}

TEST_F(ConfigStoreTest, FirstRunSeedIsWrittenToDiskAndSurvivesReload)
{
    ASSERT_FALSE(std::filesystem::exists(m_configFile)) << "fixture must start with no config file";
    {
        ConfigStore fresh(m_configFile, m_cacheRoot);
        EXPECT_EQ(fresh.tsaUrls(), kSeededTsaUrls);
        EXPECT_EQ(fresh.tslSources(), kSeededTslSources);
        // Half one: the seed must reach the DISK. A seed that only populates the
        // in-memory value set (the applyDefaults-style shortcut) satisfies the two
        // getters above and fails right here.
        EXPECT_TRUE(std::filesystem::exists(m_configFile)) << "the first-run seed never wrote the config file";
    }
    // Half two: loadFromFile CLEARS both list keys before parsing whenever the file
    // exists, so a seed that never reached disk is dropped by the NEXT construction
    // — the first boot looks seeded and every boot after it is silently empty.
    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_EQ(reopened.tsaUrls(), kSeededTsaUrls);
    EXPECT_EQ(reopened.tslSources(), kSeededTslSources);
    // The eager flag is what routes a source into a startup fetch thread; no
    // seeded source carries it, before or after the round trip through the file.
    for (const auto& src : reopened.tslSources()) {
        EXPECT_FALSE(src.eager) << "seeded source " << src.url << " would be fetched at startup";
    }
}

// The seed owns the two list keys and NOTHING else. Persisting the whole value
// set froze the first start's DERIVED answers into the file: a terminal first
// run pinned $HOME/.cache into a config the packaged systemd unit — whose
// CACHE_DIRECTORY names a different, writable-under-ProtectHome root — then
// kept using, and the built-in default level could never change for an
// already-installed agent.
TEST_F(ConfigStoreTest, SeedWritesOnlyTheKeysItOwns)
{
    ASSERT_FALSE(std::filesystem::exists(m_configFile));
    {
        ConfigStore fresh(m_configFile, m_cacheRoot);
    }

    const std::string written = readConfig();
    EXPECT_EQ(written.find("TslCacheDir"), std::string::npos) << "the seed froze a derived cache path into the file:\n"
                                                              << written;
    EXPECT_EQ(written.find("AiaCacheDir"), std::string::npos) << "the seed froze a derived cache path into the file:\n"
                                                              << written;
    EXPECT_EQ(written.find("DefaultLevel"), std::string::npos)
        << "the seed froze the built-in default level into the file:\n"
        << written;

    // The consequence the rule exists for: the same file opened under another
    // cache root must derive that root's paths, not replay the first one's.
    const std::filesystem::path otherRoot = m_dir / "other-cache";
    ConfigStore relocated(m_configFile, otherRoot);
    EXPECT_EQ(relocated.tslCacheDir(), (otherRoot / "tsl").string())
        << "the cache path followed the FIRST start's root instead of this one's";

    // An admin-authored value still wins — the rule is about derived
    // defaults, not about silencing the keys (they are file-only).
    writeConfig(written + "TslCacheDir = " + (m_dir / "chosen").string() + "\n");
    ConfigStore reopened(m_configFile, otherRoot);
    EXPECT_EQ(reopened.tslCacheDir(), (m_dir / "chosen").string());
}

TEST_F(ConfigStoreTest, ExistingConfigWithEmptyListsIsNotReseeded)
{
    // Documentary pin for an accepted limitation: a never-set list and a list an
    // administrator deliberately emptied are INDISTINGUISHABLE — an empty list
    // writes zero lines, and the store has no per-key presence signal. Whole-file
    // existence is therefore the only gate the seed can use, so a config file that
    // exists is taken at its word, empty lists and all.
    writeConfig("DefaultLevel = b-b\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_TRUE(cfg.tsaUrls().empty()) << "an existing config file was re-seeded";
    EXPECT_TRUE(cfg.tslSources().empty()) << "an existing config file was re-seeded";
    // And it stays that way: the store rewrites the file on any mutation, which
    // must not resurrect the seed either.
    EXPECT_TRUE(cfg.setDefaultReason("keeps the file current").ok);
    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_TRUE(reopened.tsaUrls().empty());
    EXPECT_TRUE(reopened.tslSources().empty());
}

TEST_F(ConfigStoreTest, ProvisionedConfigIsLeftByteIdenticalByConstruction)
{
    // A deployment that provisioned its own values (Config1.SetValue, or an
    // administrator editing the file) must not be re-provisioned, merged into or
    // reordered by a later start: construction of a store over an existing file is
    // a pure read.
    {
        ConfigStore provisioning(m_configFile, m_cacheRoot);
        ASSERT_TRUE(provisioning.setTsaUrls(std::vector<std::string>{"https://tsa.example.test/tsr"}).ok);
        const TslSource leaf{"https://tl.example.test/leaf.xml", false, false};
        ASSERT_TRUE(provisioning.setTslSources(std::vector<TslSource>{leaf}).ok);
    }
    const std::string before = readConfig();
    ASSERT_FALSE(before.empty());
    const auto writtenAt = std::filesystem::last_write_time(m_configFile);

    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_EQ(readConfig(), before) << "construction rewrote a provisioned config file";
    EXPECT_EQ(std::filesystem::last_write_time(m_configFile), writtenAt) << "construction touched the config file";
    // The provisioned values are what the store serves — nothing was merged in.
    EXPECT_EQ(reopened.tsaUrls(), std::vector<std::string>{"https://tsa.example.test/tsr"});
    ASSERT_EQ(reopened.tslSources().size(), 1u);
    EXPECT_EQ(reopened.tslSources()[0].url, "https://tl.example.test/leaf.xml");
}

TEST_F(ConfigStoreTest, GarbledFileFallsBackToDefaults)
{
    writeConfig("this is not = = valid\n\xff\xfe garbage\nDefaultLevel\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.defaultLevel(), "b-b"); // never throws; defaults stand
}

TEST_F(ConfigStoreTest, LoadsScalarsAndLists)
{
    writeConfig("# comment\n"
                "DefaultLevel = b-lt\n"
                "TsaUrl = https://tsa.example/a\n"
                "TsaUrl = http://tsa.example/b\n"
                "TslSource = https://tl.example/lotl.xml|lotl|eager\n"
                "TslSource = https://tl.example/leaf.xml\n"
                "DefaultReason = signed via LibreSCRS\n"
                "PluginDir = /opt/librescrs/plugins\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.defaultLevel(), "b-lt");
    ASSERT_EQ(cfg.tsaUrls().size(), 2u);
    EXPECT_EQ(cfg.tsaUrls()[0], "https://tsa.example/a");
    ASSERT_EQ(cfg.tslSources().size(), 2u);
    EXPECT_EQ(cfg.tslSources()[0].url, "https://tl.example/lotl.xml");
    EXPECT_TRUE(cfg.tslSources()[0].isLotl);
    EXPECT_TRUE(cfg.tslSources()[0].eager);
    EXPECT_FALSE(cfg.tslSources()[1].isLotl);
    EXPECT_EQ(cfg.defaultReason(), "signed via LibreSCRS");
    EXPECT_EQ(cfg.pluginDir(), "/opt/librescrs/plugins");
}

TEST_F(ConfigStoreTest, RejectsNonHttpTsaAndBadLevelOnLoad)
{
    writeConfig("DefaultLevel = b-xx\n"
                "TsaUrl = file:///etc/passwd\n"
                "TsaUrl = ftp://nope\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.defaultLevel(), "b-b"); // invalid level ignored
    EXPECT_TRUE(cfg.tsaUrls().empty());   // non-http(s) dropped
}

TEST_F(ConfigStoreTest, SetDefaultLevelValidatesAndPersists)
{
    {
        ConfigStore cfg(m_configFile, m_cacheRoot);
        const auto bad = cfg.setDefaultLevel("nonsense");
        EXPECT_FALSE(bad.ok);
        EXPECT_EQ(bad.errorName, "org.librescrs.Agent.Error.InvalidConfigValue");
        const auto good = cfg.setDefaultLevel("b-lta");
        EXPECT_TRUE(good.ok);
    }
    // A second store over the same file sees the persisted value.
    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_EQ(reopened.defaultLevel(), "b-lta");
}

TEST_F(ConfigStoreTest, SetTsaUrlsValidatesAndPersists)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    ASSERT_TRUE(cfg.setTsaUrls({}).ok); // drop the first-run seed; this test is about the validator
    EXPECT_FALSE(cfg.setTsaUrls({"https://ok", "ftp://bad"}).ok);
    EXPECT_TRUE(cfg.tsaUrls().empty()); // rejected wholesale; nothing applied
    EXPECT_TRUE(cfg.setTsaUrls({"https://a", "http://b"}).ok);
    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_EQ(reopened.tsaUrls().size(), 2u);
}

TEST_F(ConfigStoreTest, RejectsSchemeOnlyTsaUrl)
{
    // A scheme-only URL ('http://' / 'https://' with no authority) is malformed:
    // it would pass the old prefix-only check, make tsaUrls() non-empty, and so
    // auto-upgrade the default level to b-t — yet the engine cannot build a TSA
    // provider from it, silently failing every default sign closed. The validator
    // must reject it so the default never upgrades.
    ConfigStore cfg(m_configFile, m_cacheRoot);
    ASSERT_TRUE(cfg.setTsaUrls({}).ok); // drop the first-run seed; this test is about the validator
    EXPECT_FALSE(cfg.setTsaUrls({"http://"}).ok);
    EXPECT_TRUE(cfg.tsaUrls().empty()) << "scheme-only http:// must not be stored";
    EXPECT_FALSE(cfg.setTsaUrls({"https://"}).ok);
    EXPECT_TRUE(cfg.tsaUrls().empty()) << "scheme-only https:// must not be stored";
    // A leading slash after the scheme is not an authority either.
    EXPECT_FALSE(cfg.setTsaUrls({"http:///path"}).ok);
    EXPECT_TRUE(cfg.tsaUrls().empty());
    // A real authority (host, host:port, host/path) stays accepted (regression).
    EXPECT_TRUE(cfg.setTsaUrls({"https://tsa.example.test/tsr", "http://h:8080/x"}).ok);
    EXPECT_EQ(cfg.tsaUrls().size(), 2u);
}

TEST_F(ConfigStoreTest, SchemeOnlyTsaUrlDroppedOnLoad)
{
    // The file-load path uses the same validator; a scheme-only entry is dropped,
    // so a TSA-configured-by-typo site does not auto-upgrade the default to b-t.
    writeConfig("TsaUrl = http://\n"
                "TsaUrl = https://\n"
                "TsaUrl = https://good.example/tsr\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    ASSERT_EQ(cfg.tsaUrls().size(), 1u) << "only the URL with an authority survives";
    EXPECT_EQ(cfg.tsaUrls()[0], "https://good.example/tsr");
}

TEST_F(ConfigStoreTest, TslSourcesRoundTrip)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    ASSERT_TRUE(cfg.setTslSources({}).ok); // drop the first-run seed; this test is about the validator
    // Non-http(s) entries are rejected wholesale (symmetric to TsaUrls).
    EXPECT_FALSE(cfg.setTslSources({TslSource{"ftp://bad", false, false}}).ok);
    EXPECT_TRUE(cfg.tslSources().empty());
    EXPECT_TRUE(cfg.setTslSources({TslSource{"https://x/lotl", true, true}, TslSource{"https://y", false, false}}).ok);
    ConfigStore reopened(m_configFile, m_cacheRoot);
    ASSERT_EQ(reopened.tslSources().size(), 2u);
    EXPECT_EQ(reopened.tslSources()[0].url, "https://x/lotl");
    EXPECT_TRUE(reopened.tslSources()[0].isLotl);
    EXPECT_TRUE(reopened.tslSources()[0].eager);
    EXPECT_FALSE(reopened.tslSources()[1].isLotl);
}

// The country-signing anchor sources follow TslSource's file grammar exactly:
// a SINGULAR key repeated once per source, fields pipe-delimited. What differs
// is the field count -- `uri[|eager]`, with no isLotl equivalent, because
// nothing in the CSCA world nests one source inside another.
TEST_F(ConfigStoreTest, CscaSourcesLoadFromFile)
{
    writeConfig("CscaSource = https://pkd.example.test/anchors.ldif\n"
                "CscaSource = https://masterlist.example.test/ml.der|eager\n"
                "CscaSource = ftp://rejected.example.test/ml.der\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    ASSERT_EQ(cfg.cscaSources().size(), 2u) << "only http(s) sources survive the load";
    EXPECT_EQ(cfg.cscaSources()[0].uri, "https://pkd.example.test/anchors.ldif");
    EXPECT_FALSE(cfg.cscaSources()[0].eager) << "eager is opt-in per source, never the default";
    EXPECT_EQ(cfg.cscaSources()[1].uri, "https://masterlist.example.test/ml.der");
    EXPECT_TRUE(cfg.cscaSources()[1].eager);
}

TEST_F(ConfigStoreTest, CscaSourcesRoundTrip)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    // Symmetric to TslSources: a non-http(s) entry rejects the whole write.
    EXPECT_FALSE(cfg.setCscaSources({CscaSource{"ftp://bad", false}}).ok);
    EXPECT_TRUE(cfg.cscaSources().empty());
    EXPECT_TRUE(cfg.setCscaSources({CscaSource{"https://a.example.test/ml.der", true},
                                    CscaSource{"https://b.example.test/anchors.ldif", false}})
                    .ok);
    ConfigStore reopened(m_configFile, m_cacheRoot);
    ASSERT_EQ(reopened.cscaSources().size(), 2u) << "the write did not survive persist + reload";
    EXPECT_EQ(reopened.cscaSources()[0].uri, "https://a.example.test/ml.der");
    EXPECT_TRUE(reopened.cscaSources()[0].eager);
    EXPECT_EQ(reopened.cscaSources()[1].uri, "https://b.example.test/anchors.ldif");
    EXPECT_FALSE(reopened.cscaSources()[1].eager);
}

TEST_F(ConfigStoreTest, CscaCacheDirIsFileOnlyAndDerivedFromTheCacheRoot)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.cscaCacheDir(), (m_cacheRoot / "csca").string());
    // Derived, never frozen: the same file under a different cache root derives
    // that root's path (the rule SeedWritesOnlyTheKeysItOwns pins for the other
    // two cache dirs).
    ASSERT_TRUE(cfg.setDefaultReason("force a persist").ok);
    EXPECT_EQ(readConfig().find("CscaCacheDir"), std::string::npos)
        << "a derived cache path was frozen into the file:\n"
        << readConfig();

    // The ONLY way to choose it is the config file itself: it is FileOnly, so
    // there is no typed setter for it at all and no D-Bus path can reach it.
    const std::filesystem::path chosen = m_dir / "anchors";
    writeConfig("CscaCacheDir = " + chosen.string() + "\n");
    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_EQ(reopened.cscaCacheDir(), chosen.string());
}

TEST_F(ConfigStoreTest, MutabilityMetadata)
{
    EXPECT_EQ(ConfigStore::mutability("DefaultLevel"), Mutability::DbusMutable);
    EXPECT_EQ(ConfigStore::mutability("DefaultReason"), Mutability::DbusMutable);
    EXPECT_EQ(ConfigStore::mutability("TsaUrls"), Mutability::DbusMutableTrust);
    EXPECT_EQ(ConfigStore::mutability("TslSources"), Mutability::DbusMutableTrust);
    // The country-signing anchor sources are trust-tier settable, exactly like
    // the trusted lists: both decide what a signature is validated AGAINST.
    EXPECT_EQ(ConfigStore::mutability("CscaSources"), Mutability::DbusMutableTrust);
    EXPECT_EQ(ConfigStore::mutability("PluginDir"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("TslCacheDir"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("AiaCacheDir"), Mutability::FileOnly);
    // The anchor cache is a writable path the agent unpacks downloaded material
    // into: a wire-settable one would let any authorized client redirect those
    // writes, so it may only ever be chosen by editing the config file.
    EXPECT_EQ(ConfigStore::mutability("CscaCacheDir"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("LastTsaUrl"), Mutability::ReadOnly);
    // What the agent HOLDS in country-signing anchors is a report, not a
    // setting: read-only for the same reason LastTsaUrl is, and for a stronger
    // one — a client that could write it would be claiming what the agent
    // trusts without installing a single anchor.
    EXPECT_EQ(ConfigStore::mutability("CscaAnchorState"), Mutability::ReadOnly);
    // PKCS#11 lease knobs are FileOnly security policy (not D-Bus mutable).
    EXPECT_EQ(ConfigStore::mutability("Pkcs11IdleTimeoutSecs"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("Pkcs11MaxLifetimeSecs"), Mutability::FileOnly);
    // Pkcs11DecryptConfirm was removed (it was a no-op security toggle): the
    // prompter has no confirm-only primitive to back it.
    EXPECT_FALSE(ConfigStore::mutability("Pkcs11DecryptConfirm").has_value());
    EXPECT_FALSE(ConfigStore::mutability("Nope").has_value());
    EXPECT_EQ(ConfigStore::keys().size(), 14u);
}

TEST_F(ConfigStoreTest, Pkcs11LeaseKnobsDefaultsAndRoundTrip)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    // Built-in defaults.
    EXPECT_EQ(cfg.pkcs11IdleTimeoutSecs(), 600u);
    EXPECT_EQ(cfg.pkcs11MaxLifetimeSecs(), 28800u);
}

TEST_F(ConfigStoreTest, Pkcs11LeaseKnobsLoadFromFile)
{
    writeConfig("Pkcs11IdleTimeoutSecs = 120\n"
                "Pkcs11MaxLifetimeSecs = 0\n");
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.pkcs11IdleTimeoutSecs(), 120u);
    EXPECT_EQ(cfg.pkcs11MaxLifetimeSecs(), 0u); // 0 => no hard cap
    // A bad value is ignored (default stands), not fatal.
    writeConfig("Pkcs11IdleTimeoutSecs = notanumber\n");
    ConfigStore cfg2(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg2.pkcs11IdleTimeoutSecs(), 600u);
}

TEST_F(ConfigStoreTest, ResetHonorsMutabilityFromDbus)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    // FileOnly + ReadOnly keys are not resettable over D-Bus.
    EXPECT_EQ(cfg.resetKey("PluginDir", /*fromDbus=*/true).errorName, "org.librescrs.Agent.Error.ReadOnlyConfig");
    EXPECT_EQ(cfg.resetKey("LastTsaUrl", /*fromDbus=*/true).errorName, "org.librescrs.Agent.Error.ReadOnlyConfig");
    EXPECT_EQ(cfg.resetKey("Bogus", /*fromDbus=*/true).errorName, "org.librescrs.Agent.Error.UnknownConfigKey");
    // A D-Bus-mutable key resets fine.
    cfg.setDefaultLevel("b-lta");
    EXPECT_TRUE(cfg.resetKey("DefaultLevel", /*fromDbus=*/true).ok);
    EXPECT_EQ(cfg.defaultLevel(), "b-b");
    // The file-load path (fromDbus=false) may reset any key.
    EXPECT_TRUE(cfg.resetKey("PluginDir", /*fromDbus=*/false).ok);
}

TEST_F(ConfigStoreTest, RecordLastTsaUrlIsReadOnlyButAgentSettable)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    cfg.recordLastTsaUrl("https://tsa.example/used");
    EXPECT_EQ(cfg.lastTsaUrl(), "https://tsa.example/used");
    ConfigStore reopened(m_configFile, m_cacheRoot);
    EXPECT_EQ(reopened.lastTsaUrl(), "https://tsa.example/used");
}

TEST_F(ConfigStoreTest, CscaAnchorStateStartsAbsentAndIsAgentRecorded)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    // Never imported: ABSENT, not a zero-valued report. A store that answered
    // "0 anchors, refusal inactive" would be indistinguishable from one that
    // had accepted an empty list, and the two mean opposite things.
    EXPECT_FALSE(cfg.cscaAnchorState().has_value());

    CscaAnchorState state;
    state.anchors = 212;
    state.issuers = 47;
    state.replayRefusalActive = true;
    state.signer = "9c1f5c7b2f4b4d6f8a0e3d5c7b9a1f3e5d7c9b1a3f5e7d9c1b3a5f7e9d1c3b5a";
    state.signerPinned = true;
    state.acceptedAt = 1756000000;
    state.signedAt = 1755000000;
    state.origin = "import";
    cfg.recordCscaAnchorState(state);
    ASSERT_TRUE(cfg.cscaAnchorState().has_value());
    EXPECT_EQ(*cfg.cscaAnchorState(), state);

    // Survives a restart: a client that has just STARTED is exactly the caller
    // this key exists for, and it reads the store the agent reopened.
    ConfigStore reopened(m_configFile, m_cacheRoot);
    ASSERT_TRUE(reopened.cscaAnchorState().has_value());
    EXPECT_EQ(*reopened.cscaAnchorState(), state);
}

TEST_F(ConfigStoreTest, CscaAnchorStateAbsentSignedAtIsNeverPersistedAsZero)
{
    // The whole reason signedAt is optional: a list signed at the epoch and a
    // list carrying no CMS signingTime at all must not read alike. A zero
    // stand-in on disk would erase that on the very next start, and
    // replayRefusalActive's false is what a person is shown because of it.
    CscaAnchorState undated;
    undated.anchors = 3;
    undated.issuers = 1;
    undated.replayRefusalActive = false;
    undated.acceptedAt = 1756000001;
    undated.origin = "import";

    {
        ConfigStore cfg(m_configFile, m_cacheRoot);
        cfg.recordCscaAnchorState(undated);
    }
    EXPECT_EQ(readConfig().find("signedAt"), std::string::npos) << readConfig();

    ConfigStore reopened(m_configFile, m_cacheRoot);
    ASSERT_TRUE(reopened.cscaAnchorState().has_value());
    EXPECT_FALSE(reopened.cscaAnchorState()->signedAt.has_value());
    EXPECT_EQ(reopened.cscaAnchorState()->acceptedAt, 1756000001);
    EXPECT_FALSE(reopened.cscaAnchorState()->replayRefusalActive);

    // An epoch-dated list is a DIFFERENT report, and reads back as one.
    CscaAnchorState epochDated = undated;
    epochDated.signedAt = 0;
    reopened.recordCscaAnchorState(epochDated);
    ConfigStore again(m_configFile, m_cacheRoot);
    ASSERT_TRUE(again.cscaAnchorState().has_value());
    ASSERT_TRUE(again.cscaAnchorState()->signedAt.has_value());
    EXPECT_EQ(*again.cscaAnchorState()->signedAt, 0);
}

TEST_F(ConfigStoreTest, CscaAnchorStateIsNotResettableOverDbus)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    CscaAnchorState state;
    state.anchors = 1;
    cfg.recordCscaAnchorState(state);
    EXPECT_EQ(cfg.resetKey("CscaAnchorState", /*fromDbus=*/true).errorName, "org.librescrs.Agent.Error.ReadOnlyConfig");
    EXPECT_TRUE(cfg.cscaAnchorState().has_value()) << "a refused reset must change nothing";
    // The file-load path may reset it, exactly as it may reset LastTsaUrl.
    EXPECT_TRUE(cfg.resetKey("CscaAnchorState", /*fromDbus=*/false).ok);
    EXPECT_FALSE(cfg.cscaAnchorState().has_value());
}

TEST_F(ConfigStoreTest, RecordCscaAnchorStateFiresOnceAndNoOpsOnAnIdenticalReport)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    std::string changed;
    int hits = 0;
    cfg.setOnChanged([&](const std::string& k) {
        changed = k;
        ++hits;
    });
    CscaAnchorState state;
    state.anchors = 9;
    state.issuers = 4;
    cfg.recordCscaAnchorState(state);
    EXPECT_EQ(changed, "CscaAnchorState");
    EXPECT_EQ(hits, 1);
    cfg.recordCscaAnchorState(state); // same report -> no persist, no Changed
    EXPECT_EQ(hits, 1);
}

TEST_F(ConfigStoreTest, OnChangedFiresWithKey)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    std::string changed;
    cfg.setOnChanged([&](const std::string& k) { changed = k; });
    cfg.setDefaultLevel("b-t");
    EXPECT_EQ(changed, "DefaultLevel");
    changed.clear();
    cfg.setTsaUrls({"https://a"});
    EXPECT_EQ(changed, "TsaUrls");
    changed.clear();
    cfg.recordLastTsaUrl("https://a"); // distinct from the default empty -> fires
    EXPECT_EQ(changed, "LastTsaUrl");
}

TEST_F(ConfigStoreTest, RecordLastTsaUrlNoOpDoesNotFire)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    cfg.recordLastTsaUrl("https://a");
    int hits = 0;
    cfg.setOnChanged([&](const std::string&) { ++hits; });
    cfg.recordLastTsaUrl("https://a"); // same value -> no persist, no Changed
    EXPECT_EQ(hits, 0);
}

TEST_F(ConfigStoreTest, RemovedChangeObserverStopsFiring)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    int first = 0;
    int second = 0;
    const auto firstId = cfg.addChangeObserver([&](const std::string&) { ++first; });
    const auto secondId = cfg.addChangeObserver([&](const std::string&) { ++second; });
    ASSERT_NE(firstId, secondId);
    cfg.setDefaultReason("one");
    EXPECT_EQ(first, 1);
    EXPECT_EQ(second, 1);

    cfg.removeChangeObserver(firstId);
    cfg.setDefaultReason("two");
    EXPECT_EQ(first, 1) << "removed observer still fired";
    EXPECT_EQ(second, 2) << "removing one observer disturbed another";

    // Double-remove and a default-constructed sentinel are harmless no-ops.
    cfg.removeChangeObserver(firstId);
    cfg.removeChangeObserver(ConfigStore::ObserverId{});
    cfg.setDefaultReason("three");
    EXPECT_EQ(second, 3);
}

TEST_F(ConfigStoreTest, RemoveChangeObserverDrainsInFlightCallback)
{
    // removeChangeObserver blocks until an in-flight notification pass has
    // completed: after it returns, the removed callback is not running and
    // never runs again. That drain is what lets an observer's owner (the
    // SigningEngineProvider dtor) destroy the callback's captured state
    // immediately after unregistering, even if a mutation races the teardown.
    ConfigStore cfg(m_configFile, m_cacheRoot);
    std::atomic<bool> inCallback{false};
    std::atomic<bool> release{false};
    std::atomic<bool> removeReturned{false};
    bool removeReturnedWhileRunning = false;
    const auto id = cfg.addChangeObserver([&](const std::string&) {
        inCallback = true;
        while (!release) {
            std::this_thread::yield(); // hold the notification pass in flight
        }
        // Still inside the callback: a drained remove cannot have returned yet.
        removeReturnedWhileRunning = removeReturned;
    });

    std::thread mutator([&] { cfg.setDefaultReason("held"); });
    while (!inCallback) {
        std::this_thread::yield();
    }
    std::thread remover([&] {
        cfg.removeChangeObserver(id);
        removeReturned = true;
    });
    // Give a (buggy) non-blocking remove ample time to return while the
    // callback is still held in flight, then let the callback finish. The
    // correct implementation keeps the remover blocked for the whole window,
    // so the in-callback observation is deterministic, never timing-flaky.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    release = true;
    remover.join();
    mutator.join();
    EXPECT_FALSE(removeReturnedWhileRunning) << "removeChangeObserver returned while the callback was in flight";
}

} // namespace
