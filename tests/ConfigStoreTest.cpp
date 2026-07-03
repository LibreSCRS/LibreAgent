// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

using LibreSCRS::Agent::Config::ConfigStore;
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

    std::filesystem::path m_dir;
    std::filesystem::path m_configFile;
    std::filesystem::path m_cacheRoot;
};

TEST_F(ConfigStoreTest, DefaultsWhenNoFile)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    EXPECT_EQ(cfg.defaultLevel(), "b-b");
    EXPECT_TRUE(cfg.tsaUrls().empty());
    EXPECT_TRUE(cfg.tslSources().empty());
    EXPECT_TRUE(cfg.lastTsaUrl().empty());
    EXPECT_TRUE(cfg.pluginDir().empty());
    EXPECT_EQ(cfg.tslCacheDir(), (m_cacheRoot / "tsl").string()); // TSL = Trusted Service List, not "tls"
    EXPECT_EQ(cfg.aiaCacheDir(), (m_cacheRoot / "aia").string());
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

TEST_F(ConfigStoreTest, MutabilityMetadata)
{
    EXPECT_EQ(ConfigStore::mutability("DefaultLevel"), Mutability::DbusMutable);
    EXPECT_EQ(ConfigStore::mutability("DefaultReason"), Mutability::DbusMutable);
    EXPECT_EQ(ConfigStore::mutability("TsaUrls"), Mutability::DbusMutableTrust);
    EXPECT_EQ(ConfigStore::mutability("TslSources"), Mutability::DbusMutableTrust);
    EXPECT_EQ(ConfigStore::mutability("PluginDir"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("TslCacheDir"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("AiaCacheDir"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("LastTsaUrl"), Mutability::ReadOnly);
    // PKCS#11 lease knobs are FileOnly security policy (not D-Bus mutable).
    EXPECT_EQ(ConfigStore::mutability("Pkcs11IdleTimeoutSecs"), Mutability::FileOnly);
    EXPECT_EQ(ConfigStore::mutability("Pkcs11MaxLifetimeSecs"), Mutability::FileOnly);
    // Pkcs11DecryptConfirm was removed (it was a no-op security toggle): the
    // prompter has no confirm-only primitive to back it.
    EXPECT_FALSE(ConfigStore::mutability("Pkcs11DecryptConfirm").has_value());
    EXPECT_FALSE(ConfigStore::mutability("Nope").has_value());
    EXPECT_EQ(ConfigStore::keys().size(), 11u);
}

TEST_F(ConfigStoreTest, Pkcs11LeaseKnobsDefaultsAndRoundTrip)
{
    ConfigStore cfg(m_configFile, m_cacheRoot);
    // Spec defaults.
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

} // namespace
