// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Card-free coverage for SigningEngineProvider's TSA wiring. The engine builds a
// LibreSCRS::Signing::SigningService from the current ConfigStore snapshot and
// rebuilds it on a TsaUrls change; this pins that the new URL-reading branch
// (empty -> a real provider) keeps the engine present across every transition,
// so B-B never breaks and a malformed/absent TSA never nulls the whole engine.
//
// NOTE: SigningService's TSA configuration is immutable and not publicly
// observable, so "a real TsaProvider is present" is not assertable through the
// seam without leaking LM Signing types into the test (the seam-boundary
// invariant). The truthful end-to-end coverage of a configured TSA lives in the
// SignFlow FakeSigner tests (tsaUsed derivation) and the env-gated HW smoke.
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>

#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
namespace fs = std::filesystem;

namespace {
fs::path uniqueDir(const char* tag)
{
    return fs::temp_directory_path() / (std::string{"ll-engineprovider-"} + tag);
}
} // namespace

TEST(SigningEngineProvider, EnginePresentWithoutTsa)
{
    const auto dir = uniqueDir("notsa");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    SigningEngineProvider engine{cfg};
    // No TSA configured: B-B must still sign, so the engine is present.
    EXPECT_NE(engine.snapshot().engine, nullptr);
    fs::remove_all(dir);
}

TEST(SigningEngineProvider, EnginePresentWithConfiguredTsaAndAcrossRebuild)
{
    const auto dir = uniqueDir("tsa");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    SigningEngineProvider engine{cfg};
    ASSERT_NE(engine.snapshot().engine, nullptr);

    // Configuring a TSA fires Changed("TsaUrls"), which the provider observes and
    // rebuilds on — exercising the new staticTsaChecked branch. The engine must
    // stay present (a thrown/ignored URL must never null it and break B-B).
    const auto set = cfg.setTsaUrls(std::vector<std::string>{"https://tsa.example.test/tsr"});
    ASSERT_TRUE(set.ok) << set.message;
    EXPECT_NE(engine.snapshot().engine, nullptr) << "engine nulled after a TSA was configured";

    // Resetting back to no TSA rebuilds again; still present.
    const auto reset = cfg.setTsaUrls(std::vector<std::string>{});
    ASSERT_TRUE(reset.ok) << reset.message;
    EXPECT_NE(engine.snapshot().engine, nullptr);
    fs::remove_all(dir);
}

TEST(SigningEngineProvider, BoundTsaUrlTracksTheUrlList)
{
    const auto dir = uniqueDir("hastsa");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    SigningEngineProvider engine{cfg};
    EXPECT_TRUE(engine.snapshot().boundTsaUrl.empty());
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{"https://tsa.example.test/tsr"}).ok);
    EXPECT_EQ(engine.snapshot().boundTsaUrl, "https://tsa.example.test/tsr");
    fs::remove_all(dir);
}

TEST(SigningEngineProvider, CapturedSnapshotBoundUrlIsImmuneToLaterConfigChange)
{
    // The bound TSA URL must be captured atomically WITH the engine snapshot so an
    // in-flight sign derives tsaUsed and records LastTsaUrl from the engine it
    // actually used — not from the live ConfigStore, which a concurrent admin
    // setTsaUrls could mutate mid-sign (a metadata TOCTOU). A snapshot taken now
    // must keep its bound URL even after the config changes.
    const auto dir = uniqueDir("boundurl");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    SigningEngineProvider engine{cfg};

    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{"https://tsa-one.example.test/tsr"}).ok);
    const auto first = engine.snapshot();
    ASSERT_NE(first.engine, nullptr);
    EXPECT_EQ(first.boundTsaUrl, "https://tsa-one.example.test/tsr");

    // A concurrent admin reconfigures the TSA; the already-captured snapshot must
    // NOT observe the change (it bound the first URL atomically with the engine).
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{"https://tsa-two.example.test/tsr"}).ok);
    EXPECT_EQ(first.boundTsaUrl, "https://tsa-one.example.test/tsr") << "captured bound URL re-read the live config";

    // Recording from the (stale) captured snapshot writes the URL THIS sign used —
    // not the live config the concurrent admin just changed. Re-reading live here
    // (the old no-arg recordLastTsaUrlUsed) would wrongly record tsa-two.
    engine.recordLastTsaUrlUsed(first.boundTsaUrl);
    EXPECT_EQ(cfg.lastTsaUrl(), "https://tsa-one.example.test/tsr")
        << "LastTsaUrl recorded a URL the sign never contacted (live re-read)";

    // A fresh snapshot reflects the new binding.
    const auto second = engine.snapshot();
    EXPECT_EQ(second.boundTsaUrl, "https://tsa-two.example.test/tsr");

    // No TSA configured -> the bound URL is empty (B-B only; nothing to contact).
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{}).ok);
    const auto third = engine.snapshot();
    ASSERT_NE(third.engine, nullptr);
    EXPECT_TRUE(third.boundTsaUrl.empty());
    fs::remove_all(dir);
}

TEST(SigningEngineProvider, DestroyedProviderStopsObservingConfigChanges)
{
    // The ctor registers a [this] change observer on the ConfigStore; the dtor
    // must unregister it. The ConfigStore here deliberately OUTLIVES the
    // provider (the AgentCore ordering), so a leaked registration is still
    // reachable: mutating an observed key after destruction would invoke the
    // dead provider's rebuild callback — a stack-use-after-scope under ASan, a
    // destroyed-mutex lock otherwise.
    const auto dir = uniqueDir("dtor");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    {
        SigningEngineProvider engine{cfg};
        ASSERT_NE(engine.snapshot().engine, nullptr);
    } // provider destroyed; its observer registration must be gone
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{"https://tsa.example.test/tsr"}).ok);
    ASSERT_TRUE(cfg.setTslSources(std::vector<Config::TslSource>{
                                      {.url = "https://tl.example.test/lotl.xml", .isLotl = true, .eager = false}})
                    .ok);
    fs::remove_all(dir);
}

TEST(SigningEngineProvider, RecordLastTsaUrlUsedWritesTheConfiguredUrl)
{
    const auto dir = uniqueDir("lasttsa");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    SigningEngineProvider engine{cfg};

    // An empty captured URL -> recording is a no-op (nothing was contacted).
    engine.recordLastTsaUrlUsed("");
    EXPECT_EQ(cfg.lastTsaUrl(), "");

    // A successful timestamped sign records the captured bound URL of the snapshot
    // it used (not the live config, which a concurrent reconfigure could change).
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{"https://tsa.example.test/tsr"}).ok);
    engine.recordLastTsaUrlUsed(engine.snapshot().boundTsaUrl);
    EXPECT_EQ(cfg.lastTsaUrl(), "https://tsa.example.test/tsr");
    fs::remove_all(dir);
}
