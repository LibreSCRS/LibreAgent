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
// The seeded-sources assertion below reads the configuration the trust store
// was built from, so this one TU needs the full LM Trust header the provider's
// public shared_ptr return type only forward-declares.
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
namespace fs = std::filesystem;

namespace {
fs::path uniqueDir(const char* tag)
{
    return fs::temp_directory_path() / (std::string{"ll-engineprovider-"} + tag);
}

// Counts the connections made to a loopback port. A trusted-list source is
// https, so a fetch reaches this listener as a connection that never gets a
// handshake: each one is accepted and closed at once, which ends that fetch
// immediately instead of leaving it to run into its request timeout.
class LoopbackListener
{
public:
    LoopbackListener()
    {
        m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (m_fd < 0) {
            return;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        socklen_t len = sizeof(addr);
        if (::bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(m_fd, 8) != 0 ||
            ::getsockname(m_fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            return;
        }
        m_port = ntohs(addr.sin_port);
        m_thread = std::jthread([this](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                pollfd pfd{.fd = m_fd, .events = POLLIN, .revents = 0};
                if (::poll(&pfd, 1, 20) > 0) {
                    if (const int client = ::accept(m_fd, nullptr, nullptr); client >= 0) {
                        ::close(client);
                        m_accepted.fetch_add(1);
                    }
                }
            }
        });
    }

    ~LoopbackListener()
    {
        if (m_thread.joinable()) {
            m_thread.request_stop();
            m_thread.join();
        }
        if (m_fd >= 0) {
            ::close(m_fd);
        }
    }

    LoopbackListener(const LoopbackListener&) = delete;
    LoopbackListener& operator=(const LoopbackListener&) = delete;

    [[nodiscard]] bool listening() const
    {
        return m_port != 0;
    }
    [[nodiscard]] std::string url() const
    {
        return "https://127.0.0.1:" + std::to_string(m_port) + "/tl.xml";
    }
    [[nodiscard]] int accepted() const
    {
        return m_accepted.load();
    }

private:
    int m_fd = -1;
    unsigned short m_port = 0;
    std::atomic<int> m_accepted{0};
    std::jthread m_thread;
};
} // namespace

TEST(SigningEngineProvider, EnginePresentWithoutTsa)
{
    const auto dir = uniqueDir("notsa");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    // A fresh store is SEEDED with timestamp authorities, so "no TSA" has to be
    // asked for rather than assumed — a site that cleared the list, or one whose
    // seed never applied.
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{}).ok);
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
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{}).ok); // clear the first-run seed
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

TEST(SigningEngineProvider, SeededTrustedListsAreNotFetchedAtStartup)
{
    // The first-run seed populates TslSources, and building the engine hands that
    // list straight to the trust store. Populating the list is not what opens a
    // socket, though: the per-source `eager` flag is, and it does so at
    // construction, on one worker thread per eager source. Every seeded source is
    // lazy, so a fresh agent must reach its steady state with zero eager sources —
    // no thread, no traffic, nothing to fail on a host that is offline at login.
    // The lists are fetched later, on the first signature that needs them.
    const auto dir = uniqueDir("seedlazy");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    const auto seeded = cfg.tslSources();
    ASSERT_FALSE(seeded.empty()) << "no seeded sources: this test would assert nothing";

    SigningEngineProvider engine{cfg};
    const auto trust = engine.trustSnapshot();
    ASSERT_NE(trust, nullptr);

    // Every seeded source reaches the trust store, and none of them is eager.
    // The seeded hosts are real ones, so this reads the flag rather than the
    // network; that the flag is what decides the startup fetch is watched on
    // the wire by OnlyAnEagerSourceIsContactedAtStartup below.
    const auto& sources = trust->config().trustedListSources;
    ASSERT_EQ(sources.size(), seeded.size()) << "the seeded sources did not reach the trust store";
    for (const auto& source : sources) {
        EXPECT_FALSE(source.eager) << "seeded source " << source.url << " is fetched at startup";
    }
    fs::remove_all(dir);
}

TEST(SigningEngineProvider, OnlyAnEagerSourceIsContactedAtStartup)
{
    // One lazy and one eager source, each on its own loopback listener. The
    // eager source is the stopwatch: its connection proves the startup fetches
    // ran, and a lazy source fetched at startup would be contacted in the same
    // window, by a worker started alongside it.
    LoopbackListener lazy;
    LoopbackListener eager;
    ASSERT_TRUE(lazy.listening() && eager.listening()) << "no loopback listener";

    const auto dir = uniqueDir("startupfetch");
    fs::remove_all(dir);
    Config::ConfigStore cfg{dir / "agent.conf", dir / "cache"};
    ASSERT_TRUE(cfg.setTslSources(std::vector<Config::TslSource>{
                                      {.url = lazy.url(), .isLotl = false, .eager = false},
                                      {.url = eager.url(), .isLotl = false, .eager = true},
                                  })
                    .ok);
    {
        SigningEngineProvider engine{cfg};
        ASSERT_NE(engine.trustSnapshot(), nullptr);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (eager.accepted() == 0 && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        ASSERT_GT(eager.accepted(), 0) << "the eager source was never contacted: this test would assert nothing";
        std::this_thread::sleep_for(std::chrono::milliseconds{200});
        EXPECT_EQ(lazy.accepted(), 0) << "a lazy source was contacted at startup";
    }
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
