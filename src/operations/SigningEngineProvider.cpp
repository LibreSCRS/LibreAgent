// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStoreService.h>
#include <filesystem>
#include <stdexcept>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

// Map the agent-side (LM-type-free) Config snapshot onto an LM TrustConfig.
// The two-control OS-store trust-anchor split is a later concern; this build
// keeps the LM default (system store included for path material).
LibreSCRS::Trust::TrustConfig buildTrustConfig(const Config::ConfigStore& cfg)
{
    LibreSCRS::Trust::TrustConfig out;
    for (const auto& src : cfg.tslSources()) {
        out.trustedListSources.push_back(
            LibreSCRS::Trust::TrustedListSource{.url = src.url, .lotl = src.isLotl, .eager = src.eager});
    }
    // Pass the cache dir only when it exists: TrustStoreService::create rejects a
    // non-existent cacheDirectory as InvalidConfig, which would null the engine
    // and fail ALL signing (even B-B, which needs no network). Best-effort create;
    // if it cannot be made, omit it and let the engine pick a default rather than
    // fail closed on a missing directory.
    if (const auto dir = cfg.tslCacheDir(); !dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (!ec && std::filesystem::is_directory(dir)) {
            out.cacheDirectory = std::filesystem::path{dir};
        }
    }
    return out;
}

} // namespace

SigningEngineProvider::SigningEngineProvider(Config::ConfigStore& config) : m_config(config)
{
    rebuild();
    // Rebuild on a trust/timestamp-affecting config change only. addChangeObserver
    // is multicast — it does NOT clobber the AgentService->Config1.Changed bridge
    // wired via setOnChanged. DefaultLevel is deliberately NOT a trigger: it is a
    // per-request value resolved at Card1.Sign entry and feeds neither the trust
    // config nor SigningService construction, so it needs no engine rebuild.
    m_config.addChangeObserver([this](const std::string& key) {
        if (key == "TsaUrls" || key == "TslSources") {
            rebuild();
        }
    });
}

SigningEngineProvider::~SigningEngineProvider() = default;

void SigningEngineProvider::rebuild()
{
    auto trustResult = LibreSCRS::Trust::TrustStoreService::create(buildTrustConfig(m_config));
    if (!trustResult) {
        log::warnf("signing engine: trust store unavailable: {}", trustResult.error().userMessage.defaultText);
        std::lock_guard lock(m_mutex);
        m_trust.reset();
        m_engine.reset();
        return;
    }
    auto trust = std::move(*trustResult);
    // Build the TSA provider from the configured URLs. An empty list yields an
    // empty provider (default-constructed std::function): B-B still signs, and a
    // B-T+ request fails closed at LM sign time with a TSA-required error rather
    // than silently degrading. A non-empty list binds the first configured URL
    // (the single-URL realization; a multi-URL fail-over policy is a later
    // concern). staticTsaChecked rejects an obviously malformed URL up-front; the
    // ConfigStore already enforced the http(s) scheme on SetValue, so a throw
    // here is defensive — fall back to an empty provider rather than nulling the
    // whole engine (which would break even B-B signing).
    LibreSCRS::Signing::TsaProvider tsa{};
    std::string boundUrl;
    if (const auto urls = m_config.tsaUrls(); !urls.empty()) {
        try {
            tsa = LibreSCRS::Signing::staticTsaChecked(urls.front());
            boundUrl = urls.front(); // the URL actually baked into this engine
        } catch (const std::invalid_argument& e) {
            log::warnf("signing engine: ignoring invalid TSA URL: {}", e.what());
        }
    }
    auto engine = std::make_shared<LibreSCRS::Signing::SigningService>(trust, std::move(tsa));

    std::lock_guard lock(m_mutex);
    m_trust = std::move(trust);
    m_engine = std::move(engine);
    m_boundTsaUrl = std::move(boundUrl);
}

EngineSnapshot SigningEngineProvider::snapshot() const
{
    std::lock_guard lock(m_mutex);
    return EngineSnapshot{.engine = m_engine, .boundTsaUrl = m_boundTsaUrl};
}

void SigningEngineProvider::recordLastTsaUrlUsed(const std::string& url)
{
    if (!url.empty()) {
        m_config.recordLastTsaUrl(url);
    }
}

} // namespace LibreSCRS::Agent::Operations
