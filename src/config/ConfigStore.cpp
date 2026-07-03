// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <array>
#include <charconv>
#include <fstream>
#include <optional>
#include <sstream>
#include <system_error>
#include <utility>

namespace LibreSCRS::Agent::Config {

namespace {

// Frozen key strings (single source of truth; mirrors the Config1 wire
// property names 1:1, spec §3.4).
constexpr const char* kDefaultLevel = "DefaultLevel";
constexpr const char* kTsaUrls = "TsaUrls";
constexpr const char* kLastTsaUrl = "LastTsaUrl";
constexpr const char* kTslSources = "TslSources";
constexpr const char* kTslCacheDir = "TslCacheDir";
constexpr const char* kAiaCacheDir = "AiaCacheDir";
constexpr const char* kDefaultReason = "DefaultReason";
constexpr const char* kDefaultLocation = "DefaultLocation";
constexpr const char* kPluginDir = "PluginDir";
constexpr const char* kPkcs11IdleTimeoutSecs = "Pkcs11IdleTimeoutSecs";
constexpr const char* kPkcs11MaxLifetimeSecs = "Pkcs11MaxLifetimeSecs";

// PKCS#11 lease-knob built-in defaults (spec §5): idle 10 min, max lifetime
// 8 h. Single source of truth for applyDefaults + resetKey so the two cannot
// drift.
constexpr std::uint32_t kPkcs11IdleDefault = 600;
constexpr std::uint32_t kPkcs11MaxLifetimeDefault = 28800;

// D-Bus error names surfaced by a rejected SetValue/Reset (spec §3.5).
constexpr const char* kErrReadOnly = "org.librescrs.Agent.Error.ReadOnlyConfig";
constexpr const char* kErrUnknownKey = "org.librescrs.Agent.Error.UnknownConfigKey";
constexpr const char* kErrInvalidValue = "org.librescrs.Agent.Error.InvalidConfigValue";

// Cache subdirectory names under the cache root. "tsl" = ETSI Trusted Service
// List (NOT "tls" — that would be Transport Layer Security); "aia" = the AIA
// caIssuers cert cache. Single source of truth so applyDefaults() and
// resetKey() cannot drift.
constexpr const char* kTslSubdir = "tsl";
constexpr const char* kAiaSubdir = "aia";

std::string trim(std::string_view s)
{
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = s.find_last_not_of(" \t\r\n");
    return std::string{s.substr(first, last - first + 1)};
}

std::optional<std::uint32_t> parseU32(std::string_view s)
{
    std::uint32_t out{};
    const auto* begin = s.data();
    const auto* end = s.data() + s.size();
    const auto [ptr, ec] = std::from_chars(begin, end, out);
    if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
    }
    return out;
}

bool isHttpUrl(std::string_view url)
{
    // Require an http(s) scheme AND a non-empty authority after it. A scheme-only
    // "http://" (or one whose authority starts with '/', i.e. an empty host) would
    // pass a bare prefix check, make the TSA list non-empty, and auto-upgrade the
    // default level to b-t — yet the engine cannot build a provider from it, so
    // every default sign would silently fail closed. Reject it here (mirrors the
    // LM staticTsaChecked rejection) so the default never upgrades on a typo.
    std::string_view authority;
    if (url.starts_with("http://")) {
        authority = url.substr(std::string_view{"http://"}.size());
    } else if (url.starts_with("https://")) {
        authority = url.substr(std::string_view{"https://"}.size());
    } else {
        return false;
    }
    return !authority.empty() && authority.front() != '/';
}

bool isKnownLevel(std::string_view level)
{
    return level == "b-b" || level == "b-t" || level == "b-lt" || level == "b-lta";
}

} // namespace

ConfigStore::ConfigStore(std::filesystem::path configFile, std::filesystem::path cacheRoot)
    : m_configFile(std::move(configFile)), m_cacheRoot(std::move(cacheRoot))
{
    applyDefaults();
    loadFromFile();
}

void ConfigStore::applyDefaults()
{
    m_defaultLevel = "b-b"; // derived to "b-t" by the consumer when a TSA is set
    m_tsaUrls.clear();
    m_lastTsaUrl.clear();
    m_tslSources.clear();
    m_tslCacheDir = (m_cacheRoot / kTslSubdir).string();
    m_aiaCacheDir = (m_cacheRoot / kAiaSubdir).string();
    m_defaultReason.clear();
    m_defaultLocation.clear();
    m_pluginDir.clear(); // empty => consumer uses the compiled default plugin dir
    m_pkcs11IdleTimeoutSecs = kPkcs11IdleDefault;
    m_pkcs11MaxLifetimeSecs = kPkcs11MaxLifetimeDefault;
}

void ConfigStore::loadFromFile()
{
    std::error_code ec;
    if (!std::filesystem::exists(m_configFile, ec) || ec) {
        return; // no file yet — defaults stand
    }
    std::ifstream in(m_configFile);
    if (!in) {
        log::warnf("config: cannot open {}; using defaults", m_configFile.string());
        return;
    }
    // List keys (TsaUrl/TslSource) accumulate across repeated lines. Clear them
    // here so the file fully REPLACES (never appends to) whatever applyDefaults
    // seeded — correct even if a future default list becomes non-empty.
    m_tsaUrls.clear();
    m_tslSources.clear();
    std::string line;
    while (std::getline(in, line)) {
        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#') {
            continue;
        }
        const auto eq = trimmed.find('=');
        if (eq == std::string::npos) {
            log::warnf("config: ignoring malformed line: {}", trimmed);
            continue;
        }
        const std::string key = trim(trimmed.substr(0, eq));
        const std::string value = trim(trimmed.substr(eq + 1));
        if (key == kDefaultLevel) {
            if (isKnownLevel(value)) {
                m_defaultLevel = value;
            } else {
                log::warnf("config: ignoring invalid DefaultLevel '{}'", value);
            }
        } else if (key == "TsaUrl") { // singular, repeated
            if (isHttpUrl(value)) {
                m_tsaUrls.push_back(value);
            }
        } else if (key == kLastTsaUrl) {
            m_lastTsaUrl = value;
        } else if (key == "TslSource") { // singular, repeated: url[|lotl][|eager]
            std::stringstream ss(value);
            std::string field;
            TslSource src;
            bool first = true;
            while (std::getline(ss, field, '|')) {
                if (first) {
                    src.url = field;
                    first = false;
                } else if (field == "lotl") {
                    src.isLotl = true;
                } else if (field == "eager") {
                    src.eager = true;
                }
            }
            if (isHttpUrl(src.url)) {
                m_tslSources.push_back(std::move(src));
            }
        } else if (key == kTslCacheDir) {
            if (!value.empty()) {
                m_tslCacheDir = value;
            }
        } else if (key == kAiaCacheDir) {
            if (!value.empty()) {
                m_aiaCacheDir = value;
            }
        } else if (key == kDefaultReason) {
            m_defaultReason = value;
        } else if (key == kDefaultLocation) {
            m_defaultLocation = value;
        } else if (key == kPluginDir) {
            m_pluginDir = value;
        } else if (key == kPkcs11IdleTimeoutSecs) {
            if (const auto n = parseU32(value)) {
                m_pkcs11IdleTimeoutSecs = *n;
            } else {
                log::warnf("config: ignoring invalid {} '{}'", kPkcs11IdleTimeoutSecs, value);
            }
        } else if (key == kPkcs11MaxLifetimeSecs) {
            if (const auto n = parseU32(value)) {
                m_pkcs11MaxLifetimeSecs = *n; // 0 => no hard cap (LeaseManager honours 0)
            } else {
                log::warnf("config: ignoring invalid {} '{}'", kPkcs11MaxLifetimeSecs, value);
            }
        } else {
            log::warnf("config: ignoring unknown key '{}'", key);
        }
    }
}

void ConfigStore::persist()
{
    std::error_code ec;
    std::filesystem::create_directories(m_configFile.parent_path(), ec);
    if (ec) {
        log::warnf("config: cannot create config dir {}: {}", m_configFile.parent_path().string(), ec.message());
        return;
    }
    const std::filesystem::path tmp = m_configFile.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            log::warnf("config: cannot write {}", tmp.string());
            return;
        }
        out << "# LibreSCRS agent signing configuration (auto-managed; Config1)\n";
        out << kDefaultLevel << " = " << m_defaultLevel << '\n';
        for (const auto& u : m_tsaUrls) {
            out << "TsaUrl = " << u << '\n';
        }
        if (!m_lastTsaUrl.empty()) {
            out << kLastTsaUrl << " = " << m_lastTsaUrl << '\n';
        }
        for (const auto& s : m_tslSources) {
            out << "TslSource = " << s.url;
            if (s.isLotl) {
                out << "|lotl";
            }
            if (s.eager) {
                out << "|eager";
            }
            out << '\n';
        }
        out << kTslCacheDir << " = " << m_tslCacheDir << '\n';
        out << kAiaCacheDir << " = " << m_aiaCacheDir << '\n';
        if (!m_defaultReason.empty()) {
            out << kDefaultReason << " = " << m_defaultReason << '\n';
        }
        if (!m_defaultLocation.empty()) {
            out << kDefaultLocation << " = " << m_defaultLocation << '\n';
        }
        if (!m_pluginDir.empty()) {
            out << kPluginDir << " = " << m_pluginDir << '\n';
        }
        // PKCS#11 lease knobs: persist only when they differ from the built-in
        // defaults so a fresh config file stays minimal.
        if (m_pkcs11IdleTimeoutSecs != kPkcs11IdleDefault) {
            out << kPkcs11IdleTimeoutSecs << " = " << m_pkcs11IdleTimeoutSecs << '\n';
        }
        if (m_pkcs11MaxLifetimeSecs != kPkcs11MaxLifetimeDefault) {
            out << kPkcs11MaxLifetimeSecs << " = " << m_pkcs11MaxLifetimeSecs << '\n';
        }
    }
    std::filesystem::rename(tmp, m_configFile, ec);
    if (ec) {
        log::warnf("config: atomic rename failed: {}", ec.message());
        std::filesystem::remove(tmp, ec);
    }
}

void ConfigStore::fireChanged(const std::string& key) const
{
    // m_onChanged + m_changeObservers are wired once during single-threaded
    // startup; reading them here (post-unlock) needs no lock.
    if (m_onChanged) {
        m_onChanged(key);
    }
    for (const auto& obs : m_changeObservers) {
        obs(key);
    }
}

// --- getters --------------------------------------------------------------

std::string ConfigStore::defaultLevel() const
{
    std::lock_guard lk(m_mutex);
    return m_defaultLevel;
}
std::vector<std::string> ConfigStore::tsaUrls() const
{
    std::lock_guard lk(m_mutex);
    return m_tsaUrls;
}
std::string ConfigStore::lastTsaUrl() const
{
    std::lock_guard lk(m_mutex);
    return m_lastTsaUrl;
}
std::vector<TslSource> ConfigStore::tslSources() const
{
    std::lock_guard lk(m_mutex);
    return m_tslSources;
}
std::string ConfigStore::tslCacheDir() const
{
    std::lock_guard lk(m_mutex);
    return m_tslCacheDir;
}
std::string ConfigStore::aiaCacheDir() const
{
    std::lock_guard lk(m_mutex);
    return m_aiaCacheDir;
}
std::string ConfigStore::defaultReason() const
{
    std::lock_guard lk(m_mutex);
    return m_defaultReason;
}
std::string ConfigStore::defaultLocation() const
{
    std::lock_guard lk(m_mutex);
    return m_defaultLocation;
}
std::string ConfigStore::pluginDir() const
{
    std::lock_guard lk(m_mutex);
    return m_pluginDir;
}
std::uint32_t ConfigStore::pkcs11IdleTimeoutSecs() const
{
    std::lock_guard lk(m_mutex);
    return m_pkcs11IdleTimeoutSecs;
}
std::uint32_t ConfigStore::pkcs11MaxLifetimeSecs() const
{
    std::lock_guard lk(m_mutex);
    return m_pkcs11MaxLifetimeSecs;
}

// --- setters --------------------------------------------------------------

ConfigStore::SetResult ConfigStore::setDefaultLevel(std::string level)
{
    if (!isKnownLevel(level)) {
        return SetResult{false, kErrInvalidValue, "DefaultLevel must be one of b-b|b-t|b-lt|b-lta"};
    }
    {
        std::lock_guard lk(m_mutex);
        m_defaultLevel = std::move(level);
        persist();
    }
    fireChanged(kDefaultLevel);
    return SetResult{true, {}, {}};
}

ConfigStore::SetResult ConfigStore::setTsaUrls(std::vector<std::string> urls)
{
    for (const auto& u : urls) {
        if (!isHttpUrl(u)) {
            return SetResult{false, kErrInvalidValue, "TsaUrls entries must be http(s) URLs"};
        }
    }
    {
        std::lock_guard lk(m_mutex);
        m_tsaUrls = std::move(urls);
        persist();
    }
    fireChanged(kTsaUrls);
    return SetResult{true, {}, {}};
}

ConfigStore::SetResult ConfigStore::setTslSources(std::vector<TslSource> sources)
{
    for (const auto& s : sources) {
        if (!isHttpUrl(s.url)) {
            return SetResult{false, kErrInvalidValue, "TslSources entries must be http(s) URLs"};
        }
    }
    {
        std::lock_guard lk(m_mutex);
        m_tslSources = std::move(sources);
        persist();
    }
    fireChanged(kTslSources);
    return SetResult{true, {}, {}};
}

ConfigStore::SetResult ConfigStore::setDefaultReason(std::string reason)
{
    {
        std::lock_guard lk(m_mutex);
        m_defaultReason = std::move(reason);
        persist();
    }
    fireChanged(kDefaultReason);
    return SetResult{true, {}, {}};
}

ConfigStore::SetResult ConfigStore::setDefaultLocation(std::string location)
{
    {
        std::lock_guard lk(m_mutex);
        m_defaultLocation = std::move(location);
        persist();
    }
    fireChanged(kDefaultLocation);
    return SetResult{true, {}, {}};
}

ConfigStore::SetResult ConfigStore::resetKey(const std::string& key, bool fromDbus)
{
    const auto m = mutability(key);
    if (!m) {
        return SetResult{false, kErrUnknownKey, "Unknown config key: " + key};
    }
    if (fromDbus && (*m == Mutability::FileOnly || *m == Mutability::ReadOnly)) {
        return SetResult{false, kErrReadOnly, "Config key is not settable over D-Bus: " + key};
    }
    // Reset to the built-in default. Recompute cache-dir defaults from cacheRoot.
    {
        std::lock_guard lk(m_mutex);
        if (key == kDefaultLevel) {
            m_defaultLevel = "b-b";
        } else if (key == kTsaUrls) {
            m_tsaUrls.clear();
        } else if (key == kTslSources) {
            m_tslSources.clear();
        } else if (key == kDefaultReason) {
            m_defaultReason.clear();
        } else if (key == kDefaultLocation) {
            m_defaultLocation.clear();
        } else if (key == kTslCacheDir) {
            m_tslCacheDir = (m_cacheRoot / kTslSubdir).string();
        } else if (key == kAiaCacheDir) {
            m_aiaCacheDir = (m_cacheRoot / kAiaSubdir).string();
        } else if (key == kPluginDir) {
            m_pluginDir.clear();
        } else if (key == kPkcs11IdleTimeoutSecs) {
            m_pkcs11IdleTimeoutSecs = kPkcs11IdleDefault;
        } else if (key == kPkcs11MaxLifetimeSecs) {
            m_pkcs11MaxLifetimeSecs = kPkcs11MaxLifetimeDefault;
        } else if (key == kLastTsaUrl) {
            m_lastTsaUrl.clear();
        }
        persist();
    }
    fireChanged(key);
    return SetResult{true, {}, {}};
}

void ConfigStore::recordLastTsaUrl(std::string url)
{
    {
        std::lock_guard lk(m_mutex);
        if (m_lastTsaUrl == url) {
            return; // no-op; avoid a spurious persist + Changed
        }
        m_lastTsaUrl = std::move(url);
        persist();
    }
    fireChanged(kLastTsaUrl);
}

// --- key metadata ---------------------------------------------------------

const std::vector<std::string>& ConfigStore::keys()
{
    static const std::vector<std::string> k{
        kDefaultLevel,         kTsaUrls,       kLastTsaUrl,      kTslSources, kTslCacheDir,
        kAiaCacheDir,          kDefaultReason, kDefaultLocation, kPluginDir,  kPkcs11IdleTimeoutSecs,
        kPkcs11MaxLifetimeSecs};
    return k;
}

std::optional<Mutability> ConfigStore::mutability(const std::string& key)
{
    if (key == kDefaultLevel || key == kDefaultReason || key == kDefaultLocation) {
        return Mutability::DbusMutable;
    }
    if (key == kTsaUrls || key == kTslSources) {
        return Mutability::DbusMutableTrust;
    }
    if (key == kTslCacheDir || key == kAiaCacheDir || key == kPluginDir || key == kPkcs11IdleTimeoutSecs ||
        key == kPkcs11MaxLifetimeSecs) {
        return Mutability::FileOnly;
    }
    if (key == kLastTsaUrl) {
        return Mutability::ReadOnly;
    }
    return std::nullopt;
}

void ConfigStore::setOnChanged(std::function<void(const std::string& key)> cb)
{
    std::lock_guard lk(m_mutex);
    m_onChanged = std::move(cb);
}

void ConfigStore::addChangeObserver(std::function<void(const std::string& key)> cb)
{
    std::lock_guard lk(m_mutex);
    m_changeObservers.push_back(std::move(cb));
}

} // namespace LibreSCRS::Agent::Config
