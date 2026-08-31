// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/backend/Logging.h>
// The level vocabulary lives with the wire's other signing-parameter
// validators; this store used to keep a private copy of it.
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace LibreSCRS::Agent::Config {

namespace {

// Frozen key strings (single source of truth; mirrors the Config1 wire
// property names 1:1).
constexpr const char* kDefaultLevel = "DefaultLevel";
constexpr const char* kTsaUrls = "TsaUrls";
constexpr const char* kLastTsaUrl = "LastTsaUrl";
constexpr const char* kTslSources = "TslSources";
constexpr const char* kTslCacheDir = "TslCacheDir";
constexpr const char* kAiaCacheDir = "AiaCacheDir";
constexpr const char* kCscaSources = "CscaSources";
constexpr const char* kCscaCacheDir = "CscaCacheDir";
constexpr const char* kCscaAnchorState = "CscaAnchorState";
constexpr const char* kDefaultReason = "DefaultReason";
constexpr const char* kDefaultLocation = "DefaultLocation";
constexpr const char* kPluginDir = "PluginDir";
constexpr const char* kPkcs11IdleTimeoutSecs = "Pkcs11IdleTimeoutSecs";
constexpr const char* kPkcs11MaxLifetimeSecs = "Pkcs11MaxLifetimeSecs";

// One table, two readers. keys() and mutability() below used to be two
// hand-maintained lists of these same fourteen keys -- one a vector of
// spellings, the other a chain of comparisons -- and nothing tied them
// together. A key added to the chain but not the vector is classified and
// unenumerable: it drops out of every consumer that walks keys(), including
// the hosts' completeness gates, while still answering mutability() as though
// it were fully known. Deriving both from one table removes that gap by
// construction rather than by a test that would have to notice it.
struct KeySpec
{
    // Two arguments, deliberately required. As a plain aggregate this struct
    // would accept `{kSomething}` and value-initialise `how` to Mutability{0}
    // -- which is DbusMutable, the MOST permissive of the four -- so a key
    // filed without a classification would silently become writable by any
    // client under the default-allow action. The diagnostic that would say so,
    // -Wmissing-field-initializers, is not an error here: LIBRESCRS_AGENT_WERROR
    // defaults OFF. A constructor makes the omission fail to compile instead,
    // which is the only form of this gate that does not depend on build flags.
    constexpr KeySpec(const char* k, Mutability m) noexcept : key(k), how(m) {}

    const char* key;
    Mutability how;
};

// Order is the order keys() has always returned; consumers render it.
constexpr std::array<KeySpec, 14> kKeySpecs{{
    {kDefaultLevel, Mutability::DbusMutable},
    {kTsaUrls, Mutability::DbusMutableTrust},
    {kLastTsaUrl, Mutability::ReadOnly},
    {kTslSources, Mutability::DbusMutableTrust},
    {kTslCacheDir, Mutability::FileOnly},
    {kAiaCacheDir, Mutability::FileOnly},
    {kCscaSources, Mutability::DbusMutableTrust},
    {kCscaCacheDir, Mutability::FileOnly},
    {kCscaAnchorState, Mutability::ReadOnly},
    {kDefaultReason, Mutability::DbusMutable},
    {kDefaultLocation, Mutability::DbusMutable},
    {kPluginDir, Mutability::FileOnly},
    {kPkcs11IdleTimeoutSecs, Mutability::FileOnly},
    {kPkcs11MaxLifetimeSecs, Mutability::FileOnly},
}};

// PKCS#11 lease-knob built-in defaults: idle 10 min, max lifetime
// 8 h. Single source of truth for applyDefaults + resetKey so the two cannot
// drift.
constexpr std::uint32_t kPkcs11IdleDefault = 600;
constexpr std::uint32_t kPkcs11MaxLifetimeDefault = 28800;
constexpr const char* kLevelDefault = "b-b"; // derived to "b-t" by the consumer when a TSA is set

// D-Bus error names surfaced by a rejected SetValue/Reset.
constexpr const char* kErrReadOnly = "org.librescrs.Agent.Error.ReadOnlyConfig";
constexpr const char* kErrUnknownKey = "org.librescrs.Agent.Error.UnknownConfigKey";
constexpr const char* kErrInvalidValue = "org.librescrs.Agent.Error.InvalidConfigValue";

// Cache subdirectory names under the cache root. "tsl" = ETSI Trusted Service
// List (NOT "tls" — that would be Transport Layer Security); "aia" = the AIA
// caIssuers cert cache. Single source of truth so applyDefaults() and
// resetKey() cannot drift.
constexpr const char* kTslSubdir = "tsl";
constexpr const char* kAiaSubdir = "aia";
// "csca" = the ICAO Country Signing CA anchor cache (passport SOD validation),
// a different trust world from the ETSI lists above and so a different dir.
constexpr const char* kCscaSubdir = "csca";

// First-run seed (see seedFirstRunDefaults below). Public timestamp authorities
// an installation can use out of the box; the first entry is the one the engine
// binds, the rest are the alternatives an administrator can promote by
// reordering the list.
constexpr std::array<const char*, 3> kSeedTsaUrls{
    "https://timestamp.sectigo.com",
    "https://timestamp.digicert.com",
    "https://ts.ssl.com",
};

// The trusted lists the seed carries: the national list, and the EU
// list-of-trusted-lists pivot from which the rest of the member-state lists are
// reached. `eager` is deliberately ABSENT from this table rather than false in
// it: no seeded source may be fetched at startup, and a table with no field for
// it cannot acquire one by a careless edit.
struct SeedTslSource
{
    const char* url;
    bool isLotl;
};
constexpr std::array<SeedTslSource, 2> kSeedTslSources{
    SeedTslSource{"https://www.mit.gov.rs/TrustedList/TSL-RS.xml", false},
    SeedTslSource{"https://ec.europa.eu/tools/lotl/eu-lotl.xml", true},
};

// The seed as a VALUE, so first-run and "restore defaults" cannot drift apart.
// Both callers take the lists from here; a second spelling of the same table is
// how the two senses of "default" came to disagree in the first place.
std::vector<std::string> seededTsaUrls()
{
    return {kSeedTsaUrls.begin(), kSeedTsaUrls.end()};
}

std::vector<TslSource> seededTslSources()
{
    std::vector<TslSource> out;
    out.reserve(kSeedTslSources.size());
    for (const auto& src : kSeedTslSources) {
        // eager stays false here for the same reason it does on first run: a
        // restore must not turn on startup network traffic the reader never
        // asked for.
        out.push_back(TslSource{.url = src.url, .isLotl = src.isLotl, .eager = false});
    }
    return out;
}

// Seed @p tsaUrls and @p tslSources for an installation that has never been
// configured, giving a usable timestamp + trusted-list configuration to an agent
// that would otherwise start with nothing to timestamp against and nothing to
// validate a certificate chain with. Returns true when it seeded, which obliges
// the caller to PERSIST: loadFromFile() clears both list keys before parsing
// whenever the file exists, so a seed that only reaches the in-memory value set
// is correct on the first start and silently gone from the second one onwards.
//
// The gate is the existence of the whole file, and can only be that. An empty
// list persists as zero lines, byte-identical to a list that was never set, and
// the store has no per-key presence signal to tell the two apart -- so "never
// configured" is expressible only as "no config file". The consequence is
// deliberate: once the file exists its lists are the administrator's answer,
// including when they are empty, and no later start re-seeds them.
bool seedFirstRunDefaults(const std::filesystem::path& configFile, std::vector<std::string>& tsaUrls,
                          std::vector<TslSource>& tslSources)
{
    std::error_code ec;
    if (std::filesystem::exists(configFile, ec) || ec) {
        return false; // already configured, or its state cannot be established
    }
    tsaUrls = seededTsaUrls();
    // eager stays false for every source. That flag drives a fetch at trust-store
    // construction -- one worker thread and one HTTPS round trip per source, on
    // every start -- and nothing about seeding a default requires it: the lazy
    // path exists precisely so a host that is offline at login is not forced into
    // startup network traffic. The lists are fetched on the first signature whose
    // level needs them.
    tslSources = seededTslSources();
    return true;
}

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

std::optional<std::int64_t> parseI64(std::string_view s)
{
    std::int64_t out{};
    const auto* begin = s.data();
    const auto* end = s.data() + s.size();
    const auto [ptr, ec] = std::from_chars(begin, end, out);
    if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
    }
    return out;
}

// The CscaAnchorState subfield names. These are the WIRE dict keys verbatim
// (the D-Bus `Config1.CscaAnchorState` property and the socket
// `csca-anchor-state` reply arm carry the same eight spellings), mirrored here
// rather than invented: one vocabulary read by the file, the bus and the
// socket cannot fork into three.
constexpr const char* kAnchorAnchors = "anchors";
constexpr const char* kAnchorIssuers = "issuers";
constexpr const char* kAnchorReplayRefusalActive = "replayRefusalActive";
constexpr const char* kAnchorSigner = "signer";
constexpr const char* kAnchorSignerPinned = "signerPinned";
constexpr const char* kAnchorAcceptedAt = "acceptedAt";
constexpr const char* kAnchorSignedAt = "signedAt";
constexpr const char* kAnchorOrigin = "origin";

// One CscaAnchorState as a single config-file value: `name=value` subfields
// joined by '|', the same separator the TslSource/CscaSource list lines use.
//
// A subfield that is ABSENT is simply not written, and that is load-bearing
// rather than a size optimisation: `signedAt` has no zero sentinel (see the
// struct's own comment), so writing a 0 for an undated list would erase the
// distinction on the very next start. `anchors`, `issuers` and
// `replayRefusalActive` are always written -- they are the three the wire
// requires, and their presence is also what tells a parsed line from garble.
std::string encodeCscaAnchorState(const CscaAnchorState& state)
{
    std::string out;
    out += std::string(kAnchorAnchors) + "=" + std::to_string(state.anchors);
    out += std::string("|") + kAnchorIssuers + "=" + std::to_string(state.issuers);
    out += std::string("|") + kAnchorReplayRefusalActive + "=" + (state.replayRefusalActive ? "true" : "false");
    if (!state.signer.empty()) {
        out += std::string("|") + kAnchorSigner + "=" + state.signer;
    }
    out += std::string("|") + kAnchorSignerPinned + "=" + (state.signerPinned ? "true" : "false");
    if (state.acceptedAt) {
        out += std::string("|") + kAnchorAcceptedAt + "=" + std::to_string(*state.acceptedAt);
    }
    if (state.signedAt) {
        out += std::string("|") + kAnchorSignedAt + "=" + std::to_string(*state.signedAt);
    }
    if (!state.origin.empty()) {
        out += std::string("|") + kAnchorOrigin + "=" + state.origin;
    }
    return out;
}

// The inverse. std::nullopt when the line carries no subfield this build
// knows, which is how a truncated or garbled value stays "nothing imported"
// instead of decoding into a zeroed report that claims an empty master list
// was accepted. An UNKNOWN subfield is skipped rather than fatal: a file
// written by a newer agent must still tell this one what it can read.
std::optional<CscaAnchorState> parseCscaAnchorState(const std::string& value)
{
    CscaAnchorState state;
    bool sawKnownField = false;
    std::stringstream fields(value);
    std::string field;
    while (std::getline(fields, field, '|')) {
        const auto eq = field.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const std::string name = trim(field.substr(0, eq));
        const std::string raw = trim(field.substr(eq + 1));
        if (name == kAnchorAnchors) {
            if (const auto n = parseU32(raw)) {
                state.anchors = *n;
                sawKnownField = true;
            }
        } else if (name == kAnchorIssuers) {
            if (const auto n = parseU32(raw)) {
                state.issuers = *n;
                sawKnownField = true;
            }
        } else if (name == kAnchorReplayRefusalActive) {
            state.replayRefusalActive = (raw == "true");
            sawKnownField = true;
        } else if (name == kAnchorSigner) {
            state.signer = raw;
            sawKnownField = true;
        } else if (name == kAnchorSignerPinned) {
            state.signerPinned = (raw == "true");
            sawKnownField = true;
        } else if (name == kAnchorAcceptedAt) {
            if (const auto n = parseI64(raw)) {
                state.acceptedAt = *n;
                sawKnownField = true;
            }
        } else if (name == kAnchorSignedAt) {
            if (const auto n = parseI64(raw)) {
                state.signedAt = *n;
                sawKnownField = true;
            }
        } else if (name == kAnchorOrigin) {
            state.origin = raw;
            sawKnownField = true;
        }
    }
    if (!sawKnownField) {
        return std::nullopt;
    }
    return state;
}

} // namespace

ConfigStore::ConfigStore(std::filesystem::path configFile, std::filesystem::path cacheRoot)
    : m_configFile(std::move(configFile)), m_cacheRoot(std::move(cacheRoot))
{
    applyDefaults();
    // First start of a never-configured installation: seed the list keys and write
    // them out before the load, which then reads back exactly what was just
    // written. On a failed write the seed still stands for this run (persist() logs
    // and returns) and the next start seeds again -- degraded, never wrong.
    // Unlike every other call site below, this persist() runs WITHOUT
    // m_mutex held. That is deliberate, not an oversight: the constructor
    // has not returned yet, so no other thread holds (or can obtain) a
    // reference to this object to call a setter/getter concurrently with it
    // -- there is nothing m_mutex could be excluding here. Taking it would
    // only add a lock/unlock with no other holder ever contending it.
    if (seedFirstRunDefaults(m_configFile, m_tsaUrls, m_tslSources)) {
        persist();
    }
    loadFromFile();
}

void ConfigStore::applyDefaults()
{
    m_defaultLevel = kLevelDefault;
    m_tsaUrls.clear();
    m_lastTsaUrl.clear();
    m_tslSources.clear();
    m_tslCacheDir = (m_cacheRoot / kTslSubdir).string();
    m_aiaCacheDir = (m_cacheRoot / kAiaSubdir).string();
    m_cscaSources.clear();
    m_cscaCacheDir = (m_cacheRoot / kCscaSubdir).string();
    m_cscaAnchorState.reset();
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
    // List keys (TsaUrl/TslSource/CscaSource) accumulate across repeated lines.
    // Clear them here so the file fully REPLACES (never appends to) whatever
    // applyDefaults seeded — correct even if a future default list becomes
    // non-empty.
    m_tsaUrls.clear();
    m_tslSources.clear();
    m_cscaSources.clear();
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
            if (Operations::SignatureParams::isKnownLevel(value)) {
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
        } else if (key == "CscaSource") { // singular, repeated: uri[|eager]
            // Two fields, not three: there is no isLotl analogue here, because a
            // country-signing source names anchors and never other sources.
            std::stringstream ss(value);
            std::string field;
            CscaSource src;
            bool first = true;
            while (std::getline(ss, field, '|')) {
                if (first) {
                    src.uri = field;
                    first = false;
                } else if (field == "eager") {
                    src.eager = true;
                }
            }
            if (isHttpUrl(src.uri)) {
                m_cscaSources.push_back(std::move(src));
            }
        } else if (key == kTslCacheDir) {
            if (!value.empty()) {
                m_tslCacheDir = value;
            }
        } else if (key == kAiaCacheDir) {
            if (!value.empty()) {
                m_aiaCacheDir = value;
            }
        } else if (key == kCscaCacheDir) {
            if (!value.empty()) {
                m_cscaCacheDir = value;
            }
        } else if (key == kCscaAnchorState) {
            // A garbled value parses to nullopt and leaves the key ABSENT
            // rather than zeroed -- "nothing imported" is the safe reading,
            // "an empty master list was accepted" is not.
            m_cscaAnchorState = parseCscaAnchorState(value);
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
    // A unique name in the SAME directory as the target: rename() below is
    // atomic only within one filesystem, so the temp file must share the
    // config file's parent. A fixed ".tmp" suffix let two writers collide on
    // the identical path -- concretely, two processes racing this exact
    // ctor-time persist() call (see the call above) could truncate or step on
    // each other's write; mkstemp's O_CREAT|O_EXCL loop guarantees each
    // caller gets its own file, no matter how many run at once.
    std::string tmpTemplate = (m_configFile.parent_path() / (m_configFile.filename().string() + ".XXXXXX")).string();
    const int fd = ::mkstemp(tmpTemplate.data());
    if (fd < 0) {
        log::warnf("config: cannot create temp file for {}: {}", m_configFile.string(), std::strerror(errno));
        return;
    }
    ::close(fd);
    const std::filesystem::path tmp{tmpTemplate};
    // mkstemp creates the file at 0600 (owner rw only), which is also the
    // RIGHT mode here, not an accidental narrowing: this config file is
    // agent-private state that only this process (this user account) ever
    // opens directly -- every other client reads it over the Config1 D-Bus
    // interface, never the raw file -- so there is no reader to lock out.
    // Pin the mode explicitly rather than let a future libc change (or a
    // stat-preserving rename onto an existing file with a looser mode) leave
    // it ambiguous which permission regime actually applies.
    std::filesystem::permissions(tmp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            log::warnf("config: cannot write {}", tmp.string());
            std::filesystem::remove(tmp, ec);
            return;
        }
        out << "# LibreSCRS agent signing configuration (auto-managed; Config1)\n";
        // The level and the derived cache paths follow the lease-knob rule
        // below: persisted only when they differ from the built-in defaults.
        // Writing the derived values froze the FIRST start's answers into the
        // file — a terminal first run pinned $HOME/.cache into a config the
        // systemd unit (whose CACHE_DIRECTORY names a different root) then
        // kept using, and a changed built-in level default could never reach
        // an already-installed agent.
        if (m_defaultLevel != kLevelDefault) {
            out << kDefaultLevel << " = " << m_defaultLevel << '\n';
        }
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
        for (const auto& s : m_cscaSources) {
            out << "CscaSource = " << s.uri;
            if (s.eager) {
                out << "|eager";
            }
            out << '\n';
        }
        if (m_tslCacheDir != (m_cacheRoot / kTslSubdir).string()) {
            out << kTslCacheDir << " = " << m_tslCacheDir << '\n';
        }
        if (m_aiaCacheDir != (m_cacheRoot / kAiaSubdir).string()) {
            out << kAiaCacheDir << " = " << m_aiaCacheDir << '\n';
        }
        if (m_cscaCacheDir != (m_cacheRoot / kCscaSubdir).string()) {
            out << kCscaCacheDir << " = " << m_cscaCacheDir << '\n';
        }
        if (m_cscaAnchorState) {
            out << kCscaAnchorState << " = " << encodeCscaAnchorState(*m_cscaAnchorState) << '\n';
        }
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
    // The single setOnChanged slot is wired once during single-threaded
    // startup and never detached; reading it here (post-unlock) needs no lock.
    if (m_onChanged) {
        m_onChanged(key);
    }
    // The multicast observers ARE detachable, so the loop runs under
    // m_observerMutex, held ACROSS the invocations: that hold is what makes
    // removeChangeObserver's blocks-until-drained guarantee true. m_mutex is
    // already released here, so callbacks may re-enter the typed getters
    // (lock order m_observerMutex -> m_mutex, never the reverse), but must
    // not touch the observer registration itself (non-recursive mutex).
    std::lock_guard lk(m_observerMutex);
    for (const auto& obs : m_changeObservers) {
        obs.fn(key);
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
std::vector<CscaSource> ConfigStore::cscaSources() const
{
    std::lock_guard lk(m_mutex);
    return m_cscaSources;
}
std::string ConfigStore::cscaCacheDir() const
{
    std::lock_guard lk(m_mutex);
    return m_cscaCacheDir;
}
std::optional<CscaAnchorState> ConfigStore::cscaAnchorState() const
{
    std::lock_guard lk(m_mutex);
    return m_cscaAnchorState;
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
    if (!Operations::SignatureParams::isKnownLevel(level)) {
        // Rendered from the vocabulary, not restated beside it: the levels this
        // rejection lists and the levels it rejects against are now the same list.
        return SetResult{false, kErrInvalidValue,
                         "DefaultLevel must be one of: " + Operations::SignatureParams::implementedSignLevelsDisplay()};
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

ConfigStore::SetResult ConfigStore::setCscaSources(std::vector<CscaSource> sources)
{
    for (const auto& s : sources) {
        if (!isHttpUrl(s.uri)) {
            return SetResult{false, kErrInvalidValue, "CscaSources entries must be http(s) URLs"};
        }
    }
    {
        std::lock_guard lk(m_mutex);
        m_cscaSources = std::move(sources);
        persist();
    }
    fireChanged(kCscaSources);
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
            // The BUILT-IN default, not emptiness. These two keys are the only
            // ones with a seed, and a reset that cleared them made the button
            // labelled "restore defaults" delete the national trusted list and
            // the EU LOTL pivot instead of bringing them back.
            //
            // This does not weaken the once-only seeding rule above: that rule
            // is about a START never re-seeding a config file that already
            // exists, because an empty list in that file is the administrator's
            // answer. A reset is not a start -- it is someone asking for the
            // built-in answer back, in as many words.
            m_tsaUrls = seededTsaUrls();
        } else if (key == kTslSources) {
            m_tslSources = seededTslSources();
        } else if (key == kCscaSources) {
            m_cscaSources.clear();
        } else if (key == kDefaultReason) {
            m_defaultReason.clear();
        } else if (key == kDefaultLocation) {
            m_defaultLocation.clear();
        } else if (key == kTslCacheDir) {
            m_tslCacheDir = (m_cacheRoot / kTslSubdir).string();
        } else if (key == kAiaCacheDir) {
            m_aiaCacheDir = (m_cacheRoot / kAiaSubdir).string();
        } else if (key == kCscaCacheDir) {
            m_cscaCacheDir = (m_cacheRoot / kCscaSubdir).string();
        } else if (key == kPluginDir) {
            m_pluginDir.clear();
        } else if (key == kPkcs11IdleTimeoutSecs) {
            m_pkcs11IdleTimeoutSecs = kPkcs11IdleDefault;
        } else if (key == kPkcs11MaxLifetimeSecs) {
            m_pkcs11MaxLifetimeSecs = kPkcs11MaxLifetimeDefault;
        } else if (key == kLastTsaUrl) {
            m_lastTsaUrl.clear();
        } else if (key == kCscaAnchorState) {
            m_cscaAnchorState.reset();
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

void ConfigStore::recordCscaAnchorState(CscaAnchorState state)
{
    {
        std::lock_guard lk(m_mutex);
        if (m_cscaAnchorState == state) {
            return; // the same report; avoid a spurious persist + Changed
        }
        m_cscaAnchorState = std::move(state);
        persist();
    }
    fireChanged(kCscaAnchorState);
}

// --- key metadata ---------------------------------------------------------

const std::vector<std::string>& ConfigStore::keys()
{
    static const std::vector<std::string> k = [] {
        std::vector<std::string> out;
        out.reserve(kKeySpecs.size());
        for (const KeySpec& spec : kKeySpecs) {
            out.emplace_back(spec.key);
        }
        return out;
    }();
    return k;
}

std::optional<Mutability> ConfigStore::mutability(const std::string& key)
{
    for (const KeySpec& spec : kKeySpecs) {
        if (key == spec.key) {
            return spec.how;
        }
    }
    return std::nullopt;
}

void ConfigStore::setOnChanged(std::function<void(const std::string& key)> cb)
{
    std::lock_guard lk(m_mutex);
    m_onChanged = std::move(cb);
}

ConfigStore::ObserverId ConfigStore::addChangeObserver(std::function<void(const std::string& key)> cb)
{
    std::lock_guard lk(m_observerMutex);
    const ObserverId id{m_nextObserverId++};
    m_changeObservers.push_back(ChangeObserver{id, std::move(cb)});
    return id;
}

void ConfigStore::removeChangeObserver(ObserverId id) noexcept
{
    if (id == ObserverId{}) {
        return; // sentinel: never names a live registration
    }
    // Acquiring m_observerMutex is the drain: fireChanged holds it across the
    // whole invocation pass, so once the erase below runs the removed callback
    // is not executing on any thread and can never be selected again.
    std::lock_guard lk(m_observerMutex);
    std::erase_if(m_changeObservers, [id](const ChangeObserver& obs) { return obs.id == id; });
}

} // namespace LibreSCRS::Agent::Config
