// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Config {

// One trusted-list source (mirrors LibreSCRS::Trust::TrustedListSource on the
// agent side so ConfigStore stays LM-type-free and unit-testable without
// linking Trust). The SigningEngineProvider maps these into a TrustConfig.
struct TslSource
{
    std::string url;
    bool isLotl{false}; // a List-of-Trusted-Lists pivot, not a leaf TL
    bool eager{false};  // fetch at startup rather than lazily at first sign

    bool operator==(const TslSource&) const = default;
};

// How a key may be changed. The authoritative human-consent gate for signing
// is the PIN; this is the authorization-of-the-CLIENT policy surface only.
enum class Mutability {
    DbusMutable,      // Config1.SetValue under org.librescrs.agent.configure (default allow)
    DbusMutableTrust, // Config1.SetValue under org.librescrs.agent.configure.trust (auth_self)
    FileOnly,         // settable only by editing the on-disk config (e.g. PluginDir: dlopen vector)
    ReadOnly,         // agent-internal state, never client-settable (e.g. LastTsaUrl)
};

// Agent-owned signing configuration: the R10 single-source-of-truth for the
// operation-affecting, NON-secret settings (level, TSA, trust list, cache dirs,
// plugin dir). Secrets (PIN/CAN/MRZ) are NEVER configuration.
//
// Pure logic + file persistence; no D-Bus, no LM types. Owned by the backend service
// via ctor-DI (no singleton); the Config1 D-Bus object and the
// SigningEngineProvider are thin consumers. Thread-safe (an internal mutex
// guards the value set; getters return copies).
class ConfigStore
{
public:
    // The on-disk config file (read + written by SetValue/Reset) and the
    // writable cache root (systemd CacheDirectory / $XDG_CACHE_HOME/librescrs)
    // under which the AIA + TSL cache dirs default. Loads the file if present,
    // otherwise applies built-in defaults. Never throws on a missing/garbled
    // file — a parse failure logs and falls back to defaults (fail-open to a
    // safe B-B-no-TSA posture, never fail-closed-unusable).
    ConfigStore(std::filesystem::path configFile, std::filesystem::path cacheRoot);

    ConfigStore(const ConfigStore&) = delete;
    ConfigStore& operator=(const ConfigStore&) = delete;

    // --- typed getters (return copies under the lock) -----------------------
    [[nodiscard]] std::string defaultLevel() const; // "b-b" (derived to "b-t" when a TSA is set)
    [[nodiscard]] std::vector<std::string> tsaUrls() const;
    [[nodiscard]] std::string lastTsaUrl() const; // ReadOnly
    [[nodiscard]] std::vector<TslSource> tslSources() const;
    [[nodiscard]] std::string tslCacheDir() const; // FileOnly; defaults under cacheRoot
    [[nodiscard]] std::string aiaCacheDir() const; // FileOnly; defaults under cacheRoot
    [[nodiscard]] std::string defaultReason() const;
    [[nodiscard]] std::string defaultLocation() const;
    [[nodiscard]] std::string pluginDir() const; // FileOnly: dlopen vector
    // PKCS#11 login-lease knobs (FileOnly security policy; not D-Bus mutable).
    // Defaults: idle 600 s, max lifetime 28800 s (8 h).
    [[nodiscard]] std::uint32_t pkcs11IdleTimeoutSecs() const;
    [[nodiscard]] std::uint32_t pkcs11MaxLifetimeSecs() const;

    // --- mutation (typed; the Config1 adaptor maps SetValue(key,variant)) ----
    // Each returns a SetResult: ok==true persists + fires onChanged; ok==false
    // carries a D-Bus error name + message and changes nothing.
    //
    // Mutability + authorization enforcement happens at the Config1 adaptor
    // (the backend Config1 SetValue / Reset path), NOT here: those check
    // mutability(key) and reject FileOnly/ReadOnly keys, then authorize the
    // caller before delegating to these setters. The five typed setters below
    // therefore take no `fromDbus` parameter (they never consult it); only
    // resetKey actually consults it. The file-load path (loadFromFile) bypasses
    // these setters entirely.
    struct SetResult
    {
        bool ok{false};
        std::string errorName; // e.g. org.librescrs.Agent.Error.{ReadOnlyConfig,UnknownConfigKey,InvalidConfigValue}
        std::string message;
    };
    SetResult setDefaultLevel(std::string level);
    SetResult setTsaUrls(std::vector<std::string> urls);
    SetResult setTslSources(std::vector<TslSource> sources);
    SetResult setDefaultReason(std::string reason);
    SetResult setDefaultLocation(std::string location);
    // Reset a single key to its built-in default (Config1.Reset). Honors
    // Mutability when fromDbus.
    SetResult resetKey(const std::string& key, bool fromDbus);

    // Agent-internal: record the last TSA URL actually used after a successful
    // timestamped sign. Bypasses the D-Bus mutability gate by design (ReadOnly
    // on the wire). Persists + fires onChanged("LastTsaUrl").
    void recordLastTsaUrl(std::string url);

    // --- key metadata (single source of truth for the Config1 adaptor) ------
    [[nodiscard]] static const std::vector<std::string>& keys();
    [[nodiscard]] static std::optional<Mutability> mutability(const std::string& key);

    // Fired (post-lock) with the changed key after any successful mutation.
    // SINGLE-SLOT: a second call REPLACES the first. The backend service wires this to
    // the Config1.Changed D-Bus bridge. Additional in-process consumers (the
    // SigningEngineProvider's rebuild-on-trust-change) register via the
    // multicast addChangeObserver below rather than clobbering this slot.
    void setOnChanged(std::function<void(const std::string& key)> cb);

    // Append an additional change observer (multicast, distinct from the single
    // setOnChanged slot). Observers fire after setOnChanged on every successful
    // mutation. Append-only: observers are process-lifetime (no detach), wired
    // once during single-threaded startup.
    void addChangeObserver(std::function<void(const std::string& key)> cb);

private:
    void applyDefaults();                           // built-in defaults (under m_cacheRoot)
    void loadFromFile();                            // parse m_configFile; tolerate absence/garble
    void persist();                                 // atomic write of the current value set
    void fireChanged(const std::string& key) const; // post-unlock

    std::filesystem::path m_configFile;
    std::filesystem::path m_cacheRoot;

    mutable std::mutex m_mutex;
    std::string m_defaultLevel;
    std::vector<std::string> m_tsaUrls;
    std::string m_lastTsaUrl;
    std::vector<TslSource> m_tslSources;
    std::string m_tslCacheDir;
    std::string m_aiaCacheDir;
    std::string m_defaultReason;
    std::string m_defaultLocation;
    std::string m_pluginDir;
    std::uint32_t m_pkcs11IdleTimeoutSecs{600};
    std::uint32_t m_pkcs11MaxLifetimeSecs{28800};

    std::function<void(const std::string&)> m_onChanged;                    // guarded by m_mutex for assignment only
    std::vector<std::function<void(const std::string&)>> m_changeObservers; // multicast; assignment guarded by m_mutex
};

} // namespace LibreSCRS::Agent::Config
