// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <memory>
#include <mutex>
#include <string>

// LM Signing/Trust types are held only as shared_ptr-to-forward-declared so
// this header stays free of the LM Signing/Trust includes (the seam-boundary
// invariant); the full headers are pulled into SigningEngineProvider.cpp only.
// The agent-side ConfigStore header is included (not forward-declared) for the
// nested ObserverId member below; it is LM-type-free, so the seam holds.
namespace LibreSCRS::Signing {
class SigningService;
}
namespace LibreSCRS::Trust {
class TrustStoreService;
}

namespace LibreSCRS::Agent::Operations {

// The current signing engine together with the TSA URL baked into it. Both are
// captured under one lock so an in-flight sign consumes a consistent pair: the
// bound URL is the one the engine will actually contact, not whatever the live
// ConfigStore happens to hold after a concurrent reconfigure (metadata TOCTOU).
// boundTsaUrl is empty when no TSA is configured (B-B only).
//
// engine is nullptr when the trust configuration could not be built (LmSigner
// maps a null engine to SigningEngineError). The shared engine is shared across
// concurrent callers; SigningService::sign is non-const but thread-safe, which
// the LM contract permits provided each caller uses a distinct (plugin, session)
// pair.
struct EngineSnapshot
{
    std::shared_ptr<LibreSCRS::Signing::SigningService> engine;
    std::string boundTsaUrl;
};

// Owns the immutable signing engine the in-process sign path consumes. A
// LibreSCRS::Signing::SigningService is immutable post-construction (trust +
// TSA are fixed at ctor time), but Config1 is runtime-mutable — this provider
// reconciles the two: it builds a SigningService from the current ConfigStore
// snapshot and atomically swaps in a freshly-built one whenever a
// trust/timestamp-affecting key changes.
//
// ctor-DI'd with the ConfigStore (no singleton); the backend service owns one for the
// process lifetime and hands each LmSigner a reference. snapshot() returns the
// current SigningService (with its bound TSA URL) by shared_ptr so an in-flight
// sign keeps the engine it started with even across a concurrent config rebuild.
class SigningEngineProvider
{
public:
    explicit SigningEngineProvider(Config::ConfigStore& config);
    ~SigningEngineProvider();

    SigningEngineProvider(const SigningEngineProvider&) = delete;
    SigningEngineProvider& operator=(const SigningEngineProvider&) = delete;

    // The current engine AND the TSA URL bound into it, captured atomically under
    // one lock. An in-flight sign uses this so its tsaUsed derivation + LastTsaUrl
    // recording reflect the engine it actually ran on — never the live ConfigStore
    // (which a concurrent admin reconfigure could mutate mid-sign). The engine's
    // own TSA configuration is immutable and not publicly observable on
    // SigningService, so the bound URL is mirrored here at rebuild() time.
    [[nodiscard]] EngineSnapshot snapshot() const;

    // Record @p url (the captured bound URL of the snapshot the sign used) into the
    // ConfigStore's read-only LastTsaUrl (the agent is the sole writer; clients
    // read it over D-Bus). A no-op when @p url is empty (no TSA was contacted), so
    // a plain B-B sign never touches it.
    void recordLastTsaUrlUsed(const std::string& url);

private:
    void rebuild(); // builds a fresh engine from the current ConfigStore snapshot

    Config::ConfigStore& m_config;
    // Handle for the [this]-capturing rebuild observer the ctor registers on
    // m_config; the dtor unregisters it, so a destroyed provider can never be
    // called back even though the ConfigStore outlives it.
    Config::ConfigStore::ObserverId m_configObserverId;
    mutable std::mutex m_mutex;
    // Kept alive alongside the engine: SigningService borrows the trust
    // lifecycle owner for its full lifetime (eager/lazy TL fetches drive it).
    std::shared_ptr<LibreSCRS::Trust::TrustStoreService> m_trust;
    std::shared_ptr<LibreSCRS::Signing::SigningService> m_engine;
    // The TSA URL baked into m_engine at rebuild() time (empty when no TSA is
    // configured). Captured atomically with m_engine under m_mutex so snapshot()
    // hands out a consistent (engine, url) pair.
    std::string m_boundTsaUrl;
};

} // namespace LibreSCRS::Agent::Operations
