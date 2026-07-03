// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/backend/AgentTransport.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/presence/CardKeyTracker.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/CancelToken.h>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

// Worker-routing facts for the card currently in a reader, resolved from the
// live presence snapshot: the per-reader worker key, the PC/SC reader name the
// worker's session opens, and the per-insertion cache key the credential/read
// caches are populated under. Supplied to the aggregate as a seam so the neutral
// core never owns the reader-token <-> object-path mapping (a backend concern).
struct ReaderCard
{
    ObjectId readerId;
    std::string readerName;
    std::string cardKey;
};

// Reader routing token -> its ReaderCard, or nullopt when no card is present.
using ResolveReaderCard = std::function<std::optional<ReaderCard>(const std::string& reader)>;

// Single owning aggregate for the platform-neutral agent core. It OWNS every
// neutral member (presence model, caches, key tracker, prompt gate, config,
// signing engine, rate limiter, lease manager, operation scheduler) as a direct
// member, declared in a clean internal dependency order so construction proceeds
// dependency-first and destruction runs strictly borrower-before-borrowee. It
// BORROWS the four collaborators a platform backend owns — the capability
// resolver (owned by the process entry point), the transport membrane, the
// authorization gate, and the prompter client — and exposes each owned/borrowed
// piece through a reference accessor the backend re-sources from.
//
// Everything a crypto worker that outlives this aggregate (an abandoned,
// still-blocked prompt / acquire / terminal op) may touch on unblock — the
// prompter, the prompt gate, the credential cache, and the lease manager — is
// gathered into ONE shared CryptoWorkerContext held here as m_cryptoCtx. Every
// worker closure that can outlive the aggregate (raw sign/decrypt, login,
// cert-DER, public-key) value-captures that single context WHOLE, so on unblock it
// touches only memory it co-owns rather than freed members. The prompter + gate
// cover the blocking call itself and its RAII unwind; the credential cache + lease
// cover the touches PAST the flow's post-prompt gate (a terminal-op wedge that
// unblocks into markPinVerified / clearPinVerified on the lease and invalidate on
// the cache, or a nested CAN/MRZ prompt that writes putCan/putMrz to the cache).
// The lease is co-owned both directly (the login continuation captures the lease
// share) and via the broker's PIN-verified-state callbacks that the raw worker
// value-captures.
//
// The owned members are non-copyable and non-movable (each guards internal
// mutexes / worker threads), so this aggregate is likewise non-copyable and
// non-movable; a backend holds it in place (e.g. via std::optional) and
// constructs it once its borrowed collaborators exist.
class AgentCore
{
public:
    AgentCore(CapabilityResolver& resolver, AgentTransport& transport, Authorizer& authorizer,
              std::shared_ptr<Operations::PrompterClientBase> prompter, std::filesystem::path configFile,
              std::filesystem::path cacheRoot, ResolveReaderCard resolveReaderCard,
              Pkcs11Broker::ResolveCardKeySeam resolveCardKey);

    AgentCore(const AgentCore&) = delete;
    AgentCore& operator=(const AgentCore&) = delete;
    AgentCore(AgentCore&&) = delete;
    AgentCore& operator=(AgentCore&&) = delete;

    // --- borrowed collaborators (owned by the backend) ---------------------
    [[nodiscard]] CapabilityResolver& capabilityResolver() const noexcept
    {
        return m_resolver;
    }
    [[nodiscard]] AgentTransport& transport() const noexcept
    {
        return m_transport;
    }
    [[nodiscard]] Authorizer& authorizer() const noexcept
    {
        return m_authorizer;
    }
    [[nodiscard]] const std::shared_ptr<Operations::PrompterClientBase>& prompter() const noexcept
    {
        return m_cryptoCtx->prompter;
    }

    // --- owned neutral core members ----------------------------------------
    [[nodiscard]] ObjectRegistry& objectRegistry() noexcept
    {
        return m_registry;
    }
    [[nodiscard]] PresenceModel& presenceModel() noexcept
    {
        return m_model;
    }
    [[nodiscard]] CredentialCache& credentialCache() noexcept
    {
        return *m_cryptoCtx->credentials;
    }
    [[nodiscard]] CardReadCache& cardReadCache() noexcept
    {
        return m_readCache;
    }
    [[nodiscard]] CardKeyTracker& cardKeyTracker() noexcept
    {
        return m_tracker;
    }
    [[nodiscard]] Operations::PromptSerializer& promptSerializer() noexcept
    {
        return *m_cryptoCtx->serializer;
    }
    [[nodiscard]] Config::ConfigStore& configStore() noexcept
    {
        return *m_config;
    }
    [[nodiscard]] Operations::SigningEngineProvider& signingEngineProvider() noexcept
    {
        return *m_signingEngine;
    }
    [[nodiscard]] Operations::RateLimiter& rateLimiter() noexcept
    {
        return m_rateLimiter;
    }
    [[nodiscard]] Pkcs11::LeaseManager& leaseManager() noexcept
    {
        return *m_cryptoCtx->lease;
    }
    // The single crypto-worker keep-alive context — the prompter, the prompt gate,
    // the credential cache, the lease manager, and the shutdown-cancel token. A
    // typed-op frontend co-owns this ONE handle (op.keepAlive) so an abandoned typed
    // op keeps every core member its unwind may touch alive through the same context
    // the raw core closures capture (the lease member is harmlessly along for the
    // ride — the typed path never touches the PKCS#11 lease).
    [[nodiscard]] const std::shared_ptr<CryptoWorkerContext>& sharedCryptoContext() const noexcept
    {
        return m_cryptoCtx;
    }
    [[nodiscard]] Operations::OperationManager& operationManager() noexcept
    {
        return m_opManager;
    }
    [[nodiscard]] Pkcs11Broker& pkcs11() noexcept
    {
        return m_pkcs11;
    }

    // --- shutdown-cancel ----------------------------------------------------
    // The agent-wide shutdown-cancel token. Wired into every crypto flow's cancel
    // token so a worker that unblocks from its consent prompt AFTER the backend
    // began teardown returns Cancelled at its post-prompt gate — before touching
    // any collaborator being torn down. The typed ops also bind it to skip their
    // wire completion. Shares cancellation state with m_shutdownCancel.
    [[nodiscard]] LibreSCRS::CancelToken shutdownToken() const noexcept
    {
        return m_shutdownCancel.token();
    }
    // Begin crypto shutdown: cancel the token above. Idempotent; the backend
    // calls it first in its quiesce, before unblocking pending prompts, so an
    // in-flight or abandoned crypto worker bails on unblock instead of driving
    // its completion into a half-torn-down composition.
    void requestCryptoShutdown() noexcept
    {
        static_cast<void>(m_shutdownCancel.requestCancel());
    }

private:
    // Assemble the broker's dependency bundle from this aggregate's own members
    // (lease, authorizer, scheduler, prompt gate, credential cache) plus the
    // injected reader/card resolution seams. Called once, as m_pkcs11's
    // initializer, when every member it reads is already constructed.
    [[nodiscard]] Pkcs11Broker::Deps makeBrokerDeps(Pkcs11Broker::ResolveCardKeySeam resolveCardKey);

    // Enqueue a certificate-DER read on the resolved reader's worker; @p done is
    // fulfilled exactly once (inline nullopt on an unresolved reader, on the
    // worker with the export result otherwise, or fail-closed via the deferred
    // reply when a backpressure rejection drops the closure).
    void exportCertDerOnWorker(const std::string& reader, const std::string& certId,
                               std::function<void(std::optional<std::vector<std::uint8_t>>)> done);

    // Enqueue a raw sign/decrypt on the resolved reader's worker. The worker
    // closure value-captures the single crypto-worker context (prompter + prompt
    // gate + credential cache + lease + shutdown token) plus the pinState (whose
    // callbacks also co-own the lease) — every member its post-unblock unwind may
    // touch. A worker abandoned while blocked in the consent prompt keeps them all
    // alive through the captured context and, on unblock at teardown, bails at the
    // flow's post-prompt gate + skips the completion where it can; where the wedge
    // is past the gate (a terminal op / nested CAN/MRZ prompt) it touches only the
    // co-owned context, never freed memory.
    void runRawCryptoOnWorker(bool isSign, const std::string& reader, const std::string& certId,
                              std::span<const std::uint8_t> bytes, const std::string& requester,
                              const Pkcs11Broker::LeasePinState& pinState,
                              std::function<void(Pkcs11Broker::CryptoResult)> done);

    // Borrowed collaborators. References carry no destruction ordering of their
    // own (the referents are owned elsewhere). The reader/card seam is likewise
    // injected and read by the broker's card-op seams.
    CapabilityResolver& m_resolver;
    AgentTransport& m_transport;
    Authorizer& m_authorizer;
    ResolveReaderCard m_resolveReaderCard;

    // Agent-wide shutdown-cancel source. Declared before every owned member so it
    // outlives the operation scheduler (last member) whose workers hold tokens
    // sharing its state; cancelled by requestCryptoShutdown() at teardown so a
    // crypto worker unblocking from its prompt bails before touching torn-down
    // members.
    LibreSCRS::CancelSource m_shutdownCancel;

    // Owned core, in dependency order: constructed top-to-bottom, destroyed
    // bottom-to-top. The presence model borrows the registry + resolver; the
    // signing engine borrows the config; the broker's seams borrow the crypto
    // context above it (built lazily — they only capture `this` at construction).
    // The operation scheduler is declared LAST so it is destroyed FIRST: its worker
    // join/abandon then runs while the broker and the crypto context are still
    // alive, so every JOINED worker is fully safe with no shared ownership at all.
    // The crypto context (prompter + prompt gate + credential cache + lease +
    // shutdown token) is a shared_ptr so a crypto worker that outlives this aggregate
    // (an abandoned, still-blocked prompt) keeps the members its post-unblock unwind
    // touches alive through its captured share of the same context; it is declared
    // before the broker + scheduler so it outlives both.
    ObjectRegistry m_registry;
    PresenceModel m_model;
    CardReadCache m_readCache;
    CardKeyTracker m_tracker;
    // The config SSOT and the signing-engine provider are shared_ptr (not direct
    // value members) so an abandoned qualified-sign worker keeps both alive on
    // unblock through its co-owned crypto context (m_cryptoCtx->config +
    // ->signingEngine hold the same shares). Declared before the context so they
    // outlive it here; the engine borrows *m_config for its full lifetime, so it is
    // declared after the config it references.
    std::shared_ptr<Config::ConfigStore> m_config;
    std::shared_ptr<Operations::SigningEngineProvider> m_signingEngine;
    Operations::RateLimiter m_rateLimiter;
    // The single crypto-worker keep-alive context: everything an abandoned worker
    // may touch as a core member, captured WHOLE by every worker closure that can
    // outlive this aggregate. Built once in the ctor from the prompter (injected),
    // a fresh prompt gate + credential cache + lease manager, the shutdown token,
    // and shares of the config + signing engine above. The broker's Deps.lease is
    // m_cryptoCtx->lease.
    std::shared_ptr<CryptoWorkerContext> m_cryptoCtx;
    Pkcs11Broker m_pkcs11;
    Operations::OperationManager m_opManager;
};

} // namespace LibreSCRS::Agent
