// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/CertDerExport.h>
#include <LibreSCRS/Agent/operations/LmRawCrypto.h>
#include <LibreSCRS/Agent/operations/RawCryptoFlow.h>
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

namespace {

// No-op phase sink for the off-Operation raw-crypto flow: the deferred-async
// PKCS#11 methods have no Operation wire phases to drive, so the flow's internal
// phase transitions are discarded.
class NullPhaseSink final : public Operations::OperationPhaseSink
{
public:
    void setPhase(std::uint32_t) noexcept override {}
};

// Run one RawCryptoFlow op (sign or decrypt) on the worker thread with @p holder
// and translate RawCryptoFlow::Outcome -> the broker's CryptoOutcome. @p isSign
// picks the terminal op + the runSign/runDecrypt entry. The credential provider
// raised inside the flow collects the PIN via the agent prompter (PIN-as-consent,
// uncached) — never off the wire.
Pkcs11Broker::CryptoResult runRawCrypto(bool isSign, Operations::CardSessionHolder& holder,
                                        Operations::PrompterClientBase& prompter,
                                        Operations::PromptSerializer& serializer, CredentialCache& cache,
                                        const std::string& cardKey, const std::string& requester,
                                        const std::string& certId, std::span<const std::uint8_t> bytes,
                                        const Pkcs11Broker::LeasePinState& pinState, LibreSCRS::CancelToken token)
{
    NullPhaseSink phaseSink;

    // The token is the aggregate's shutdown-cancel token: on the normal path it
    // is never cancelled, but at teardown it trips so this flow returns Cancelled
    // at its post-prompt gate BEFORE touching the credential cache / lease /
    // terminal op — none of which the abandoned worker may safely reach once the
    // aggregate is gone.
    Operations::RawCryptoFlow flow{Operations::RawCryptoFlowDeps{
        .holder = holder,
        .prompter = prompter,
        .serializer = serializer,
        .cache = cache,
        .phaseSink = phaseSink,
        .cardKey = cardKey,
        .requester = requester,
        .certId = certId,
        .signOp = Operations::signRaw,
        .decryptOp = Operations::decryptRaw,
        .token = std::move(token),
        .isPinVerified = pinState.isVerified,
        .markPinVerified = pinState.markVerified,
        .clearPinVerified = pinState.clearVerified,
    }};
    const auto r = isSign ? flow.runSign(bytes) : flow.runDecrypt(bytes);
    using FO = Operations::RawCryptoFlow::Outcome;
    using HO = Pkcs11Broker::CryptoOutcome;
    HO outcome = HO::CardError;
    switch (r.outcome) {
    case FO::Ok:
        outcome = HO::Ok;
        break;
    case FO::Cancelled:
        outcome = HO::Cancelled;
        break;
    case FO::KeyNotFound:
        outcome = HO::KeyNotFound;
        break;
    case FO::AuthFailed:
        outcome = HO::AuthFailed;
        break;
    case FO::NotSupported:
        outcome = HO::NotSupported;
        break;
    case FO::CardError:
        outcome = HO::CardError;
        break;
    }
    return Pkcs11Broker::CryptoResult{.outcome = outcome, .bytes = r.bytes};
}

} // namespace

AgentCore::AgentCore(CapabilityResolver& resolver, AgentTransport& transport, Authorizer& authorizer,
                     std::shared_ptr<Operations::PrompterClientBase> prompter, std::filesystem::path configFile,
                     std::filesystem::path cacheRoot, ResolveReaderCard resolveReaderCard,
                     Pkcs11Broker::ResolveCardKeySeam resolveCardKey)
    : m_resolver(resolver), m_transport(transport), m_authorizer(authorizer),
      m_resolveReaderCard(std::move(resolveReaderCard)), m_model(m_registry, m_resolver),
      m_config(std::make_shared<Config::ConfigStore>(std::move(configFile), std::move(cacheRoot))),
      m_signingEngine(std::make_shared<Operations::SigningEngineProvider>(*m_config)),
      // The single crypto-worker keep-alive context: the injected prompter plus a
      // fresh prompt gate, credential cache, and lease manager, the shutdown token,
      // and shares of the config + signing engine above. Every worker closure that
      // can outlive this aggregate captures this WHOLE, so an abandoned worker
      // touches only co-owned memory on unblock — including an abandoned
      // qualified-sign worker whose seam unblocks into the engine's snapshot() +
      // recordLastTsaUrlUsed (through *config). The login-lease bounds are a
      // file-only security policy read from the config; capture them once here into
      // the lease manager.
      m_cryptoCtx(std::make_shared<CryptoWorkerContext>(CryptoWorkerContext{
          .prompter = std::move(prompter),
          .serializer = std::make_shared<Operations::PromptSerializer>(),
          .credentials = std::make_shared<CredentialCache>(),
          .lease = std::make_shared<Pkcs11::LeaseManager>(
              Pkcs11::LeaseConfig{.idleTimeout = std::chrono::seconds{m_config->pkcs11IdleTimeoutSecs()},
                                  .maxLifetime = std::chrono::seconds{m_config->pkcs11MaxLifetimeSecs()}}),
          .shutdown = m_shutdownCancel.token(),
          .config = m_config,
          .signingEngine = m_signingEngine,
          // The read + snapshot caches are co-owned here (not direct members) so an
          // abandoned credential worker keeps them alive on unblock — see the
          // AgentCore member note. Both are leaf caches (no dependencies).
          .snapshotCache = std::make_shared<CredentialSnapshotCache>(),
          .readCache = std::make_shared<CardReadCache>(),
      })),
      // The broker's seams only CAPTURE `this` at construction (they read the
      // scheduler lazily, at op time), so it is built before the scheduler below.
      m_pkcs11(makeBrokerDeps(std::move(resolveCardKey))),
      // The scheduler is the LAST member — destroyed FIRST — so its worker
      // join/abandon runs while every member its workers touch is still alive. It
      // resolves each per-reader holder's candidate list through the borrowed
      // capability resolver.
      m_opManager(&m_resolver)
{}

void AgentCore::exportCertDerOnWorker(const std::string& reader, const std::string& certId,
                                      std::function<void(std::optional<std::vector<std::uint8_t>>)> done)
{
    const auto rc = m_resolveReaderCard(reader);
    if (!rc) {
        done(std::nullopt);
        return;
    }
    // Async hop: enqueue the read on the worker and return the caller thread
    // immediately. The closure runs the export ON THE WORKER THREAD and invokes
    // @p done there; it value-captures certId + owns @p done, so both stay valid
    // after the enqueuing frame is gone. A backpressure rejection drops the
    // closure and the deferred reply's fail-closed destructor replies. It also
    // value-captures the crypto-worker context: the wedge here is the uncancellable
    // holder.acquire(); a worker abandoned in it and unblocked at teardown skips its
    // completion (the reply channel is gone) rather than driving into a torn-down
    // wire. This is the no-consent public-data path (CertDer + the PublicKey caller
    // below route through it), so nothing else in the context is dereferenced — the
    // whole-context capture keeps the skip uniform across every worker closure.
    auto ctx = m_cryptoCtx;
    static_cast<void>(m_opManager.enqueueOnReaderWorker(
        rc->readerId, rc->readerName, [certId, done = std::move(done), ctx](Operations::CardSessionHolder& holder) {
            auto acquired = holder.acquire();
            if (ctx->shutdown.isCancelled()) {
                // teardown: skip the completion (reply channel gone). @p done's
                // deferred reply still fires fail-closed when this closure is
                // destroyed at zombie drain, so the client is never left hanging.
                return;
            }
            if (!acquired) {
                done(std::nullopt);
                return;
            }
            done(Operations::exportCertDer(acquired->candidates, certId, *acquired->session));
        }));
}

void AgentCore::runRawCryptoOnWorker(bool isSign, const std::string& reader, const std::string& certId,
                                     std::span<const std::uint8_t> bytes, const std::string& requester,
                                     const Pkcs11Broker::LeasePinState& pinState,
                                     std::function<void(Pkcs11Broker::CryptoResult)> done)
{
    const auto rc = m_resolveReaderCard(reader);
    if (!rc) {
        done(Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::CardError, {}});
        return;
    }
    // The worker closure must OWN everything it touches: the hop returns (caller
    // thread released) while the worker still runs this closure, so a by-reference
    // capture of the caller-frame bytes would be a use-after-free. Copy the input
    // into a shared_ptr and value-capture the rest.
    auto input = std::make_shared<std::vector<std::uint8_t>>(bytes.begin(), bytes.end());
    // Shutdown keep-alive: value-capture the single crypto-worker context WHOLE, so a
    // worker abandoned while blocked in the consent prompt keeps every member it may
    // touch on unblock alive through its captured share even after this aggregate is
    // gone:
    //   * prompter  — the blocking call itself (and its backing connection);
    //   * serializer — the SlotGuard unwind that locks + notifies the gate
    //                  unconditionally on any live-process unblock;
    //   * credentials — a nested CAN/MRZ prompt writes putCan/putMrz to the cache,
    //                  and the AuthFailed unwind invalidates it, BOTH past the
    //                  flow's post-prompt gate (so the shutdown token cannot always
    //                  bail before the cache is touched);
    //   * lease      — reached both through pinState (captured by value below, whose
    //                  callbacks co-own the same lease share) and directly by the
    //                  broker's login continuation; markPinVerified on a successful
    //                  terminal op and clearPinVerified on the recovery path both run
    //                  past the gate too;
    //   * shutdown   — wired into the flow (its post-prompt gate) and the completion
    //                  skip: on teardown the worker returns Cancelled — where it can
    //                  — without driving its completion into the being-torn-down
    //                  reply channel + broker. Skipping @p done does NOT strand the
    //                  client: @p done owns the deferred D-Bus reply (a Reply bound
    //                  over a shared sdbus::Result), whose fail-closed destructor
    //                  fires the error reply when this closure is destroyed at zombie
    //                  drain, so the client learns the outcome rather than hanging.
    //                  Where the wedge is past the gate (a terminal op / nested
    //                  prompt), the co-owned context keeps the touched members alive.
    auto ctx = m_cryptoCtx;
    const bool queued = m_opManager.enqueueOnReaderWorker(
        rc->readerId, rc->readerName,
        [done, input, cardKey = rc->cardKey, requester, certId, pinState, ctx,
         isSign](Operations::CardSessionHolder& holder) {
            auto result = runRawCrypto(isSign, holder, *ctx->prompter, *ctx->serializer, *ctx->credentials, cardKey,
                                       requester, certId, *input, pinState, ctx->shutdown);
            if (ctx->shutdown.isCancelled()) {
                // teardown: skip the completion (broker + reply channel gone). @p
                // done's deferred reply still fires fail-closed at zombie drain via
                // its destructor, so the client is never left hanging. A cancel
                // landing AFTER this check, with the completion already in flight,
                // is caught by the broker wrapper's own re-check of its co-owned
                // token copy immediately before its lease revoke — the wrapper's
                // only raw broker deref on this path.
                return;
            }
            done(std::move(result));
        });
    if (!queued) {
        done(Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::CardError, {}});
    }
}

Pkcs11Broker::Deps AgentCore::makeBrokerDeps(Pkcs11Broker::ResolveCardKeySeam resolveCardKey)
{
    return Pkcs11Broker::Deps{
        .lease = m_cryptoCtx->lease,
        .authorizer = m_authorizer,
        .certDer =
            [this](const std::string& reader, const std::string& certId,
                   std::function<void(std::optional<std::vector<std::uint8_t>>)> done) {
                exportCertDerOnWorker(reader, certId, std::move(done));
            },
        .publicKey =
            [this](const std::string& reader, const std::string& certId,
                   std::function<void(std::optional<Pkcs11Broker::PublicKey>)> done) {
                // Public data: export the cert DER (same worker-thread path as
                // CertDer) then extract the RSA modulus + exponent from its SPKI on
                // the worker. nullopt when the cert is absent (-> KeyNotFound); an
                // engaged PublicKey with EMPTY fields signals "resolved but not RSA"
                // (-> NotSupported).
                exportCertDerOnWorker(reader, certId,
                                      [done = std::move(done)](std::optional<std::vector<std::uint8_t>> der) {
                                          if (!der) {
                                              done(std::nullopt);
                                              return;
                                          }
                                          auto rsa = Operations::rsaPublicKeyFromCertDer(*der);
                                          if (!rsa) {
                                              done(Pkcs11Broker::PublicKey{});
                                              return;
                                          }
                                          done(Pkcs11Broker::PublicKey{.modulus = std::move(rsa->modulus),
                                                                       .exponent = std::move(rsa->exponent)});
                                      });
            },
        .login =
            [this](const std::string& reader, std::function<void(Pkcs11Broker::LoginOutcome)> done) {
                // Login = optimistic grant: open the card channel only (no PIN
                // prompt, no crypto op) and grant the lease on success. The first
                // SignRaw/Decrypt raises the PIN prompter (PIN-as-consent) and
                // verifies on-card.
                const auto rc = m_resolveReaderCard(reader);
                if (!rc) {
                    done(Pkcs11Broker::LoginOutcome::CardError);
                    return;
                }
                // The wedge here is the uncancellable holder.acquire(). The worker
                // value-captures the crypto-worker context WHOLE so, if abandoned and
                // unblocked at teardown, it skips its completion (@p done runs the
                // broker's login continuation, which grants the lease) rather than
                // driving into a torn-down composition; where the completion DOES run
                // it touches only the co-owned lease the continuation captured.
                auto ctx = m_cryptoCtx;
                const bool queued = m_opManager.enqueueOnReaderWorker(
                    rc->readerId, rc->readerName, [done, ctx](Operations::CardSessionHolder& holder) {
                        auto acquired = holder.acquire();
                        if (ctx->shutdown.isCancelled()) {
                            // teardown: skip the completion (broker + lease gone).
                            // @p done's deferred reply still fires fail-closed at
                            // zombie drain via its destructor, so the client learns
                            // the outcome rather than hanging.
                            return;
                        }
                        done(acquired ? Pkcs11Broker::LoginOutcome::Ok : Pkcs11Broker::LoginOutcome::CardError);
                    });
                if (!queued) {
                    done(Pkcs11Broker::LoginOutcome::CardError); // backpressure -> fail closed
                }
            },
        .signRaw =
            [this](const std::string& reader, const std::string& certId, Mechanism /*mechanism*/,
                   const MechanismParams& /*params*/, std::span<const std::uint8_t> bytes, const std::string& requester,
                   const Pkcs11Broker::LeasePinState& pinState, std::function<void(Pkcs11Broker::CryptoResult)> done) {
                runRawCryptoOnWorker(/*isSign=*/true, reader, certId, bytes, requester, pinState, std::move(done));
            },
        .decrypt =
            [this](const std::string& reader, const std::string& certId, Mechanism /*mechanism*/,
                   const MechanismParams& /*params*/, std::span<const std::uint8_t> bytes, const std::string& requester,
                   const Pkcs11Broker::LeasePinState& pinState, std::function<void(Pkcs11Broker::CryptoResult)> done) {
                runRawCryptoOnWorker(/*isSign=*/false, reader, certId, bytes, requester, pinState, std::move(done));
            },
        .resolveCardKey = std::move(resolveCardKey),
        // The broker's runCrypto completion wrapper re-checks this token (a
        // value-captured copy) immediately before its AuthFailed lease revoke —
        // its only raw broker deref — narrowing the window between the worker's
        // pre-completion skip and that deref at teardown.
        .shutdown = m_cryptoCtx->shutdown,
        .now = {}, // steady_clock::now
    };
}

} // namespace LibreSCRS::Agent
