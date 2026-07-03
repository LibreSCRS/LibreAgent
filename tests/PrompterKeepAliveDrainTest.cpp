// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Shutdown keep-alive proof for the raw-crypto worker path. When a client asks
// for a private-key op, the card I/O runs on a per-reader worker that raises the
// consent prompt and BLOCKS in it until the human answers. If the agent is torn
// down while that prompt is still open, the worker is uncancellable (parked in a
// blocking prompt call) and is abandoned to the never-joined zombie list rather
// than joined — so it outlives the composition that owned the prompter.
//
// The crypto seam guards against a use-after-free on that path by having the
// worker closure VALUE-CAPTURE a shared_ptr to the prompter. This test models the
// exact ownership: a fake prompter whose requestPin blocks on a latch, a worker
// closure that captures a shared_ptr to it, the worker abandoned while blocked,
// then the composition's own shared_ptr dropped. When the latch finally releases,
// the still-blocked worker reads the prompter's own storage — which must be live
// because the captured shared_ptr kept it alive. A regression (a raw reference
// capture) would read freed memory and trip ThreadSanitizer here.
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/Reply.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // OperationPhaseSink
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RawCryptoFlow.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/CancelToken.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

// A latch the worker blocks on inside requestPin — the stand-in for the human
// PIN entry / the uncancellable blocking prompt call. The test releases it only
// AFTER abandoning the worker and dropping the composition's prompter share.
struct Latch
{
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};

    void release()
    {
        {
            std::lock_guard lock(mutex);
            released = true;
        }
        cv.notify_all();
    }
    void waitForRelease()
    {
        std::unique_lock lock(mutex);
        cv.wait(lock, [this] { return released; });
    }
};

// Fake prompter whose requestPin blocks on the latch, then reads its OWN
// object-owned storage (m_marker) after the release and publishes it. Reading
// m_marker dereferences `this`: if the prompter has been freed by the time the
// latch releases, that read is a use-after-free.
class BlockingPrompter final : public PrompterClientBase
{
public:
    BlockingPrompter(Latch& latch, std::atomic<bool>& entered, std::atomic<int>& observedMarker, int marker)
        : m_latch(latch), m_entered(entered), m_observedMarker(observedMarker), m_marker(marker)
    {}

    [[nodiscard]] PromptResult requestPin(const PromptOptions&) override
    {
        m_entered.store(true, std::memory_order_release);
        m_latch.waitForRelease();
        // Live-memory read: publishing m_marker forces a deref of `this` on the
        // (possibly abandoned) worker thread AFTER the composition's share was
        // dropped.
        m_observedMarker.store(m_marker, std::memory_order_release);
        return PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }

private:
    Latch& m_latch;
    std::atomic<bool>& m_entered;
    std::atomic<int>& m_observedMarker;
    int m_marker;
};

const ObjectId kReaderId{7};
constexpr int kMarker{0x5A5A};

} // namespace

// The worker closure value-captures a shared_ptr to the prompter (as the crypto
// seam does). Abandoning the blocked worker, then dropping the composition's own
// share, must leave the prompter alive through the captured share — so the
// worker's eventual read of prompter storage is UAF-free (TSan-clean).
TEST(PrompterKeepAliveDrain, AbandonedWorkerKeepsPrompterAliveThroughCapturedShare)
{
    Latch latch;
    std::atomic<bool> entered{false};
    std::atomic<int> observedMarker{0};

    // The "composition" holds the sole share to start with.
    std::shared_ptr<PrompterClientBase> prompter =
        std::make_shared<BlockingPrompter>(latch, entered, observedMarker, kMarker);

    {
        OperationManager mgr; // bus-less core path

        // The worker probe VALUE-CAPTURES the prompter share and blocks in
        // requestPin — exactly what the raw-crypto seam's worker closure does.
        mgr.enqueueHolderProbeForTest(
            kReaderId, [prompter](CardSessionHolder&) { static_cast<void>(prompter->requestPin(PromptOptions{})); });

        // Wait until the worker is actually parked inside requestPin.
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "worker never entered the blocking prompt";

        // The closure captured its own share, so the composition is no longer the
        // sole owner.
        EXPECT_GE(prompter.use_count(), 2);

        // Abandon the wedged worker (it never returns from the blocking prompt, so
        // removeReader detaches it to the zombie list and returns promptly).
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReaderId);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged worker";

        // Drop the composition's share: only the abandoned worker's captured share
        // now keeps the prompter alive.
        prompter.reset();

        // Release the latch: the abandoned worker unblocks and reads prompter
        // storage. With the captured share that read hits live memory; a raw
        // reference capture would read freed memory (TSan trap).
        latch.release();

        const auto readDeadline = std::chrono::steady_clock::now() + 2s;
        while (observedMarker.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < readDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(observedMarker.load(std::memory_order_acquire), kMarker)
            << "the abandoned worker never completed its live-memory read of the prompter";

        // Let the zombie thread finish unwinding (drop its captured share, free the
        // prompter) before ~OperationManager, keeping the run sanitizer-clean.
        std::this_thread::sleep_for(100ms);
    }
}

// Faithful raw-seam drain. The prior proof captured only the prompter and never
// routed through the prompt gate, so it could not observe the serializer UAF. This
// abandoned worker runs the REAL seam — SerializingPrompter -> PromptSerializer,
// the exact path RawCryptoFlow::collectPin() uses — co-owning BOTH the prompter
// share AND the prompt-gate share, as the AgentCore raw closure now does. The
// blocking prompt parks the worker while it HOLDS the serializer slot; the
// composition drops its own shares (serializer + prompter) while the zombie is
// blocked; releasing the latch lets the worker unblock and unwind — the SlotGuard's
// release() locks + notifies the serializer and requestPin returns through the
// prompter, both of which MUST be live because the closure co-owns them
// (TSan-clean). A raw-ref capture of the serializer (the pre-fix bug) would touch
// freed memory in release() the moment the composition's share is dropped.
TEST(PrompterKeepAliveDrain, AbandonedWorkerKeepsSerializerAndPrompterAliveThroughRealSeam)
{
    Latch latch;
    std::atomic<bool> entered{false};
    std::atomic<int> observedMarker{0};

    auto serializer = std::make_shared<PromptSerializer>();
    std::shared_ptr<PrompterClientBase> prompter =
        std::make_shared<BlockingPrompter>(latch, entered, observedMarker, kMarker);

    {
        OperationManager mgr; // bus-less core path

        // The worker probe value-captures BOTH shares and routes the prompt through
        // the agent-wide gate exactly as the raw-crypto seam does.
        mgr.enqueueHolderProbeForTest(kReaderId, [serializer, prompter](CardSessionHolder&) {
            LibreSCRS::CancelToken token; // no external cancel on this synchronous path
            SerializingPrompter gated{*serializer, *prompter, std::move(token)};
            static_cast<void>(gated.requestPin(PromptOptions{}));
        });

        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "worker never entered the blocking prompt";

        // Both members are co-owned by the closure, so the composition is no longer
        // the sole owner of either.
        EXPECT_GE(serializer.use_count(), 2);
        EXPECT_GE(prompter.use_count(), 2);

        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReaderId);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged worker";

        // Drop the composition's shares: only the abandoned worker's captured shares
        // now keep the serializer + prompter alive.
        serializer.reset();
        prompter.reset();

        // Release the latch: the worker unblocks, requestPin reads prompter storage,
        // and the SlotGuard's release() locks + notifies the serializer. Both are
        // live-memory reads only because the closure co-owns both shares.
        latch.release();

        const auto readDeadline = std::chrono::steady_clock::now() + 2s;
        while (observedMarker.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < readDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(observedMarker.load(std::memory_order_acquire), kMarker)
            << "the abandoned worker never completed its live-memory read through the real seam";

        // Let the zombie thread finish unwinding (drop its captured shares) before
        // ~OperationManager, keeping the run sanitizer-clean.
        std::this_thread::sleep_for(100ms);
    }
}

// ---------------------------------------------------------------------------
// PAST-THE-GATE drain proofs. The prior cases modelled the CONSENT-PROMPT wedge
// (worker parked in requestPin, bails at the flow's post-prompt cancel gate). But
// two wedge points run PAST that gate, where the shutdown token can no longer make
// the flow bail, so the credential cache AND the lease must ALSO be co-owned:
//   (A) the terminal on-card op (PSO / SCardTransmit) is itself an uncancellable
//       blocking call; a worker wedged there unblocks into markPinVerified (the
//       common successful-sign case) or, on AuthFailed, cache.invalidate;
//   (B) the read flows have no signing-PIN prompt — they wedge in a nested CAN/MRZ
//       credential prompt, then write putCan/putMrz to the cache the instant the
//       prompt returns Ok, below the flow gate.
// These cases run the REAL RawCryptoFlow / CredentialCache paths with a fake
// terminal / prompter that blocks on a latch, free the composition while the zombie
// is blocked, then release the latch and assert the past-the-gate touch hits live
// (co-owned) memory (TSan-clean). RED-proven during development by reverting each
// co-ownership mechanism (Pkcs11Broker::Deps.lease -> raw ref; the worker's
// credentials share -> raw pointer) and observing the sanitizer trap.
namespace {

// Prompter that returns a PIN immediately (no block): lets the raw flow clear its
// consent prompt fast so the worker reaches the TERMINAL op — the wedge under test.
class FastPinPrompter final : public PrompterClientBase
{
public:
    [[nodiscard]] PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1234"}, ""};
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
};

// Prompter whose requestCan BLOCKS on the latch, then (after release) returns a CAN
// secret so CredentialCache::requestCredential runs putCan on the cache — the read
// path's past-the-gate wedge.
class CanWedgePrompter final : public PrompterClientBase
{
public:
    CanWedgePrompter(Latch& latch, std::atomic<bool>& entered) : m_latch(latch), m_entered(entered) {}
    [[nodiscard]] PromptResult requestPin(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions&) override
    {
        m_entered.store(true, std::memory_order_release);
        m_latch.waitForRelease();
        return PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }

private:
    Latch& m_latch;
    std::atomic<bool>& m_entered;
};

class NullPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t) noexcept override {}
};

// A per-reader held-session holder over a DETACHED (card-free) CardSession, so the
// raw flow's FlowPrelude::openSession succeeds with no live card.
std::shared_ptr<CardSessionHolder> makeDetachedHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_shared<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

struct AllowAllAuthorizer final : Authorizer
{
    bool authorize(std::string_view, const CallerToken&) override
    {
        return true;
    }
};

const std::vector<std::uint8_t> kWedgeInput{0x01, 0x02, 0x03, 0x04};
const ObjectId kWedgeCard{7};

// Drive the REAL Pkcs11Broker crypto path to a worker wedged in the terminal op.
// The broker builds the lease-scoped pinState from its Deps.lease SHARE (production
// code); the injected seam spawns a worker that value-captures that pinState (so it
// transitively co-owns the lease) PLUS the credential-cache/serializer/prompter/
// holder shares, then runs a RawCryptoFlow with a fake terminal op that blocks on
// @p latch and returns @p wedgeStatus on release. The whole composition (broker +
// lease + shares) is dropped while the worker is blocked; only the worker's captured
// shares keep it alive. On @p wedgeStatus == Ok the flow runs markPinVerified (the
// lease touch); on AuthFailed it runs cache.invalidate (the credential-cache touch)
// — both PAST the flow's post-prompt gate. @p completed flips true once the worker
// finishes its unwind. TSan-clean iff every past-the-gate touch hit co-owned memory.
void driveTerminalWedge(RawCryptoStatus wedgeStatus, Latch& latch, std::atomic<bool>& enteredTerminal,
                        std::atomic<bool>& completed)
{
    auto lease = std::make_shared<Pkcs11::LeaseManager>(
        Pkcs11::LeaseConfig{.idleTimeout = std::chrono::minutes(10), .maxLifetime = std::chrono::hours(8)});
    auto credentials = std::make_shared<CredentialCache>();
    auto serializer = std::make_shared<PromptSerializer>();
    std::shared_ptr<PrompterClientBase> prompter = std::make_shared<FastPinPrompter>();
    auto holder = makeDetachedHolder();
    AllowAllAuthorizer authz;

    const Pkcs11::LeaseKey key{.caller = CallerToken{":1.99"}, .card = kWedgeCard};
    lease->grant(key, std::chrono::steady_clock::now());

    std::thread worker;

    // The injected seam captures the REAL pinState (which co-owns the lease share)
    // and spawns the worker exactly as AgentCore::runRawCryptoOnWorker does: the
    // closure value-captures pinState + the cache/serializer/prompter/holder shares.
    auto seam = [&](const std::string&, const std::string&, Mechanism, const MechanismParams&,
                    std::span<const std::uint8_t>, const std::string&, const Pkcs11Broker::LeasePinState& pinState,
                    std::function<void(Pkcs11Broker::CryptoResult)>) {
        worker = std::thread([pinState, credentials, serializer, prompter, holder, wedgeStatus, &latch,
                              &enteredTerminal, &completed] {
            auto terminalOp = [&latch, &enteredTerminal,
                               wedgeStatus](const CandidateList&, const std::string&, std::span<const std::uint8_t>,
                                            const LibreSCRS::Secure::String*, LibreSCRS::SmartCard::CardSession&,
                                            LibreSCRS::CancelToken) -> RawCryptoResult {
                enteredTerminal.store(true, std::memory_order_release);
                latch.waitForRelease();
                if (wedgeStatus == RawCryptoStatus::Ok) {
                    return RawCryptoResult{RawCryptoStatus::Ok, {'S', 'I', 'G'}};
                }
                return RawCryptoResult{wedgeStatus, {}};
            };
            NullPhaseSink phaseSink;
            LibreSCRS::CancelSource flowCancel; // never cancelled: the flow proceeds past the gate into the terminal op
            RawCryptoFlow flow{RawCryptoFlowDeps{
                .holder = *holder,
                .prompter = *prompter,
                .serializer = *serializer,
                .cache = *credentials,
                .phaseSink = phaseSink,
                .cardKey = "card-A",
                .requester = "test-client",
                .certId = "abc123",
                .signOp = terminalOp,
                .decryptOp = terminalOp,
                .token = flowCancel.token(),
                .isPinVerified = pinState.isVerified,
                .markPinVerified = pinState.markVerified,
                .clearPinVerified = pinState.clearVerified,
            }};
            static_cast<void>(flow.runSign(kWedgeInput));
            completed.store(true, std::memory_order_release);
        });
    };

    auto broker = std::make_unique<Pkcs11Broker>(Pkcs11Broker::Deps{
        .lease = lease,
        .authorizer = authz,
        .certDer = [](const std::string&, const std::string&,
                      std::function<void(std::optional<std::vector<std::uint8_t>>)> done) { done(std::nullopt); },
        .publicKey = [](const std::string&, const std::string&,
                        std::function<void(std::optional<Pkcs11Broker::PublicKey>)> done) { done(std::nullopt); },
        .login = [](const std::string&,
                    std::function<void(Pkcs11Broker::LoginOutcome)> done) { done(Pkcs11Broker::LoginOutcome::Ok); },
        .signRaw = seam,
        .decrypt = seam,
        .resolveCardKey = [](const std::string&) { return std::optional<ObjectId>{kWedgeCard}; },
        .now = {},
    });

    // Fire the sign: the broker validates + touches the lease, builds pinState from
    // its lease SHARE, and hands it to the seam (spawning the worker). done is left
    // unfired (the shutdown-cancel skip analogue), so the broker continuation never
    // runs on the zombie.
    broker->signRaw("FakeReader", "abc123", Mechanism::RsaPkcs1Sign, MechParamsEmpty{}, kWedgeInput,
                    Pkcs11Broker::Caller{.busName = CallerToken{":1.99"}, .label = "test-client"},
                    Reply<Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>>{
                        [](const std::vector<std::uint8_t>&) {}, [](Pkcs11Broker::CryptoOutcome) {},
                        Pkcs11Broker::CryptoOutcome::CardError});

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!enteredTerminal.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(enteredTerminal.load(std::memory_order_acquire)) << "worker never reached the terminal op";

    // Every co-owned member has at least the composition's share + the worker's.
    EXPECT_GE(lease.use_count(), 2);
    EXPECT_GE(credentials.use_count(), 2);

    // Drop the composition while the worker is wedged PAST the flow gate: only the
    // worker's captured shares (broker's pinState co-owns the lease; the closure
    // co-owns the cache) keep the touched members alive now.
    broker.reset();
    lease.reset();
    credentials.reset();
    serializer.reset();
    prompter.reset();
    holder.reset();

    // Release the terminal op: the flow completes its past-the-gate unwind
    // (markPinVerified on the lease for Ok, cache.invalidate for AuthFailed) against
    // co-owned memory.
    latch.release();

    if (worker.joinable()) {
        worker.join();
    }
    EXPECT_TRUE(completed.load(std::memory_order_acquire)) << "the wedged worker never finished its unwind";
}

// Build an EstablishPaceChannel requirement for the given secret kind, the shape LM
// hands the read credential provider during plugin self-activation.
LibreSCRS::Auth::AuthRequirement paceReq(LibreSCRS::Auth::PaceSecretKind kind)
{
    return LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{}, kind, std::nullopt,
                                                           LibreSCRS::LocalizedText{});
}

} // namespace

// TERMINAL-WEDGE (lease): an abandoned raw-crypto worker wedged in the on-card op
// unblocks into markPinVerified — which reaches the lease THROUGH the broker's
// pinState callbacks. Those callbacks co-own the lease share (Pkcs11Broker::Deps.lease
// is a shared_ptr), so dropping the whole composition while the worker is blocked
// leaves the lease alive via the worker's value-captured pinState (TSan-clean).
// Reverting Deps.lease to a raw reference makes the pinState capture the broker
// `this`; dropping the broker then traps in markPinVerified — the RED proof.
TEST(PrompterKeepAliveDrain, TerminalWedgeKeepsLeaseAliveThroughBrokerPinState)
{
    Latch latch;
    std::atomic<bool> enteredTerminal{false};
    std::atomic<bool> completed{false};
    driveTerminalWedge(RawCryptoStatus::Ok, latch, enteredTerminal, completed);
}

// TERMINAL-WEDGE (credential cache): the same abandoned worker, but the on-card op
// returns AuthFailed, so on unblock the flow runs cache.invalidate PAST the gate.
// The worker value-captures the credential-cache share (as AgentCore's raw closure
// does), so the cache outlives the dropped composition (TSan-clean). Reverting the
// closure's credentials capture to a raw pointer traps in invalidate — the RED proof.
TEST(PrompterKeepAliveDrain, TerminalWedgeKeepsCredentialCacheAliveOnAuthFailedUnwind)
{
    Latch latch;
    std::atomic<bool> enteredTerminal{false};
    std::atomic<bool> completed{false};
    driveTerminalWedge(RawCryptoStatus::AuthFailed, latch, enteredTerminal, completed);
}

// READ-OP CAN/MRZ-PROMPT WEDGE (credential cache): the read flows have no signing
// PIN — they wedge in a nested CAN/MRZ prompt inside CredentialCache::requestCredential,
// then write putCan the instant the prompt returns Ok (below the flow gate, inside a
// provider that holds a bare &cache). This models that exact path: a worker that
// value-captures the cache share blocks in requestCan, the composition drops its
// cache share, then the release lets the worker run putCan against the co-owned
// cache (TSan-clean). Capturing the cache by raw pointer instead traps in putCan.
TEST(PrompterKeepAliveDrain, ReadCredentialPromptWedgeKeepsCredentialCacheAlive)
{
    using LibreSCRS::Auth::PaceSecretKind;

    Latch latch;
    std::atomic<bool> entered{false};
    std::atomic<bool> completed{false};

    auto credentials = std::make_shared<CredentialCache>();
    std::shared_ptr<PrompterClientBase> prompter = std::make_shared<CanWedgePrompter>(latch, entered);

    std::thread worker([credentials, prompter, &completed] {
        PromptOptions opts;
        opts.requester = "test-client";
        opts.artifact = "identity";
        // Exactly what FlowPrelude::makeReadCredentialProvider's lambda does on a
        // CAN cache miss: prompt (blocks), then putCan on Ok.
        static_cast<void>(credentials->requestCredential("card-A", paceReq(PaceSecretKind::Can), *prompter, opts));
        completed.store(true, std::memory_order_release);
    });

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "worker never reached the CAN prompt";
    EXPECT_GE(credentials.use_count(), 2);

    // Drop the composition's cache share while the worker is blocked in the prompt;
    // only the worker's captured share keeps the cache alive for the putCan below.
    credentials.reset();

    latch.release();

    if (worker.joinable()) {
        worker.join();
    }
    EXPECT_TRUE(completed.load(std::memory_order_acquire)) << "the wedged read worker never completed putCan";
}

// ---------------------------------------------------------------------------
// LOGIN-WEDGE drain proof. The login path raises NO consent prompt: its worker
// wedges in the uncancellable held-session acquire, and on unblock the login
// CONTINUATION (Pkcs11Broker::login) grants the PKCS#11 lease. Before the fix that
// continuation captured the broker `this` and reached the lease through
// m_deps.lease -> a freed-broker use-after-free on an abandoned login worker whose
// broker was already torn down. The continuation now co-owns the lease SHARE
// (captures `lease = m_deps.lease`), and the AgentCore login worker closure
// value-captures the whole crypto-worker context (for the shutdown skip). This
// drives the REAL Pkcs11Broker::login continuation with a worker wedged in a fake
// acquire, frees the composition (broker + lease) while it is parked, then releases
// the latch: the continuation's grant hits the co-owned lease (TSan-clean), or the
// shutdown skip fires and no grant happens. RED-proven during development by
// reverting the continuation to capture the broker `this`: dropping the broker then
// traps in lease->grant.
namespace {

// Drive the REAL Pkcs11Broker::login to a worker wedged in the (fake) held-session
// acquire. The seam spawns a worker that value-captures the crypto-worker context +
// the broker's login continuation (`done`) and blocks on @p latch; on release it
// mirrors AgentCore's login closure: skip on shutdown-cancel, else drive `done`.
// The whole composition (broker + lease + context) is dropped while the worker is
// blocked; only the worker's captured shares keep the lease alive. @p grantsObserved
// is bumped from the Reply's ok callback, which the continuation invokes after the
// grant — observable AFTER the composition is freed. TSan-clean iff the grant hits
// co-owned memory.
void driveLoginWedge(bool cancelBeforeRelease, Latch& latch, std::atomic<bool>& entered, std::atomic<bool>& completed,
                     std::atomic<int>& grantsObserved)
{
    auto lease = std::make_shared<Pkcs11::LeaseManager>(
        Pkcs11::LeaseConfig{.idleTimeout = std::chrono::minutes(10), .maxLifetime = std::chrono::hours(8)});
    LibreSCRS::CancelSource shutdownSource;
    // The single crypto-worker context the AgentCore login closure captures whole.
    auto ctx = std::make_shared<CryptoWorkerContext>(CryptoWorkerContext{
        .prompter = std::make_shared<FastPinPrompter>(),
        .serializer = std::make_shared<PromptSerializer>(),
        .credentials = std::make_shared<CredentialCache>(),
        .lease = lease,
        .shutdown = shutdownSource.token(),
    });
    AllowAllAuthorizer authz;

    std::thread worker;
    auto loginSeam = [&](const std::string&, std::function<void(Pkcs11Broker::LoginOutcome)> done) {
        worker = std::thread([done, ctx, &latch, &entered, &completed] {
            entered.store(true, std::memory_order_release);
            latch.waitForRelease();
            if (ctx->shutdown.isCancelled()) {
                completed.store(true, std::memory_order_release);
                return; // the AgentCore login closure's shutdown skip
            }
            done(Pkcs11Broker::LoginOutcome::Ok);
            completed.store(true, std::memory_order_release);
        });
    };

    auto broker = std::make_unique<Pkcs11Broker>(Pkcs11Broker::Deps{
        .lease = lease,
        .authorizer = authz,
        .certDer = [](const std::string&, const std::string&,
                      std::function<void(std::optional<std::vector<std::uint8_t>>)> done) { done(std::nullopt); },
        .publicKey = [](const std::string&, const std::string&,
                        std::function<void(std::optional<Pkcs11Broker::PublicKey>)> done) { done(std::nullopt); },
        .login = loginSeam,
        .signRaw = [](const std::string&, const std::string&, Mechanism, const MechanismParams&,
                      std::span<const std::uint8_t>, const std::string&, const Pkcs11Broker::LeasePinState&,
                      std::function<void(Pkcs11Broker::CryptoResult)>) {},
        .decrypt = [](const std::string&, const std::string&, Mechanism, const MechanismParams&,
                      std::span<const std::uint8_t>, const std::string&, const Pkcs11Broker::LeasePinState&,
                      std::function<void(Pkcs11Broker::CryptoResult)>) {},
        .resolveCardKey = [](const std::string&) { return std::optional<ObjectId>{kWedgeCard}; },
        .now = {},
    });

    broker->login("FakeReader", Pkcs11Broker::Caller{.busName = CallerToken{":1.99"}, .label = "test-client"},
                  Reply<Pkcs11Broker::LoginOutcome, std::uint32_t>{
                      [&grantsObserved](std::uint32_t) { grantsObserved.fetch_add(1, std::memory_order_acq_rel); },
                      [](Pkcs11Broker::LoginOutcome) {}, Pkcs11Broker::LoginOutcome::CardError});

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(entered.load(std::memory_order_acquire)) << "login worker never reached the wedge";

    // The continuation (held by `done`, held by the worker) co-owns the lease share,
    // and the worker's captured context co-owns it too.
    EXPECT_GE(lease.use_count(), 2);

    if (cancelBeforeRelease) {
        shutdownSource.requestCancel();
    }

    // Drop the whole composition while the worker is wedged: only the worker's
    // captured shares (the continuation's lease share + the context) keep the lease
    // alive now.
    broker.reset();
    lease.reset();
    ctx.reset();

    // Release the wedge: the worker either skips (cancelled) or runs the continuation
    // -> lease->grant on the co-owned lease share, all against co-owned memory.
    latch.release();

    if (worker.joinable()) {
        worker.join();
    }
    EXPECT_TRUE(completed.load(std::memory_order_acquire)) << "the wedged login worker never finished";
}

} // namespace

// Not cancelled: the login continuation runs lease->grant on the co-owned lease
// share AFTER the composition is freed -> live memory (TSan-clean), and the Reply's
// ok callback fires exactly once.
TEST(PrompterKeepAliveDrain, LoginWedgeKeepsLeaseAliveThroughContinuationCoOwnedLease)
{
    Latch latch;
    std::atomic<bool> entered{false};
    std::atomic<bool> completed{false};
    std::atomic<int> grantsObserved{0};
    driveLoginWedge(/*cancelBeforeRelease=*/false, latch, entered, completed, grantsObserved);
    EXPECT_EQ(grantsObserved.load(std::memory_order_acquire), 1)
        << "the login continuation must grant the lease through its co-owned share";
}

// Cancelled: the AgentCore login closure's shutdown skip fires, so the continuation
// is never invoked (no grant) and no torn-down member is touched (TSan-clean).
TEST(PrompterKeepAliveDrain, LoginWedgeSkipsGrantOnShutdownCancel)
{
    Latch latch;
    std::atomic<bool> entered{false};
    std::atomic<bool> completed{false};
    std::atomic<int> grantsObserved{0};
    driveLoginWedge(/*cancelBeforeRelease=*/true, latch, entered, completed, grantsObserved);
    EXPECT_EQ(grantsObserved.load(std::memory_order_acquire), 0)
        << "the shutdown skip must prevent the login continuation from running";
}
