// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // CallerToken, ObjectId
#include <LibreSCRS/Agent/Reply.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

class Authorizer;

// Implements the org.librescrs.Agent.Pkcs11_1 surface (CertDer / PublicKey /
// Login / Logout / SignRaw / Decrypt) hosted ONCE on the manager path
// /org/librescrs/Agent. Composed INTO the manager frontend (the backend
// transport hosts a single object per path, so the Pkcs11_1 surface rides on the
// same object as Manager1 + Config1; the frontend forwards the virtuals straight
// here).
//
// ASYNC HANDOFF: every card-touching method is an async backend method. This
// class does the cheap bus-thread validation SYNCHRONOUSLY (authz / rate-limit /
// card-resolve / lease gate) and, on failure, fulfils the Reply with an error
// inline — still off the dispatch thread instantly. The actual card I/O is run
// by the injected seam on the per-reader WORKER thread; the seam invokes a
// continuation (built here, capturing the Reply + lease key) on completion that
// does the post-processing (lease revoke on auth-fail, audit) and fulfils the
// Reply. The dispatch thread is therefore released the moment validation passes
// and the work is enqueued — the bus loop is never parked on an in-flight op.
//
// This class deliberately holds NO backend transport/connection handle of its
// own: card I/O must run on the per-reader worker thread (the CardSessionHolder
// is worker-thread-only), while the inbound method dispatches on the frontend
// thread. The
// async worker hop is injected as function seams (production wires them through
// OperationManager::enqueueOnReaderWorker; unit tests inject card-free, bus-free
// fakes that complete inline). The caller identity is also injected per call by
// the backend (resolved while the in-flight message is current).
//
// SECURITY / POLICY (spec §4-§6):
//  - CertDer / PublicKey are public data: no consent, no lease, audited at info.
//  - Login is authorization-gated (kActionPkcs11Login); it establishes a lease for
//    (caller, card). It is OPTIMISTIC + non-prompting (only opens the channel);
//    PIN-as-consent is collected on the FIRST crypto op of the lease. It is NOT
//    rate-limited: it raises no consent prompt, and CKA_ALWAYS_AUTHENTICATE makes
//    consumers issue a Login(CKU_CONTEXT_SPECIFIC) before EVERY sign, so a
//    per-window login cap would reject legitimate multi-sign sessions. The
//    anti-phishing flood throttle lives on the consent surfaces: Card1.Sign and
//    the cold-lease first op below.
//  - SignRaw / Decrypt are lease-gated (touch() else UserNotLoggedIn), NOT
//    re-authorized (the lease IS the grant) but EVERY call is audited.
//  - The COLD-LEASE FIRST op (lease not yet PIN-verified — the one op that
//    raises the PIN-as-consent prompt) is additionally rate-limited per caller
//    (RateLimiter policy, keyed on the reuse-immune unique bus name, same as the
//    Card1.Sign throttle). This bounds the Login -> first-op loop a malicious
//    same-user peer could otherwise drive to pop unbounded PIN dialogs.
//    Warm-lease silent ops are never throttled and consume no budget; an
//    over-cap call fails closed with CryptoOutcome::RateLimited before any
//    prompt or card I/O.
//  - The lease key's caller component is the unique bus name (reuse-immune for
//    the connection lifetime); the requester label is display/audit only.
class Pkcs11Broker
{
public:
    // Per-call caller identity, resolved by the backend from the in-flight
    // message (opaque CallerToken for authz + lease key; label for audit/chrome).
    struct Caller
    {
        CallerToken busName; // opaque connecting-peer identity — lease key + authz
        std::string label;   // sanitised display label — audit only
    };

    // RSA public key components (unpadded big-endian, PKCS#11 CKA_* convention).
    struct PublicKey
    {
        std::vector<std::uint8_t> modulus;
        std::vector<std::uint8_t> exponent;
    };

    // Hermetic outcome of a raw crypto op, mirroring RawCryptoFlow::Outcome but
    // kept wire/LM-free here so the host stays unit-testable. The seam produces
    // the first six values; UnknownCard / UserNotLoggedIn / RateLimited are
    // broker-synthesized GATE outcomes (no card / no live lease / prompt-flood
    // cap) — a CryptoResult never sets them. The backend (dbus/Pkcs11OutcomeNames)
    // maps each to its wire error name.
    enum class CryptoOutcome : std::uint8_t {
        Ok,
        Cancelled,
        KeyNotFound,
        AuthFailed,
        NotSupported,
        CardError,
        // broker gates (not seam-produced):
        UnknownCard,
        UserNotLoggedIn,
        /// The caller exceeded the per-caller budget for PIN-prompt-raising
        /// cold-lease first ops (anti-phishing throttle, RateLimiter policy);
        /// the backend maps it to the same wire error as the Card1.Sign
        /// throttle (Error.RateLimited). Append-only: added after
        /// UserNotLoggedIn, never reordered.
        RateLimited,
    };
    struct CryptoResult
    {
        CryptoOutcome outcome{CryptoOutcome::CardError}; // fails closed
        std::vector<std::uint8_t> bytes;
    };

    // Login = open + classify the card channel on @p reader (no PIN prompt: the
    // PIN is collected on the first crypto op). The lease is granted on success.
    // The seam produces the first four values; UnknownCard / NotAuthorized are
    // broker-synthesized GATE outcomes (no card / client not authorized) — the
    // login seam never returns them. The backend maps each to its wire name.
    enum class LoginOutcome : std::uint8_t {
        Ok,
        Cancelled,
        NotAuthorizedByCard,
        CardError,
        // broker gates (not seam-produced):
        UnknownCard,
        NotAuthorized,
    };

    // Lease-scoped PIN-verified state passed INTO the crypto seam so the flow
    // prompts + verifies the PIN only on the FIRST op of a lease and skips the
    // re-prompt on subsequent ops (the held channel persists the on-card verified
    // state). NEVER carries the PIN — only the boolean. Bound to the call's
    // LeaseKey before invoking the seam.
    struct LeasePinState
    {
        std::function<bool()> isVerified;    // true => skip the prompt + verify
        std::function<void()> markVerified;  // set after a verify+op both succeed
        std::function<void()> clearVerified; // reset when a verify-skipped op finds the channel dropped
    };

    // --- Async card-op seams ----------------------------------------------
    // Each seam ENQUEUES the card I/O onto the per-reader worker and returns the
    // dispatch thread immediately; @p done is invoked ON THE WORKER THREAD with
    // the outcome (and, for the teardown/abandon path, may never be invoked — the
    // Reply's fail-closed destructor covers that). The seam (and @p done) must
    // capture only by value / shared_ptr — the dispatch frame is long gone by the
    // time the worker runs. Tests inject seams that complete @p done inline.

    // CertDer / PublicKey seams: resolve certId -> DER / RSA(modulus,exponent) off
    // the card on @p reader. nullopt on miss (-> Error.KeyNotFound); an engaged
    // PublicKey with EMPTY fields signals "resolved but not RSA" (-> NotSupported).
    using CertDerSeam = std::function<void(const std::string& reader, const std::string& certId,
                                           std::function<void(std::optional<std::vector<std::uint8_t>>)> done)>;
    using PublicKeySeam = std::function<void(const std::string& reader, const std::string& certId,
                                             std::function<void(std::optional<PublicKey>)> done)>;

    // Login seam: open + classify the card channel on @p reader; @p done carries
    // whether the channel was established (the lease is granted on Ok).
    using LoginSeam = std::function<void(const std::string& reader, std::function<void(LoginOutcome)> done)>;

    // Sign / Decrypt seams: run the raw crypto op on @p reader for @p certId over
    // @p bytes. @p mechanism + @p params carry the requested primitive (the core
    // wires only RsaPkcs1Sign/RsaPkcs1Decrypt + MechParamsEmpty; future EC/ECDH/RSA-OAEP
    // arms are additive with no signature change). @p pinState carries the
    // lease-scoped verified flag (PIN never crosses this boundary). @p requester is
    // the caller's display label, threaded so the PIN-as-consent prompt names the
    // app asking. @p done carries the CryptoResult.
    using CryptoSeam = std::function<void(const std::string& reader, const std::string& certId, Mechanism mechanism,
                                          const MechanismParams& params, std::span<const std::uint8_t> bytes,
                                          const std::string& requester, const LeasePinState& pinState,
                                          std::function<void(CryptoResult)> done)>;

    // reader routing token -> the card's opaque ObjectId (the lease key's card
    // component). nullopt when no card is present.
    using ResolveCardKeySeam = std::function<std::optional<ObjectId>(const std::string& reader)>;

    using NowSeam = std::function<std::chrono::steady_clock::time_point()>;

    struct Deps
    {
        // The lease manager is held as a shared_ptr (an internal composition type,
        // NOT a backend interface) so the PIN-verified-state callbacks bound below
        // (isVerified/markVerified/clearVerified) can CO-OWN it: a raw-crypto worker
        // abandoned while blocked in the consent prompt value-captures those
        // callbacks and, on unblock, touches the lease through its captured share —
        // never a freed referent — even after this broker is gone.
        std::shared_ptr<Pkcs11::LeaseManager> lease;
        Authorizer& authorizer;
        CertDerSeam certDer;
        PublicKeySeam publicKey;
        LoginSeam login;
        CryptoSeam signRaw;
        CryptoSeam decrypt;
        ResolveCardKeySeam resolveCardKey;
        NowSeam now{}; // defaults to steady_clock::now
    };

    explicit Pkcs11Broker(Deps deps);

    // The async card-touching methods. The backend forwards to these after
    // resolving the caller, handing each a Reply that production binds to the
    // backend result sink and tests bind to capturing lambdas. Each validates
    // synchronously (fulfilling @p reply with an error on a failed gate) then
    // hands the card I/O to the worker, which fulfils @p reply on completion.

    // Public data: no Authorizer gate, no lease, no PIN — audited at info. The
    // future RSA public-key encrypt (Mechanism::RsaPkcs1Encrypt) joins THIS
    // no-consent path via a dedicated EncryptSeam, NOT the lease-gated runCrypto
    // body (spec §8; consent is by private-key use).
    void certDer(const std::string& reader, const std::string& certId, const Caller& caller,
                 Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);
    void publicKey(const std::string& reader, const std::string& certId, const Caller& caller,
                   Reply<CryptoOutcome, std::vector<std::uint8_t>, std::vector<std::uint8_t>> reply);
    void login(const std::string& reader, const Caller& caller, Reply<LoginOutcome, std::uint32_t> reply);
    void signRaw(const std::string& reader, const std::string& certId, Mechanism mechanism,
                 const MechanismParams& params, std::span<const std::uint8_t> input, const Caller& caller,
                 Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);
    void decrypt(const std::string& reader, const std::string& certId, Mechanism mechanism,
                 const MechanismParams& params, std::span<const std::uint8_t> ciphertext, const Caller& caller,
                 Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);

    // Logout is synchronous: pure lease bookkeeping, no card I/O.
    void logout(const std::string& reader, const Caller& caller);

    // Lease invalidation hooks, called by the agent's card-removal /
    // client-disconnect observers. Thread-safe via LeaseManager's own mutex.
    void onCardRemoved(ObjectId cardKey);
    void onClientDisconnected(const CallerToken& client);

private:
    // Shared SignRaw/Decrypt body: FIRST reject any @p mechanism other than the
    // single wired @p allowedMechanism for this path (fail-closed NotSupported) —
    // the seam is hard-wired to one primitive (SignRaw -> RsaPkcs1Sign, Decrypt ->
    // RsaPkcs1Decrypt), so forwarding a non-wired arm (RSA-PSS / ECDSA / OAEP / the
    // public-key encrypt arms) would silently run it as RSA-PKCS#1 v1.5. Then
    // lease-gate (touch) synchronously and run the seam on the worker; the
    // continuation forwards the seam CryptoOutcome to @p reply (bytes on Ok),
    // revokes the lease on auth-fail, audits, and fulfils @p reply. @p opName is
    // the audit/log label ("SignRaw"|"Decrypt").
    void runCrypto(const char* opName, Mechanism allowedMechanism, const CryptoSeam& seam, Mechanism mechanism,
                   const MechanismParams& params, const std::string& reader, const std::string& certId,
                   std::span<const std::uint8_t> bytes, const Caller& caller,
                   Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);

    [[nodiscard]] std::chrono::steady_clock::time_point nowOr() const;

    Deps m_deps;
    // Per-caller throttle for the PIN-prompt-raising cold-lease first op (see the
    // SECURITY/POLICY block above). Broker-owned so the limit is ACTIVE in every
    // composition with no host wiring; it runs on the SAME clock seam as the
    // lease (Deps::now), so tests drive both deterministically. Its budget is
    // independent of the host's Card1.Sign limiter — the two consent surfaces
    // are throttled separately, with identical policy constants.
    Operations::RateLimiter m_rateLimiter;
};

} // namespace LibreSCRS::Agent
