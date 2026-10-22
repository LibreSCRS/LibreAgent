// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // CallerToken, ObjectId
#include <LibreSCRS/Agent/Reply.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <LibreSCRS/CancelToken.h>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
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
// class does the cheap bus-thread validation SYNCHRONOUSLY (authz /
// card-resolve / lease gate; the PIN-prompt budget is asked on the worker, see
// below) and, on failure, fulfils the Reply with an error
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
// SECURITY / POLICY:
//  - CertDer / PublicKey are public data: no consent, no lease, audited at info.
//  - Login is authorization-gated (kActionPkcs11Login); it establishes a lease for
//    (caller, card). It is OPTIMISTIC + non-prompting (only opens the channel);
//    PIN-as-consent is collected by the crypto ops (see below). It is NOT
//    rate-limited: it raises no consent prompt, and a consumer issues
//    Login(CKU_CONTEXT_SPECIFIC) before every operation with a key whose
//    CKA_ALWAYS_AUTHENTICATE is TRUE, so a per-window login cap would reject
//    legitimate multi-sign sessions. The anti-phishing flood throttle lives on
//    the consent surfaces: Card1.Sign and the PIN prompts below.
//  - SignRaw / Decrypt are lease-gated (touch() else UserNotLoggedIn), NOT
//    re-authorized (the lease IS the grant) but EVERY call is audited.
//  - Every PIN prompt the raw-crypto flow raises is rate-limited per caller
//    (RateLimiter policy, keyed on the reuse-immune unique bus name, same as the
//    Card1.Sign throttle) through LeasePinState::allowPrompt, asked on the
//    worker immediately before the prompt: the first op of a lease, every op
//    with a key the card marks for consent per operation, and the recovery
//    re-prompt. A refused prompt is never raised: a cold-lease prompt is
//    refused before the card session is even opened, a re-prompt before the
//    operation is retried; either way the op fails RateLimited. Ops that raise
//    no prompt are never throttled and consume no budget.
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

    // A certificate's public key: an RSA modulus + exponent (unpadded
    // big-endian, the PKCS#11 CKA_* convention) or an EC point on a NIST curve
    // (fixed-width x and y). Any other key has no public key on this surface.
    using PublicKey = Operations::CertPublicKey;

    // Hermetic outcome of a raw crypto op, mirroring RawCryptoFlow::Outcome but
    // kept wire/LM-free here so the host stays unit-testable. The seam produces
    // the first six values and RateLimited (a PIN prompt the per-caller budget
    // refused); UnknownCard / UserNotLoggedIn are broker-synthesized GATE
    // outcomes (no card / no live lease) that a CryptoResult from the seam never
    // sets. The backend (dbus/Pkcs11OutcomeNames) maps each to its wire error
    // name.
    enum class CryptoOutcome : std::uint8_t {
        Ok,
        Cancelled,
        KeyNotFound,
        AuthFailed,
        NotSupported,
        CardError,
        // broker gates:
        UnknownCard,
        UserNotLoggedIn,
        /// The caller exceeded the per-caller budget for PIN prompts
        /// (anti-phishing throttle, RateLimiter policy). Produced by the seam,
        /// not the broker: the flow asks before every prompt. The backend maps
        /// it to the same wire error as the Card1.Sign throttle
        /// (Error.RateLimited). Append-only: added after UserNotLoggedIn,
        /// never reordered.
        RateLimited,
        /// The request does not fit the key -- a mechanism of the other family,
        /// an input of the wrong length, a peer point off the key's curve --
        /// refused by the agent before any PIN prompt. Produced by the seam;
        /// the lease is untouched. The backend maps it to InvalidRequest.
        /// Append-only: added after RateLimited.
        InvalidInput,
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
    // prompts for the PIN only on the FIRST op of a lease and skips the
    // re-prompt on subsequent ops (the held channel persists the on-card verified
    // state) -- except for a key the card marks for consent per operation, which
    // prompts every time. NEVER carries the PIN — only the boolean and the
    // prompt gate. Bound to the call's LeaseKey and caller before invoking the
    // seam.
    struct LeasePinState
    {
        std::function<bool()> isVerified;    // true => skip the prompt
        std::function<void()> markVerified;  // set after a PIN-presenting op succeeds
        std::function<void()> clearVerified; // reset when a PIN-less op finds the channel dropped
        std::function<bool()> allowPrompt;   // asked before EVERY PIN prompt; false = the caller is over its budget
    };

    // --- Async card-op seams ----------------------------------------------
    // Each seam ENQUEUES the card I/O onto the per-reader worker and returns the
    // dispatch thread immediately; @p done is invoked ON THE WORKER THREAD with
    // the outcome (and, for the teardown/abandon path, may never be invoked — the
    // Reply's fail-closed destructor covers that). The seam (and @p done) must
    // capture only by value / shared_ptr — the dispatch frame is long gone by the
    // time the worker runs. Tests inject seams that complete @p done inline.

    // CertDer / PublicKey seams: resolve certId -> DER / public key off the card
    // on @p reader. CertDer: nullopt on miss (-> Error.KeyNotFound). PublicKey:
    // KeyNotFound when the certificate is absent, NotSupported when its key is
    // neither RSA nor EC on a NIST curve.
    using CertDerSeam = std::function<void(const std::string& reader, const std::string& certId,
                                           std::function<void(std::optional<std::vector<std::uint8_t>>)> done)>;
    using PublicKeySeam = std::function<void(const std::string& reader, const std::string& certId,
                                             std::function<void(std::expected<PublicKey, CryptoOutcome>)> done)>;

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
        CryptoSeam derive; // ECDH, CKD_NULL: bytes are the peer's point
        ResolveCardKeySeam resolveCardKey;
        // Agent-wide shutdown-cancel token. The runCrypto completion wrapper
        // value-captures a copy so it can re-check cancellation immediately
        // before its AuthFailed lease revoke — the wrapper's only raw broker
        // deref — and skip the completion when teardown began after the
        // worker's own pre-completion check had already passed (the dropped
        // reply then fails closed at drain). Defaults to a never-cancellable
        // token, which keeps the re-check inert for hosts that join every
        // worker before tearing the broker down.
        LibreSCRS::CancelToken shutdown{};
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
    // body (consent is by private-key use).
    void certDer(const std::string& reader, const std::string& certId, const Caller& caller,
                 Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);
    void publicKey(const std::string& reader, const std::string& certId, const Caller& caller,
                   Reply<CryptoOutcome, PublicKey> reply);
    void login(const std::string& reader, const Caller& caller, Reply<LoginOutcome, std::uint32_t> reply);
    void signRaw(const std::string& reader, const std::string& certId, Mechanism mechanism,
                 const MechanismParams& params, std::span<const std::uint8_t> input, const Caller& caller,
                 Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);
    void decrypt(const std::string& reader, const std::string& certId, Mechanism mechanism,
                 const MechanismParams& params, std::span<const std::uint8_t> ciphertext, const Caller& caller,
                 Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);
    // ECDH with the card's key (CKM_ECDH1_DERIVE, CKD_NULL): lease-gated and
    // audited like SignRaw. @p params must be MechParamsEcdh with kdf ==
    // kEcdhKdfNull and no shared data -- anything else is NotSupported, never
    // run as plain ECDH. The reply carries the raw secret Z.
    void derive(const std::string& reader, const std::string& certId, const MechanismParams& params,
                const Caller& caller, Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);

    // Logout is synchronous: pure lease bookkeeping, no card I/O.
    void logout(const std::string& reader, const Caller& caller);

    // Whether @p caller's lease on the card in @p reader still holds. Asking
    // neither extends the lease nor touches what it records about the PIN: a
    // PKCS#11 module asks this every second for its loader. Synchronous, no
    // card I/O; false for a reader with no card.
    [[nodiscard]] bool loginActive(const std::string& reader, const Caller& caller);

    // Lease invalidation hooks, called by the agent's card-removal /
    // client-disconnect observers. Thread-safe via LeaseManager's own mutex.
    void onCardRemoved(ObjectId cardKey);
    void onClientDisconnected(const CallerToken& client);

private:
    // Shared SignRaw/Decrypt/Derive body: FIRST reject any @p mechanism NOT in the set
    // this path wires (fail-closed NotSupported). The signRaw seam runs exactly
    // the mechanism it is handed — RsaPkcs1Sign, Sha256RsaPkcs1Sign or
    // EcdsaSign, all on MechParamsEmpty; the decrypt seam runs RsaPkcs1Decrypt;
    // the derive seam runs EcdhDerive (CKD_NULL, checked by derive()).
    // Every other arm (RSA-PSS / OAEP / the
    // public-key encrypt arms) stays rejected here: forwarding one would run it
    // as the seam's default primitive. Then lease-gate (touch) synchronously and
    // run the seam on the worker; the continuation forwards the seam
    // CryptoOutcome to @p reply (bytes on Ok), revokes the lease on auth-fail,
    // audits, and fulfils @p reply. @p opName is the audit/log label
    // ("SignRaw"|"Decrypt"|"Derive").
    void runCrypto(const char* opName, std::initializer_list<Mechanism> allowedMechanisms, const CryptoSeam& seam,
                   Mechanism mechanism, const MechanismParams& params, const std::string& reader,
                   const std::string& certId, std::span<const std::uint8_t> bytes, const Caller& caller,
                   Reply<CryptoOutcome, std::vector<std::uint8_t>> reply);

    [[nodiscard]] std::chrono::steady_clock::time_point nowOr() const;

    Deps m_deps;
    // Per-caller throttle for every PIN prompt the raw-crypto flow raises (see
    // the SECURITY/POLICY block above). Broker-owned so the limit is ACTIVE in
    // every composition that hands LeasePinState::allowPrompt to the flow; it
    // runs on the SAME clock seam as the lease (Deps::now), so tests drive both
    // deterministically. Its budget is independent of the host's Card1.Sign
    // limiter — the two consent surfaces are throttled separately, with
    // identical policy constants. Shared: the prompt gate handed to the worker
    // co-owns it, because an abandoned worker can ask it after this broker is
    // gone.
    std::shared_ptr<Operations::RateLimiter> m_rateLimiter;
};

} // namespace LibreSCRS::Agent
