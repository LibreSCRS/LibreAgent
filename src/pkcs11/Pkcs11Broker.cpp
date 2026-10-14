// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Agent/backend/Logging.h>

#include <algorithm>
#include <utility>

namespace LibreSCRS::Agent {

namespace {

// First 8 hex chars of a certId for logs — never log the full id (links a
// caller to a specific key across log lines) and NEVER log secret bytes.
std::string certIdPrefix(const std::string& certId)
{
    return certId.substr(0, std::min<std::size_t>(certId.size(), 8));
}

} // namespace

Pkcs11Broker::Pkcs11Broker(Deps deps)
    : m_deps(std::move(deps)),
      // The PIN-prompt limiter shares the broker's injected clock seam so tests
      // drive the window/backoff deterministically; production leaves the seam
      // empty and both run on steady_clock.
      m_rateLimiter(std::make_shared<Operations::RateLimiter>(
          m_deps.now ? m_deps.now : Operations::RateLimiter::Clock{[] { return std::chrono::steady_clock::now(); }}))
{}

std::chrono::steady_clock::time_point Pkcs11Broker::nowOr() const
{
    return m_deps.now ? m_deps.now() : std::chrono::steady_clock::now();
}

void Pkcs11Broker::certDer(const std::string& reader, const std::string& certId, const Caller& caller,
                           Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    // Public data: no consent, no lease, no authz. Still resolve the card so a
    // bogus reader path is a clean UnknownCard rather than an empty DER.
    const auto cardKey = m_deps.resolveCardKey(reader);
    if (!cardKey) {
        reply.fail(CryptoOutcome::UnknownCard);
        return;
    }
    // Hand the card read to the worker; fulfil the deferred reply on completion.
    // The continuation captures only by value (label/certId) + the Reply, so it
    // is valid after the dispatch thread has long returned.
    m_deps.certDer(
        reader, certId,
        [reply, label = caller.label, idPrefix = certIdPrefix(certId)](std::optional<std::vector<std::uint8_t>> der) {
            if (!der) {
                reply.fail(CryptoOutcome::KeyNotFound);
                return;
            }
            log::infof("pkcs11: CertDer cert={} caller={}", idPrefix, label);
            reply.ok(*der);
        });
}

void Pkcs11Broker::publicKey(const std::string& reader, const std::string& certId, const Caller& caller,
                             Reply<CryptoOutcome, PublicKey> reply)
{
    // Public data (the key lives in the cert): no consent, no lease, no authz --
    // same posture as CertDer.
    const auto cardKey = m_deps.resolveCardKey(reader);
    if (!cardKey) {
        reply.fail(CryptoOutcome::UnknownCard);
        return;
    }
    m_deps.publicKey(
        reader, certId,
        [reply, label = caller.label, idPrefix = certIdPrefix(certId)](std::expected<PublicKey, CryptoOutcome> pk) {
            if (!pk) {
                reply.fail(pk.error());
                return;
            }
            log::infof("pkcs11: PublicKey cert={} caller={}", idPrefix, label);
            reply.ok(*pk);
        });
}

void Pkcs11Broker::login(const std::string& reader, const Caller& caller, Reply<LoginOutcome, std::uint32_t> reply)
{
    // Authorize the CLIENT (default-allow; site policy may restrict), keyed on
    // the unique bus name, BEFORE raising any card op. Login is deliberately NOT
    // rate-limited: it is optimistic + non-prompting (the login seam
    // only opens the channel — no PIN prompt), so there is no reflexive-PIN
    // surface to throttle here; and a consumer issues Login(CKU_CONTEXT_SPECIFIC)
    // before every operation with a key whose CKA_ALWAYS_AUTHENTICATE is TRUE,
    // so a per-window login cap would reject legitimate multi-sign sessions with
    // CKR_FUNCTION_REJECTED. The anti-phishing flood throttle lives on the
    // consent surfaces (Card1.Sign, and every PIN prompt of a crypto op).
    //
    // Undecided folds into the same refusal here -- default-allow means polkit
    // answers without a dialog, there is no human waiting on this leg, and the
    // PKCS#11 caller has no user to tell.
    if (m_deps.authorizer.authorize(kActionPkcs11Login, caller.busName) != AuthorizationOutcome::Granted) {
        reply.fail(LoginOutcome::NotAuthorized);
        return;
    }
    const auto cardKey = m_deps.resolveCardKey(reader);
    if (!cardKey) {
        reply.fail(LoginOutcome::UnknownCard);
        return;
    }

    // Establish the card channel once. DECISION (baked in): Login grants the
    // lease OPTIMISTICALLY once the channel opens; the FIRST SignRaw/Decrypt is
    // what actually verifies the PIN on-card. If that first op returns AuthFailed
    // the lease is revoked (see runCrypto) so the next call re-prompts. This keeps
    // the wire contract simple (Login = "I have a card + a human") and never
    // caches the PIN.
    //
    // The continuation runs on the per-reader WORKER thread; a login worker
    // abandoned while blocked in the uncancellable channel acquire outlives this
    // broker. So it co-owns the lease SHARE (captures `lease = m_deps.lease`, NOT
    // the broker `this`) and captures the clock seam + the fixed idle-timeout by
    // value — mirroring the pinState callbacks below — so on unblock it grants
    // through its own captured lease rather than dereferencing a freed broker.
    m_deps.login(reader, [lease = m_deps.lease, now = m_deps.now,
                          idleSecs = static_cast<std::uint32_t>(m_deps.lease->idleTimeout().count()), reply, caller,
                          card = *cardKey](LoginOutcome outcome) {
        switch (outcome) {
        case LoginOutcome::Ok:
            break;
        case LoginOutcome::Cancelled:
            // User declined the PIN/CAN prompt: surface Cancelled so the module
            // reports CKR_FUNCTION_CANCELED (a declined consent is not a fault).
            reply.fail(LoginOutcome::Cancelled);
            return;
        case LoginOutcome::NotAuthorizedByCard:
            reply.fail(LoginOutcome::NotAuthorizedByCard);
            return;
        case LoginOutcome::CardError:
            reply.fail(LoginOutcome::CardError);
            return;
        case LoginOutcome::UnknownCard:
        case LoginOutcome::NotAuthorized:
            // Broker-gate values: they are synthesized on the dispatch thread
            // before the seam runs, so the login seam can never return them.
            // Fail closed to a card error if one ever appears here.
            reply.fail(LoginOutcome::CardError);
            return;
        }
        lease->grant(Pkcs11::LeaseKey{.caller = caller.busName, .card = card},
                     now ? now() : std::chrono::steady_clock::now());
        log::infof("pkcs11: Login granted card={} caller={}", card.value(), caller.label);
        reply.ok(idleSecs);
    });
}

void Pkcs11Broker::logout(const std::string& reader, const Caller& caller)
{
    const auto cardKey = m_deps.resolveCardKey(reader);
    if (!cardKey) {
        // Idempotent: a logout for an absent card is a clean no-op (the lease,
        // if any, was already revoked on card removal).
        return;
    }
    m_deps.lease->revoke(Pkcs11::LeaseKey{.caller = caller.busName, .card = *cardKey});
    log::infof("pkcs11: Logout card={} caller={}", cardKey->value(), caller.label);
}

void Pkcs11Broker::runCrypto(const char* opName, std::initializer_list<Mechanism> allowedMechanisms,
                             const CryptoSeam& seam, Mechanism mechanism, const MechanismParams& params,
                             const std::string& reader, const std::string& certId, std::span<const std::uint8_t> bytes,
                             const Caller& caller, Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    // Mechanism gate (fail-closed): this path wires a fixed SET of primitives.
    // Any arm outside it is NOT wired end-to-end and would otherwise be run as
    // the seam's default primitive, so reject it as NotSupported BEFORE resolving
    // the card, touching the lease, or handing anything to the worker. Mechanism
    // support is public (PKCS#11 C_GetMechanismList), so surfacing it ahead of the
    // lease gate leaks nothing.
    if (std::find(allowedMechanisms.begin(), allowedMechanisms.end(), mechanism) == allowedMechanisms.end()) {
        reply.fail(CryptoOutcome::NotSupported);
        return;
    }
    // A host that wires no seam for this operation does not run it: refused
    // like an unwired mechanism, never an exception out of the caller's thread.
    if (!seam) {
        reply.fail(CryptoOutcome::NotSupported);
        return;
    }
    const auto cardKey = m_deps.resolveCardKey(reader);
    if (!cardKey) {
        reply.fail(CryptoOutcome::UnknownCard);
        return;
    }
    const Pkcs11::LeaseKey key{.caller = caller.busName, .card = *cardKey};

    // Lease gate: touch() returns false (and reaps) when no live lease exists,
    // which the module maps to CKR_USER_NOT_LOGGED_IN. A live lease is the
    // grant — the op is NOT re-authorized — but it IS audited below. touch()
    // also bumps the idle clock, so a busy app keeps its lease alive.
    if (!m_deps.lease->touch(key, nowOr())) {
        reply.fail(CryptoOutcome::UserNotLoggedIn);
        return;
    }

    // Lease-scoped PIN-verified state (PIN-as-consent): the seam prompts for the
    // PIN on the FIRST op of the lease, then marks it verified; subsequent ops
    // skip the re-prompt unless the card marks the key for consent per
    // operation. Only the boolean and the prompt gate cross this boundary —
    // never the PIN. Bound to THIS call's LeaseKey and caller.
    //
    // Each callback CO-OWNS the lease (captures a shared_ptr copy, NOT the broker
    // `this`): the raw-crypto worker value-captures this pinState, so a worker
    // abandoned while blocked in the consent prompt touches the lease through its
    // own captured share on unblock — never the freed broker, never a freed lease —
    // even after this broker is gone (markPinVerified on a successful sign, or
    // clearPinVerified on the verify-state-loss recovery path, both PAST the flow's
    // post-prompt cancel gate).
    const LeasePinState pinState{
        .isVerified = [lease = m_deps.lease, key]() { return lease->isPinVerified(key); },
        .markVerified = [lease = m_deps.lease, key]() { lease->markPinVerified(key); },
        .clearVerified = [lease = m_deps.lease, key]() { lease->clearPinVerified(key); },
        // Every PIN prompt the flow raises -- a cold lease's first, a key the
        // card marks for consent per operation, the recovery re-prompt -- asks
        // this first, on the worker, so each prompt is charged and none is
        // raised over the cap. Co-owns the limiter (see m_rateLimiter).
        .allowPrompt = [limiter = m_rateLimiter, caller = caller.busName]() { return limiter->allow(caller); },
    };

    // Thread the caller's display label as the prompt requester so the
    // PIN-as-consent dialog names the app asking (never blank). The continuation
    // runs on the worker thread when the card op completes; it owns everything it
    // touches (by-value caller / key / cardKey + the Reply) except the broker
    // `this` its AuthFailed arm derefs — guarded by the token re-check below.
    seam(reader, certId, mechanism, params, bytes, caller.label, pinState,
         [this, shutdown = m_deps.shutdown, reply, key, opName, label = caller.label, card = *cardKey,
          idPrefix = certIdPrefix(certId)](CryptoResult result) {
             // A plaintext or a derived secret: this copy is wiped on every way
             // out, once the reply has taken its own.
             const LibreSCRS::Agent::SecureZeroOnExit wipe{result.bytes};
             if (result.outcome == CryptoOutcome::Ok) {
                 // Audit EVERY op (caller identity + op + certId prefix), never the
                 // bytes. Decrypt is a local oracle, so the same line
                 // covers both — the app id (label) is the per-call attribution.
                 log::infof("pkcs11: {} OK card={} caller={} cert={}", opName, card.value(), label, idPrefix);
                 reply.ok(result.bytes);
                 return;
             }
             if (result.outcome == CryptoOutcome::AuthFailed) {
                 // Wrong PIN / card blocked: revoke the lease so the next op
                 // re-prompts. The LeaseManager mutex makes this worker-thread
                 // revoke safe against the bus thread's lease reads. The revoke is
                 // also this wrapper's ONLY raw broker deref: the raw-crypto worker
                 // skips the completion when the shutdown token is already
                 // cancelled, but a cancellation can land AFTER that check with
                 // this wrapper in flight, and the broker may then be freed within
                 // the abandon grace. Re-check the token — the value-captured copy,
                 // so the check itself touches no broker state — immediately before
                 // the deref and skip the completion when tripped; the dropped
                 // reply fails closed at drain. Residual: a cancellation landing
                 // between this check and the revoke is still possible (a token
                 // check narrows the window to these two adjacent statements; only
                 // a join could eliminate it), still bounded by the teardown grace.
                 if (shutdown.isCancelled()) {
                     return;
                 }
                 m_deps.lease->revoke(key);
                 log::infof("pkcs11: {} auth-failed card={} caller={} (lease revoked)", opName, card.value(), label);
             }
             // Forward the seam outcome 1:1 (KeyNotFound / AuthFailed / NotSupported
             // / Cancelled / CardError, RateLimited when the flow's prompt gate
             // refused a prompt, and InvalidInput when the request does not fit
             // the key -- the lease stays). A CryptoResult never carries a
             // broker-gate value (UnknownCard / UserNotLoggedIn).
             reply.fail(result.outcome);
         });
}

void Pkcs11Broker::signRaw(const std::string& reader, const std::string& certId, Mechanism mechanism,
                           const MechanismParams& params, std::span<const std::uint8_t> input, const Caller& caller,
                           Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    // Three sign primitives are wired, each run as itself on MechParamsEmpty.
    runCrypto("SignRaw", {Mechanism::RsaPkcs1Sign, Mechanism::Sha256RsaPkcs1Sign, Mechanism::EcdsaSign}, m_deps.signRaw,
              mechanism, params, reader, certId, input, caller, std::move(reply));
}

void Pkcs11Broker::decrypt(const std::string& reader, const std::string& certId, Mechanism mechanism,
                           const MechanismParams& params, std::span<const std::uint8_t> ciphertext,
                           const Caller& caller, Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    // Decrypt rides the same lease as sign: a live lease
    // is the grant, every op is audited in runCrypto. The optional per-app
    // decrypt-confirmation knob was removed: the prompter has no no-secret
    // confirmation primitive (only RequestSecret), so the knob was a verified
    // no-op — a misleading security toggle. It can return as a real control once
    // the prompter grows a confirm-only method (a 3-component addition).
    runCrypto("Decrypt", {Mechanism::RsaPkcs1Decrypt}, m_deps.decrypt, mechanism, params, reader, certId, ciphertext,
              caller, std::move(reply));
}

void Pkcs11Broker::derive(const std::string& reader, const std::string& certId, const MechanismParams& params,
                          const Caller& caller, Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    // Only the raw secret is wired. A key-derivation function arrives as a
    // request of its own, so a KDF named here is refused rather than ignored.
    const auto* ecdh = std::get_if<MechParamsEcdh>(&params);
    if (ecdh == nullptr || ecdh->kdf != kEcdhKdfNull || !ecdh->sharedData.empty()) {
        reply.fail(CryptoOutcome::NotSupported);
        return;
    }
    runCrypto("Derive", {Mechanism::EcdhDerive}, m_deps.derive, Mechanism::EcdhDerive, params, reader, certId,
              ecdh->peerPublicPoint, caller, std::move(reply));
}

void Pkcs11Broker::onCardRemoved(ObjectId cardKey)
{
    m_deps.lease->revokeCard(cardKey);
}

void Pkcs11Broker::onClientDisconnected(const CallerToken& client)
{
    m_deps.lease->revokeCaller(client);
}

} // namespace LibreSCRS::Agent
