// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/Logging.h>

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
      // The first-op prompt limiter shares the broker's injected clock seam so
      // tests drive the window/backoff deterministically; production leaves the
      // seam empty and both run on steady_clock.
      m_rateLimiter(m_deps.now ? m_deps.now
                               : Operations::RateLimiter::Clock{[] { return std::chrono::steady_clock::now(); }})
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
                             Reply<CryptoOutcome, std::vector<std::uint8_t>, std::vector<std::uint8_t>> reply)
{
    // Public data (the RSA modulus + exponent live in the cert): no consent, no
    // lease, no authz — same posture as CertDer.
    const auto cardKey = m_deps.resolveCardKey(reader);
    if (!cardKey) {
        reply.fail(CryptoOutcome::UnknownCard);
        return;
    }
    m_deps.publicKey(reader, certId,
                     [reply, label = caller.label, idPrefix = certIdPrefix(certId)](std::optional<PublicKey> pk) {
                         if (!pk) {
                             reply.fail(CryptoOutcome::KeyNotFound);
                             return;
                         }
                         if (pk->modulus.empty() || pk->exponent.empty()) {
                             // Resolved, but the key is not RSA (no modulus/exponent to serve).
                             reply.fail(CryptoOutcome::NotSupported);
                             return;
                         }
                         log::infof("pkcs11: PublicKey cert={} caller={}", idPrefix, label);
                         reply.ok(pk->modulus, pk->exponent);
                     });
}

void Pkcs11Broker::login(const std::string& reader, const Caller& caller, Reply<LoginOutcome, std::uint32_t> reply)
{
    // Authorize the CLIENT (default-allow; site policy may restrict), keyed on
    // the unique bus name, BEFORE raising any card op. Login is deliberately NOT
    // rate-limited: it is optimistic + non-prompting (the login seam
    // only opens the channel — no PIN prompt), so there is no reflexive-PIN
    // surface to throttle here; and CKA_ALWAYS_AUTHENTICATE makes consumers issue
    // a Login(CKU_CONTEXT_SPECIFIC) before every sign, so a per-window login cap
    // would reject legitimate multi-sign sessions with CKR_FUNCTION_REJECTED. The
    // anti-phishing flood throttle lives on the consent surface (Card1.Sign).
    if (!m_deps.authorizer.authorize(kActionPkcs11Login, caller.busName)) {
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

void Pkcs11Broker::runCrypto(const char* opName, Mechanism allowedMechanism, const CryptoSeam& seam,
                             Mechanism mechanism, const MechanismParams& params, const std::string& reader,
                             const std::string& certId, std::span<const std::uint8_t> bytes, const Caller& caller,
                             Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    // Mechanism gate (fail-closed): the seam wires exactly ONE primitive for this
    // path. Any other arm is NOT wired end-to-end and would otherwise be run as
    // RSA-PKCS#1 v1.5 by the seam, so reject it as NotSupported BEFORE resolving
    // the card, touching the lease, or handing anything to the worker. Mechanism
    // support is public (PKCS#11 C_GetMechanismList), so surfacing it ahead of the
    // lease gate leaks nothing.
    if (mechanism != allowedMechanism) {
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

    // Anti-phishing throttle on the PKCS#11 PIN-prompt surface (parity with the
    // Card1.Sign throttle; same reuse-immune unique-bus-name key). ONLY the
    // cold-lease FIRST op is gated: that is the op that raises the PIN-as-consent
    // prompt (the flow prompts iff the lease is not yet PIN-verified), and it is
    // what a malicious peer loops via Login -> first-op to pop unbounded PIN
    // dialogs — Login itself stays un-throttled (see login()). Warm-lease ops are
    // silent, so they are never throttled and consume no budget (the
    // short-circuit keeps allow() unconsulted). Placed AFTER the lease gate so a
    // lease-less call is a plain UserNotLoggedIn (it raises no prompt) and never
    // charges the budget. The verified flag is read on the dispatch thread while
    // a worker may flip it; that race is benign for a throttle (at worst one
    // budget slot charged to an op that turned warm in flight).
    if (!m_deps.lease->isPinVerified(key) && !m_rateLimiter.allow(caller.busName)) {
        // Over the cap: fail closed BEFORE the seam runs — no prompt is raised,
        // no card I/O is enqueued, and the flood surfaces as a hard error.
        reply.fail(CryptoOutcome::RateLimited);
        return;
    }

    // Lease-scoped PIN-verified state (PIN-as-consent): the seam prompts +
    // verifies the PIN only on the FIRST op of the lease, then marks it verified;
    // subsequent ops skip the re-prompt. Only the boolean crosses this boundary —
    // never the PIN. Bound to THIS call's LeaseKey.
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
    };

    // Thread the caller's display label as the prompt requester so the
    // PIN-as-consent dialog names the app asking (never blank). The continuation
    // runs on the worker thread when the card op completes; it owns everything it
    // touches (by-value caller / key / cardKey + the Reply) except the broker
    // `this` its AuthFailed arm derefs — guarded by the token re-check below.
    seam(reader, certId, mechanism, params, bytes, caller.label, pinState,
         [this, shutdown = m_deps.shutdown, reply, key, opName, label = caller.label, card = *cardKey,
          idPrefix = certIdPrefix(certId)](CryptoResult result) {
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
             // / Cancelled / CardError). A CryptoResult is seam output, so it never
             // carries a broker-gate value (UnknownCard / UserNotLoggedIn /
             // RateLimited).
             reply.fail(result.outcome);
         });
}

void Pkcs11Broker::signRaw(const std::string& reader, const std::string& certId, Mechanism mechanism,
                           const MechanismParams& params, std::span<const std::uint8_t> input, const Caller& caller,
                           Reply<CryptoOutcome, std::vector<std::uint8_t>> reply)
{
    runCrypto("SignRaw", Mechanism::RsaPkcs1Sign, m_deps.signRaw, mechanism, params, reader, certId, input, caller,
              std::move(reply));
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
    runCrypto("Decrypt", Mechanism::RsaPkcs1Decrypt, m_deps.decrypt, mechanism, params, reader, certId, ciphertext,
              caller, std::move(reply));
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
