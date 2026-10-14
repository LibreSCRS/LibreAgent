// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Agent-side security properties of the org.librescrs.Agent.Pkcs11_1 surface,
// exercised hermetically through Pkcs11Broker with injected seams +
// clock + LeaseManager (no card, no bus):
//   - authorization denial: a denying Authorizer makes Login throw NotAuthorized and
//     never drives the login seam;
//   - lease bounds: after Login, advancing the injected clock past the idle
//     timeout (and, separately, past the max-lifetime) makes SignRaw/Decrypt
//     throw UserNotLoggedIn; a fresh Login re-establishes the lease;
//   - no PIN / no plaintext in audit logs: std::clog is captured across a full
//     Login + SignRaw + Decrypt and asserted to contain the app label + a certId
//     PREFIX but NONE of the secret/plaintext byte material;
//   - PIN-prompt rate limit: every prompt the crypto seam raises asks the
//     broker's per-caller gate first -- rapid Login -> cold-first-op cycles from
//     ONE caller hit RateLimited after the per-caller cap (Login itself stays
//     un-throttled), and so do repeated prompts for a key the card marks under a
//     warm lease; warm-lease silent ops are neither throttled nor budgeted, and
//     the injected clock recovers a throttled caller deterministically.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include "Pkcs11BrokerTestSupport.h"
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <expected>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::testsupport;
using namespace std::chrono;

namespace {

constexpr const char* kReader = "/org/librescrs/Agent/reader/0";
constexpr const char* kCertId = "deadbeefcafef00d"; // 16-char id; only first 8 should ever be logged
const std::vector<std::uint8_t> kInput{0x01, 0x02, 0x03};
// Distinctive sentinel byte runs that must NEVER appear in the audit log.
const std::vector<std::uint8_t> kSecretSig{0xDE, 0xAD, 0xC0, 0xDE, 0x53, 0x49, 0x47};
const std::vector<std::uint8_t> kSecretPlain{0x50, 0x4C, 0x41, 0x49, 0x4E, 0xFE, 0xED};

Pkcs11Broker::Caller appCaller()
{
    return Pkcs11Broker::Caller{.busName = CallerToken{":1.42"}, .label = "firefox"};
}

struct DenyAll final : Authorizer
{
    AuthorizationOutcome authorize(std::string_view, const CallerToken&) override
    {
        return AuthorizationOutcome::Denied;
    }
};

// Allows every action but counts how many times it is consulted, so a test can
// assert the public-data reads never gate on the Authorizer at all.
struct CountingAuthorizer final : Authorizer
{
    int calls{0};
    AuthorizationOutcome authorize(std::string_view, const CallerToken&) override
    {
        ++calls;
        return AuthorizationOutcome::Granted;
    }
};

struct Harness
{
    std::shared_ptr<Pkcs11::LeaseManager> lease = std::make_shared<Pkcs11::LeaseManager>(
        Pkcs11::LeaseConfig{.idleTimeout = minutes(10), .maxLifetime = hours(8)});
    AllowAllAuthorizer authz;
    steady_clock::time_point clockNow{};

    std::optional<ObjectId> cardKey{ObjectId{7}};
    Pkcs11Broker::LoginOutcome loginOutcome{Pkcs11Broker::LoginOutcome::Ok};
    Pkcs11Broker::CryptoResult signResult{Pkcs11Broker::CryptoOutcome::Ok, kSecretSig};
    Pkcs11Broker::CryptoResult decryptResult{Pkcs11Broker::CryptoOutcome::Ok, kSecretPlain};

    int loginCalls{0};
    int signCalls{0};
    int decryptCalls{0};
    // When set, a successful crypto seam call marks the lease PIN-verified via
    // the pinState callback — exactly what the production RawCryptoFlow does
    // after the first op's prompt + PIN-presenting op succeed — so a test can put
    // the lease into the WARM (silent, no-prompt) state.
    bool markVerifiedOnCryptoOk{false};
    // PIN prompts the crypto seams raised (each one past the broker's prompt gate).
    int promptCount{0};
    bool promptEveryOp{false}; // the card marks the key: it prompts even under a warm lease

    Pkcs11Broker make(Authorizer& a)
    {
        return Pkcs11Broker{Pkcs11Broker::Deps{
            .lease = lease,
            .authorizer = a,
            .certDer =
                certDerSeam([](const std::string&, const std::string&) -> std::optional<std::vector<std::uint8_t>> {
                    return std::vector<std::uint8_t>{0x30};
                }),
            .publicKey = publicKeySeam([](const std::string&, const std::string&)
                                           -> std::expected<Pkcs11Broker::PublicKey, Pkcs11Broker::CryptoOutcome> {
                return Pkcs11Broker::PublicKey{
                    Operations::RsaPublicKey{.modulus = {0xAB}, .exponent = {0x01, 0x00, 0x01}}};
            }),
            .login = loginSeam([this](const std::string&) {
                ++loginCalls;
                return loginOutcome;
            }),
            .signRaw = cryptoSeam([this](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                         const std::string&, const Pkcs11Broker::LeasePinState& pinState) {
                // Emulates RawCryptoFlow: a prompt is raised on a cold lease, or
                // for a key the card marks, and every prompt asks the broker first.
                if (promptEveryOp || !pinState.isVerified()) {
                    if (!pinState.allowPrompt()) {
                        return Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::RateLimited, {}};
                    }
                    ++promptCount;
                }
                ++signCalls; // the card is reached only past the prompt
                if (markVerifiedOnCryptoOk && !promptEveryOp && signResult.outcome == Pkcs11Broker::CryptoOutcome::Ok &&
                    pinState.markVerified) {
                    pinState.markVerified();
                }
                return signResult;
            }),
            .decrypt = cryptoSeam([this](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                         const std::string&, const Pkcs11Broker::LeasePinState& pinState) {
                // Same prompt emulation as signRaw above.
                if (promptEveryOp || !pinState.isVerified()) {
                    if (!pinState.allowPrompt()) {
                        return Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::RateLimited, {}};
                    }
                    ++promptCount;
                }
                ++decryptCalls; // the card is reached only past the prompt
                if (markVerifiedOnCryptoOk && !promptEveryOp &&
                    decryptResult.outcome == Pkcs11Broker::CryptoOutcome::Ok && pinState.markVerified) {
                    pinState.markVerified();
                }
                return decryptResult;
            }),
            .resolveCardKey = [this](const std::string&) { return cardKey; },
            .now = [this]() { return clockNow; },
        }};
    }
    Pkcs11Broker make()
    {
        return make(authz);
    }
};

// Captures std::clog for the duration of a scope and exposes the text.
struct ClogCapture
{
    std::stringstream buf;
    std::streambuf* saved;
    ClogCapture() : saved(std::clog.rdbuf(buf.rdbuf())) {}
    ~ClogCapture()
    {
        std::clog.rdbuf(saved);
    }
    std::string text()
    {
        return buf.str();
    }
};

bool containsBytes(const std::string& hay, const std::vector<std::uint8_t>& needle)
{
    const std::string n(needle.begin(), needle.end());
    return hay.find(n) != std::string::npos;
}

} // namespace

// --- authorization denial --------------------------------------------------

TEST(Pkcs11Security, AuthzDenialBlocksLoginBeforeAnyCardOp)
{
    Harness h;
    DenyAll deny;
    auto obj = h.make(deny);
    try {
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        FAIL() << "expected NotAuthorized";
    } catch (Pkcs11Broker::LoginOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::LoginOutcome::NotAuthorized);
    }
    EXPECT_EQ(h.loginCalls, 0) << "a denied caller must never raise the prompter / touch the card";
    // And no lease was granted -> a follow-up SignRaw is not-logged-in.
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
}

// --- public-vs-private consent routing ------------------------------------

TEST(Pkcs11Security, PublicReadsNeverConsultAuthorizerOrLease)
{
    Harness h;
    CountingAuthorizer counting;
    auto obj = h.make(counting);
    // No Login at all: a public read must still succeed...
    EXPECT_NO_THROW(static_cast<void>(callCertDer(obj, kReader, kCertId, appCaller())));
    EXPECT_NO_THROW(static_cast<void>(callPublicKey(obj, kReader, kCertId, appCaller())));
    // ...without ever gating on the Authorizer...
    EXPECT_EQ(counting.calls, 0) << "public reads must not consult the Authorizer";
    // ...and without minting a lease (the lease is the private-op grant).
    EXPECT_FALSE(h.lease->isActive(Pkcs11::LeaseKey{.caller = CallerToken{":1.42"}, .card = *h.cardKey}, h.clockNow));
}

// --- lease bounds ---------------------------------------------------------

TEST(Pkcs11Security, IdleTimeoutInvalidatesLeaseThenReloginWorks)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller())); // grant at t=0
    h.clockNow += minutes(11);                               // past the 10-min idle bound, no touch
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn for an idle-expired lease";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
    // A fresh Login re-establishes the lease; the next op succeeds.
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
    EXPECT_EQ(h.loginCalls, 2);
}

TEST(Pkcs11Security, MaxLifetimeInvalidatesLeaseEvenWhenBusy)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller())); // grant at t=0
    // Keep it busy every 5 min so idle never trips, but max-lifetime (8h) caps it.
    for (int i = 1; i <= 90; ++i) {
        h.clockNow += minutes(5);
        EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
    }
    h.clockNow = steady_clock::time_point{} + hours(8) + minutes(1);
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn past the max-lifetime cap";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
    static_cast<void>(callLogin(obj, kReader, appCaller())); // re-login resets the origin
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
}

// --- no PIN / no plaintext in audit logs ----------------------------------

TEST(Pkcs11Security, AuditLogsCarryNoSecretOrPlaintextBytes)
{
    Harness h;
    auto obj = h.make();
    std::string log;
    {
        ClogCapture cap;
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        static_cast<void>(callDecrypt(obj, kReader, kCertId, kInput, appCaller()));
        log = cap.text();
    }
    // Sanity: the audit trail IS present (app label + a certId prefix).
    EXPECT_NE(log.find("firefox"), std::string::npos) << "missing the per-call app attribution";
    EXPECT_NE(log.find("deadbeef"), std::string::npos) << "missing the certId prefix";
    // The FULL certId must NOT appear (only the 8-char prefix is loggable).
    EXPECT_EQ(log.find("deadbeefcafef00d"), std::string::npos) << "full certId leaked into the log";
    // No secret signature / plaintext byte material anywhere.
    EXPECT_FALSE(containsBytes(log, kSecretSig)) << "signature bytes leaked into the audit log";
    EXPECT_FALSE(containsBytes(log, kSecretPlain)) << "decrypt plaintext leaked into the audit log";
    EXPECT_FALSE(containsBytes(log, kInput)) << "operation input bytes leaked into the audit log";
}

// --- PIN-prompt rate limit ----------------------------------------------------
// A PIN prompt is raised by the cold-lease FIRST SignRaw/Decrypt of a lease and
// by every op with a key the card marks for consent per operation, so a peer
// looping Login -> first-op could otherwise pop an unbounded series of PIN
// dialogs. Every prompt asks the broker's per-caller gate (LeasePinState::
// allowPrompt; same policy + unique-bus-name key as the Card1.Sign throttle)
// first; the harness seams emulate the flow asking it. Login itself must stay
// un-throttled (a consumer re-logs in with CKU_CONTEXT_SPECIFIC before every
// operation with a key whose CKA_ALWAYS_AUTHENTICATE is TRUE), and warm-lease
// silent ops must neither be throttled nor consume budget.

using Operations::RateLimiter;

TEST(Pkcs11Security, ColdFirstOpFloodHitsRateLimitWhileLoginStaysUnthrottled)
{
    Harness h;
    auto obj = h.make();
    // N rapid Login -> cold-first-op cycles from ONE caller: each re-grant resets
    // the lease's verified flag, so every SignRaw is a prompt-raising first op.
    // All of them fit the per-caller window cap.
    for (std::size_t i = 0; i < RateLimiter::kMaxPerWindow; ++i) {
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()))) << "cycle " << i;
    }
    // The next Login is STILL accepted — Login is non-prompting and never
    // rate-limited (a login cap would reject legitimate multi-sign sessions).
    EXPECT_NO_THROW(static_cast<void>(callLogin(obj, kReader, appCaller())));
    EXPECT_EQ(h.loginCalls, static_cast<int>(RateLimiter::kMaxPerWindow) + 1);
    // ...but its cold first-op is over the cap: refused RateLimited by the
    // prompt gate the flow asks first: no prompt is raised and the card is not
    // reached (in production the cold prompt is charged before the card session
    // is opened).
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected RateLimited for the over-cap cold first-op";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::RateLimited);
    }
    EXPECT_EQ(h.signCalls, static_cast<int>(RateLimiter::kMaxPerWindow)) << "the denied op must never reach the card";
    // Decrypt raises the same PIN prompt on a cold lease, so it shares the gate:
    // the same over-budget caller is denied there too, before the card.
    try {
        static_cast<void>(callDecrypt(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected RateLimited for the cold-lease Decrypt of a throttled caller";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::RateLimited);
    }
    EXPECT_EQ(h.decryptCalls, 0);
    // The budget is per caller (keyed on the reuse-immune unique bus name): a
    // different caller's legitimate single Login -> first-op is unaffected.
    const Pkcs11Broker::Caller other{.busName = CallerToken{":1.99"}, .label = "kleopatra"};
    EXPECT_NO_THROW(static_cast<void>(callLogin(obj, kReader, other)));
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, other)));
}

TEST(Pkcs11Security, WarmLeaseOpsAreNeverThrottledAndConsumeNoBudget)
{
    Harness h;
    h.markVerifiedOnCryptoOk = true; // the seam marks the lease verified, like production
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    // Cold first op: prompts, consumes exactly ONE budget slot, warms the lease.
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
    // Warm-lease silent ops, far past the window cap: never throttled.
    for (std::size_t i = 0; i < 3 * RateLimiter::kMaxPerWindow; ++i) {
        EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()))) << "warm op " << i;
    }
    EXPECT_NO_THROW(static_cast<void>(callDecrypt(obj, kReader, kCertId, kInput, appCaller())))
        << "Decrypt rides the same warm lease silently";
    // And they consumed ZERO budget: the remaining (cap - 1) COLD first-ops (each
    // behind a fresh re-Login that resets the verified flag) still fit...
    for (std::size_t i = 1; i < RateLimiter::kMaxPerWindow; ++i) {
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())))
            << "cold first-op " << i;
    }
    // ...and only the (cap + 1)th cold first-op is denied.
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected RateLimited once the cold-first-op budget is spent";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::RateLimited);
    }
    // Seam-call arithmetic: 1 cold + 15 warm signs + 4 cold re-logins = 20 signs,
    // 1 warm decrypt; the denied op never ran.
    EXPECT_EQ(h.signCalls, static_cast<int>(4 * RateLimiter::kMaxPerWindow));
    EXPECT_EQ(h.decryptCalls, 1);
}

TEST(Pkcs11Security, ThrottledCallerRecoversAfterWindowAndBackoff)
{
    Harness h;
    auto obj = h.make();
    for (std::size_t i = 0; i < RateLimiter::kMaxPerWindow; ++i) {
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
    }
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected RateLimited";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::RateLimited);
    }
    // Not a permanent lockout: past the sliding window AND any escalated backoff
    // (still well inside the 10-min lease idle bound) the caller recovers. The
    // limiter runs on the SAME injected clock as the lease, so this is
    // deterministic — no sleeps.
    h.clockNow += RateLimiter::kWindow + RateLimiter::kMaxBackoff + seconds(1);
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
}

TEST(Pkcs11Security, EveryPromptIsChargedNotOnlyALeasesFirst)
{
    // A key the card marks asks for the PIN on every use, warm lease or not.
    // Each of those prompts is one a looping peer could raise, so each is
    // charged: past the per-caller cap the next one is refused unraised.
    Harness h;
    h.markVerifiedOnCryptoOk = true;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()))); // warms the lease
    h.promptEveryOp = true;
    for (std::size_t i = 1; i < RateLimiter::kMaxPerWindow; ++i) {
        EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()))) << "prompt " << i;
    }
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected RateLimited for a prompt past the cap under a warm lease";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::RateLimited);
    }
    EXPECT_EQ(h.promptCount, static_cast<int>(RateLimiter::kMaxPerWindow));
}

// NOTE: the per-app decrypt-confirm knob was REMOVED — it was a
// verified no-op (the prompter has only RequestSecret, no no-secret confirm
// primitive to back it), and shipping a no-op security toggle is misleading. The
// former DecryptConfirmKnobReachesTheSeam test re-read the flag inside a fake
// seam, so it never exercised production behaviour. Decrypt rides the lease like
// sign (audited per op). The control can return once the prompter grows a real
// confirm-only method.
