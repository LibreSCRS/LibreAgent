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
//     PREFIX but NONE of the secret/plaintext byte material.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include "Pkcs11BrokerTestSupport.h"
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
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
    bool authorize(std::string_view, const CallerToken&) override
    {
        return false;
    }
};

// Allows every action but counts how many times it is consulted, so a test can
// assert the public-data reads never gate on the Authorizer at all.
struct CountingAuthorizer final : Authorizer
{
    int calls{0};
    bool authorize(std::string_view, const CallerToken&) override
    {
        ++calls;
        return true;
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

    Pkcs11Broker make(Authorizer& a)
    {
        return Pkcs11Broker{Pkcs11Broker::Deps{
            .lease = lease,
            .authorizer = a,
            .certDer =
                certDerSeam([](const std::string&, const std::string&) -> std::optional<std::vector<std::uint8_t>> {
                    return std::vector<std::uint8_t>{0x30};
                }),
            .publicKey =
                publicKeySeam([](const std::string&, const std::string&) -> std::optional<Pkcs11Broker::PublicKey> {
                    return Pkcs11Broker::PublicKey{.modulus = {0xAB}, .exponent = {0x01, 0x00, 0x01}};
                }),
            .login = loginSeam([this](const std::string&) {
                ++loginCalls;
                return loginOutcome;
            }),
            .signRaw = cryptoSeam([this](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                         const std::string&, const Pkcs11Broker::LeasePinState&) {
                ++signCalls;
                return signResult;
            }),
            .decrypt = cryptoSeam([this](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                         const std::string&, const Pkcs11Broker::LeasePinState&) {
                ++decryptCalls;
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

// NOTE: the per-app decrypt-confirm knob (spec §5 D3.4) was REMOVED — it was a
// verified no-op (the prompter has only RequestSecret, no no-secret confirm
// primitive to back it), and shipping a no-op security toggle is misleading. The
// former DecryptConfirmKnobReachesTheSeam test re-read the flag inside a fake
// seam, so it never exercised production behaviour. Decrypt rides the lease like
// sign (audited per op). The control can return once the prompter grows a real
// confirm-only method.
