// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic, card-free, bus-free exercise of Pkcs11Broker — the logic behind the
// org.librescrs.Agent.Pkcs11_1 surface. The card I/O (CertDerExport,
// RawCryptoFlow) and the worker-thread hop are injected as function seams, the
// clock is injected, and the LeaseManager runs in-process. The thin transport
// forwarding (ManagerObject -> these methods + caller resolution) is covered by
// the backend's D-Bus introspection test.
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "Pkcs11BrokerTestSupport.h"
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include "fakes/FakeAgentTransport.h"
#include "fakes/FakeAuthorizer.h"
#include "fakes/FakePrompter.h"
#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::testsupport;
using namespace std::chrono;

namespace {

constexpr const char* kReader = "/org/librescrs/Agent/reader/0";
constexpr const char* kCertId = "abc123";
const std::vector<std::uint8_t> kDer{0xde, 0xad, 0xbe, 0xef};
const std::vector<std::uint8_t> kInput{0x01, 0x02, 0x03};

Pkcs11Broker::Caller appCaller()
{
    return Pkcs11Broker::Caller{.busName = CallerToken{":1.42"}, .label = "firefox"};
}

// Drive signRaw/decrypt with an ARBITRARY mechanism (the testsupport helpers
// hardcode the single wired arm), returning the terminal CryptoOutcome: Ok maps
// to CryptoOutcome::Ok, a failure returns its fail Outcome. Throws if the reply
// was not fulfilled inline (a wiring bug).
Pkcs11Broker::CryptoOutcome signRawMechanismOutcome(Pkcs11Broker& obj, Mechanism m, const Pkcs11Broker::Caller& caller)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    auto cap = std::make_shared<std::optional<CO>>();
    obj.signRaw(kReader, kCertId, m, MechParamsEmpty{}, kInput, caller,
                Reply<CO, std::vector<std::uint8_t>>{[cap](const std::vector<std::uint8_t>&) { *cap = CO::Ok; },
                                                     [cap](CO oc) { *cap = oc; }, CO::CardError});
    if (!cap->has_value()) {
        throw std::logic_error{"signRaw reply not fulfilled inline"};
    }
    return **cap;
}

Pkcs11Broker::CryptoOutcome decryptMechanismOutcome(Pkcs11Broker& obj, Mechanism m, const Pkcs11Broker::Caller& caller)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    auto cap = std::make_shared<std::optional<CO>>();
    obj.decrypt(kReader, kCertId, m, MechParamsEmpty{}, kInput, caller,
                Reply<CO, std::vector<std::uint8_t>>{[cap](const std::vector<std::uint8_t>&) { *cap = CO::Ok; },
                                                     [cap](CO oc) { *cap = oc; }, CO::CardError});
    if (!cap->has_value()) {
        throw std::logic_error{"decrypt reply not fulfilled inline"};
    }
    return **cap;
}

// Drives Pkcs11Broker with controllable seams + an injected clock.
struct Harness
{
    std::shared_ptr<Pkcs11::LeaseManager> lease = std::make_shared<Pkcs11::LeaseManager>(
        Pkcs11::LeaseConfig{.idleTimeout = minutes(10), .maxLifetime = hours(8)});
    AllowAllAuthorizer authz;

    // Injected clock the lease reads through Pkcs11Broker::nowOr.
    steady_clock::time_point clockNow{};

    // Seam control knobs. The card is now an opaque per-insertion ObjectId.
    std::optional<ObjectId> cardKey{ObjectId{7}};
    std::optional<std::vector<std::uint8_t>> certDerResult{kDer};
    std::optional<Pkcs11Broker::PublicKey> publicKeyResult{
        Pkcs11Broker::PublicKey{.modulus = {0xAB, 0xCD}, .exponent = {0x01, 0x00, 0x01}}};
    Pkcs11Broker::LoginOutcome loginOutcome{Pkcs11Broker::LoginOutcome::Ok};
    Pkcs11Broker::CryptoResult signResult{Pkcs11Broker::CryptoOutcome::Ok, {'S', 'I', 'G'}};
    Pkcs11Broker::CryptoResult decryptResult{Pkcs11Broker::CryptoOutcome::Ok, {'P', 'T'}};

    int loginCalls{0};
    int signCalls{0};
    int decryptCalls{0};
    // The requester (caller display label) the crypto seam last received, so a
    // test can assert it reaches the PIN-as-consent prompt (never blank).
    std::string capturedSignRequester;
    std::string capturedDecryptRequester;

    Pkcs11Broker make()
    {
        return Pkcs11Broker{Pkcs11Broker::Deps{
            .lease = lease,
            .authorizer = authz,
            .certDer = certDerSeam([this](const std::string&, const std::string&) { return certDerResult; }),
            .publicKey = publicKeySeam([this](const std::string&, const std::string&) { return publicKeyResult; }),
            .login = loginSeam([this](const std::string&) {
                ++loginCalls;
                return loginOutcome;
            }),
            .signRaw = cryptoSeam([this](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                         const std::string& requester, const Pkcs11Broker::LeasePinState&) {
                ++signCalls;
                capturedSignRequester = requester;
                return signResult;
            }),
            .decrypt = cryptoSeam([this](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                         const std::string& requester, const Pkcs11Broker::LeasePinState&) {
                ++decryptCalls;
                capturedDecryptRequester = requester;
                return decryptResult;
            }),
            .resolveCardKey = [this](const std::string&) { return cardKey; },
            .now = [this]() { return clockNow; },
        }};
    }
};

} // namespace

// --- CertDer + Login/Logout -----------------------------------------------

TEST(Pkcs11Broker, CertDerReturnsDerForKnownCert)
{
    Harness h;
    auto obj = h.make();
    EXPECT_EQ(callCertDer(obj, kReader, kCertId, appCaller()), kDer);
}

TEST(Pkcs11Broker, CertDerThrowsKeyNotFoundOnMiss)
{
    Harness h;
    h.certDerResult = std::nullopt;
    auto obj = h.make();
    try {
        static_cast<void>(callCertDer(obj, kReader, kCertId, appCaller()));
        FAIL() << "expected KeyNotFound";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::KeyNotFound);
    }
}

TEST(Pkcs11Broker, CertDerThrowsUnknownCardWhenNoCard)
{
    Harness h;
    h.cardKey = std::nullopt;
    auto obj = h.make();
    try {
        static_cast<void>(callCertDer(obj, kReader, kCertId, appCaller()));
        FAIL() << "expected UnknownCard";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UnknownCard);
    }
}

// PublicKey is public data (no consent/lease) returning the RSA
// modulus + exponent the crypto-free module serves as CKA_MODULUS /
// CKA_PUBLIC_EXPONENT.
TEST(Pkcs11Broker, PublicKeyReturnsModulusAndExponent)
{
    Harness h;
    auto obj = h.make();
    const auto pk = callPublicKey(obj, kReader, kCertId, appCaller());
    EXPECT_EQ(pk.modulus, (std::vector<std::uint8_t>{0xAB, 0xCD}));
    EXPECT_EQ(pk.exponent, (std::vector<std::uint8_t>{0x01, 0x00, 0x01}));
}

TEST(Pkcs11Broker, PublicKeyThrowsKeyNotFoundOnMiss)
{
    Harness h;
    h.publicKeyResult = std::nullopt;
    auto obj = h.make();
    try {
        static_cast<void>(callPublicKey(obj, kReader, kCertId, appCaller()));
        FAIL() << "expected KeyNotFound";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::KeyNotFound);
    }
}

TEST(Pkcs11Broker, PublicKeyThrowsNotSupportedWhenNotRsa)
{
    Harness h;
    // Resolved (engaged optional) but EMPTY fields == "not an RSA key".
    h.publicKeyResult = Pkcs11Broker::PublicKey{};
    auto obj = h.make();
    try {
        static_cast<void>(callPublicKey(obj, kReader, kCertId, appCaller()));
        FAIL() << "expected NotSupported";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::NotSupported);
    }
}

TEST(Pkcs11Broker, PublicKeyThrowsUnknownCardWhenNoCard)
{
    Harness h;
    h.cardKey = std::nullopt;
    auto obj = h.make();
    try {
        static_cast<void>(callPublicKey(obj, kReader, kCertId, appCaller()));
        FAIL() << "expected UnknownCard";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UnknownCard);
    }
}

TEST(Pkcs11Broker, LoginGrantsLeaseAndReturnsIdleTimeout)
{
    Harness h;
    auto obj = h.make();
    const std::uint32_t idle = callLogin(obj, kReader, appCaller());
    EXPECT_EQ(idle, 600u); // 10 min idle timeout
    EXPECT_EQ(h.loginCalls, 1);
    // The lease is now active for (caller, card): a SignRaw rides it.
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())));
}

TEST(Pkcs11Broker, LoginRejectedWhenAuthorizerDenies)
{
    struct DenyAll final : Authorizer
    {
        bool authorize(std::string_view, const CallerToken&) override
        {
            return false;
        }
    };
    Harness h;
    DenyAll deny;
    Pkcs11Broker obj{Pkcs11Broker::Deps{
        .lease = h.lease,
        .authorizer = deny,
        .certDer = certDerSeam([&](const std::string&, const std::string&) { return h.certDerResult; }),
        .publicKey = publicKeySeam([&](const std::string&, const std::string&) { return h.publicKeyResult; }),
        .login = loginSeam([&](const std::string&) { return h.loginOutcome; }),
        .signRaw = cryptoSeam([&](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                  const std::string&, const Pkcs11Broker::LeasePinState&) { return h.signResult; }),
        .decrypt = cryptoSeam([&](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                  const std::string&, const Pkcs11Broker::LeasePinState&) { return h.decryptResult; }),
        .resolveCardKey = [&](const std::string&) { return h.cardKey; },
        .now = [&]() { return h.clockNow; },
    }};
    try {
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        FAIL() << "expected NotAuthorized";
    } catch (Pkcs11Broker::LoginOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::LoginOutcome::NotAuthorized);
    }
}

TEST(Pkcs11Broker, LoginCancelledByUserSurfacesCancelled)
{
    Harness h;
    h.loginOutcome = Pkcs11Broker::LoginOutcome::Cancelled;
    auto obj = h.make();
    try {
        static_cast<void>(callLogin(obj, kReader, appCaller()));
        FAIL() << "expected Cancelled";
    } catch (Pkcs11Broker::LoginOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::LoginOutcome::Cancelled);
    }
    // No lease was granted.
    EXPECT_FALSE(h.lease->isActive(Pkcs11::LeaseKey{.caller = CallerToken{":1.42"}, .card = *h.cardKey}, h.clockNow));
}

TEST(Pkcs11Broker, LogoutRevokesLease)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    obj.logout(kReader, appCaller());
    // SignRaw now fails not-logged-in.
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn after logout";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
}

TEST(Pkcs11Broker, LogoutIsIdempotentWithNoCard)
{
    Harness h;
    h.cardKey = std::nullopt;
    auto obj = h.make();
    EXPECT_NO_THROW(obj.logout(kReader, appCaller()));
}

// --- SignRaw / Decrypt (lease-gated + audited) ----------------------------

TEST(Pkcs11Broker, SignRawWithoutLoginThrowsUserNotLoggedIn)
{
    Harness h;
    auto obj = h.make();
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
    EXPECT_EQ(h.signCalls, 0) << "no card op without a lease";
}

TEST(Pkcs11Broker, SignRawWithinLeaseReturnsBytes)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    const auto sig = callSignRaw(obj, kReader, kCertId, kInput, appCaller());
    EXPECT_EQ(sig, (std::vector<std::uint8_t>{'S', 'I', 'G'}));
    EXPECT_EQ(h.signCalls, 1);
}

TEST(Pkcs11Broker, CryptoSeamReceivesTheCallerLabelAsRequester)
{
    // PIN-as-consent is the security model, so the prompt must name the app
    // asking. The host threads Caller::label into the crypto seam as the
    // requester — never blank — for both SignRaw and Decrypt.
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
    EXPECT_EQ(h.capturedSignRequester, "firefox") << "SignRaw threads the caller label to the prompt";
    static_cast<void>(callDecrypt(obj, kReader, kCertId, kInput, appCaller()));
    EXPECT_EQ(h.capturedDecryptRequester, "firefox") << "Decrypt threads the caller label to the prompt";
}

TEST(Pkcs11Broker, SignRawTouchExtendsIdleClock)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller())); // grant at t=0
    h.clockNow += minutes(9);
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()))); // touch at t=9
    h.clockNow += minutes(9);                                                                    // t=18, < 9+10
    EXPECT_NO_THROW(static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller())))
        << "the touch at t=9 kept the lease alive past the original 10-min idle";
}

TEST(Pkcs11Broker, SignRawExpiredLeaseThrowsUserNotLoggedIn)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    h.clockNow += minutes(11); // past idle timeout, no intervening touch
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn for an expired lease";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
}

TEST(Pkcs11Broker, SignRawAuthFailedRevokesLease)
{
    Harness h;
    h.signResult = Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::AuthFailed, {}};
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected AuthFailed";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::AuthFailed);
    }
    // Lease was revoked -> next op is not-logged-in (forces a re-prompt).
    h.signResult = Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::Ok, {'S'}};
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected UserNotLoggedIn after an auth-failure-revoked lease";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
}

TEST(Pkcs11Broker, DecryptWithinLeaseReturnsPlaintext)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    const auto pt = callDecrypt(obj, kReader, kCertId, kInput, appCaller());
    EXPECT_EQ(pt, (std::vector<std::uint8_t>{'P', 'T'}));
    EXPECT_EQ(h.decryptCalls, 1);
}

TEST(Pkcs11Broker, NamSignNotSupportedSurfacesNotSupported)
{
    // The NAM degraded path: the seam returns NotSupported (LmRawCrypto already
    // produces it for the pkcs15 family) -> the host raises Error.NotSupported,
    // which the module maps to CKR_FUNCTION_NOT_SUPPORTED.
    Harness h;
    h.signResult = Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::NotSupported, {}};
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected NotSupported";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::NotSupported);
    }
}

TEST(Pkcs11Broker, NamDecryptNotSupportedSurfacesNotSupported)
{
    Harness h;
    h.decryptResult = Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::NotSupported, {}};
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    try {
        static_cast<void>(callDecrypt(obj, kReader, kCertId, kInput, appCaller()));
        FAIL() << "expected NotSupported";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::NotSupported);
    }
}

TEST(Pkcs11Broker, LeaseScopedToCaller)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller())); // caller :1.42
    // A different caller has no lease for the same card.
    Pkcs11Broker::Caller other{.busName = CallerToken{":1.99"}, .label = "evil"};
    try {
        static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, other));
        FAIL() << "a different caller must not ride :1.42's lease";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UserNotLoggedIn);
    }
}

// --- Mechanism + MechanismParams carried through the CryptoSeam -----------

// The wire SignRaw/Decrypt methods carry no mechanism, so ManagerObject supplies
// the constant RsaPkcs1Sign / RsaPkcs1Decrypt + MechParamsEmpty. Inject a RAW
// seam (not the cryptoSeam adapter) to observe the mechanism the broker forwards.
TEST(Pkcs11Broker, ForwardsRsaPkcs1MechanismToSeam)
{
    Harness h;
    Mechanism sawSign{Mechanism::EcdsaSign}; // sentinels != expected
    Mechanism sawDecrypt{Mechanism::EcdsaSign};
    bool signEmpty = false, decEmpty = false;
    Pkcs11Broker obj{Pkcs11Broker::Deps{
        .lease = h.lease,
        .authorizer = h.authz,
        .certDer = certDerSeam([&](const std::string&, const std::string&) { return h.certDerResult; }),
        .publicKey = publicKeySeam([&](const std::string&, const std::string&) { return h.publicKeyResult; }),
        .login = loginSeam([&](const std::string&) { return h.loginOutcome; }),
        .signRaw =
            [&](const std::string&, const std::string&, Mechanism m, const MechanismParams& p,
                std::span<const std::uint8_t>, const std::string&, const Pkcs11Broker::LeasePinState&,
                std::function<void(Pkcs11Broker::CryptoResult)> done) {
                sawSign = m;
                signEmpty = std::holds_alternative<MechParamsEmpty>(p);
                done(h.signResult);
            },
        .decrypt =
            [&](const std::string&, const std::string&, Mechanism m, const MechanismParams& p,
                std::span<const std::uint8_t>, const std::string&, const Pkcs11Broker::LeasePinState&,
                std::function<void(Pkcs11Broker::CryptoResult)> done) {
                sawDecrypt = m;
                decEmpty = std::holds_alternative<MechParamsEmpty>(p);
                done(h.decryptResult);
            },
        .resolveCardKey = [&](const std::string&) { return h.cardKey; },
        .now = [&]() { return h.clockNow; }}};
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
    static_cast<void>(callDecrypt(obj, kReader, kCertId, kInput, appCaller()));
    EXPECT_EQ(sawSign, Mechanism::RsaPkcs1Sign);
    EXPECT_EQ(sawDecrypt, Mechanism::RsaPkcs1Decrypt);
    EXPECT_TRUE(signEmpty);
    EXPECT_TRUE(decEmpty);
}

// Mechanism gate: each crypto path wires exactly ONE primitive (SignRaw ->
// RsaPkcs1Sign, Decrypt -> RsaPkcs1Decrypt). Any other arm is rejected
// NotSupported BEFORE the seam runs, so a non-wired mechanism can never be
// silently executed as RSA-PKCS#1 v1.5. The gate precedes the lease touch, so a
// live lease does not let a non-wired arm through.
TEST(Pkcs11Broker, SignRawRejectsNonWiredMechanismNotSupported)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller())); // a live lease would otherwise allow the op
    EXPECT_EQ(signRawMechanismOutcome(obj, Mechanism::RsaPssSign, appCaller()),
              Pkcs11Broker::CryptoOutcome::NotSupported);
    EXPECT_EQ(signRawMechanismOutcome(obj, Mechanism::EcdsaSign, appCaller()),
              Pkcs11Broker::CryptoOutcome::NotSupported);
    // A public-key / encrypt arm must never ride the lease-gated private-key path.
    EXPECT_EQ(signRawMechanismOutcome(obj, Mechanism::RsaPkcs1Encrypt, appCaller()),
              Pkcs11Broker::CryptoOutcome::NotSupported);
    EXPECT_EQ(h.signCalls, 0) << "the seam must never run for a non-wired mechanism";
}

TEST(Pkcs11Broker, DecryptRejectsNonWiredMechanismNotSupported)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    EXPECT_EQ(decryptMechanismOutcome(obj, Mechanism::RsaOaepDecrypt, appCaller()),
              Pkcs11Broker::CryptoOutcome::NotSupported);
    EXPECT_EQ(decryptMechanismOutcome(obj, Mechanism::RsaOaepEncrypt, appCaller()),
              Pkcs11Broker::CryptoOutcome::NotSupported);
    // The wired SIGN arm is not a decrypt arm either — cross-arm requests fail closed.
    EXPECT_EQ(decryptMechanismOutcome(obj, Mechanism::RsaPkcs1Sign, appCaller()),
              Pkcs11Broker::CryptoOutcome::NotSupported);
    EXPECT_EQ(h.decryptCalls, 0) << "the seam must never run for a non-wired mechanism";
}

// A Reply dropped without ever being fulfilled (worker op torn down mid-flight)
// MUST deliver its fallback Outcome from the last owner's destructor — the
// fail-closed guarantee that stops a client hanging forever. This is the
// neutral-Outcome analogue of the old fail-closed communication-error dtor.
TEST(Pkcs11Broker, DroppedReplyDeliversFallbackOutcomeFailClosed)
{
    std::optional<Pkcs11Broker::CryptoOutcome> got;
    {
        Reply<Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
            [](const std::vector<std::uint8_t>&) {}, [&got](Pkcs11Broker::CryptoOutcome oc) { got = oc; },
            Pkcs11Broker::CryptoOutcome::CardError};
    } // dropped unfulfilled
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, Pkcs11Broker::CryptoOutcome::CardError);
}

// --- Broker ownership + Deps-seam building inside AgentCore ----------------
// AgentCore now OWNS the Pkcs11Broker and builds its Deps seams from its own
// scheduler / prompt gate / credential cache plus the injected reader/card
// resolution seams. These cases prove the aggregate hands out a live broker
// whose gates are wired to those injected seams. Hermetic: the reader seam
// returns nullopt so no worker is ever enqueued (no PC/SC, no card).

namespace {

namespace fs = std::filesystem;

// The base CapabilityResolver's defaulted virtuals already model the
// empty-candidate resolver a bus-free wiring test needs.
class NeutralResolver final : public CapabilityResolver
{};

// Owns the borrowed collaborators + config dir alongside the AgentCore under
// test, with the two card-resolution seams supplied per case.
struct CoreHarness
{
    fs::path dir;
    NeutralResolver resolver;
    FakeAgentTransport transport;
    FakeAuthorizer authorizer;
    std::shared_ptr<Operations::FakePrompter> prompter{std::make_shared<Operations::FakePrompter>()};
    AgentCore core;

    CoreHarness(const char* tag, ResolveReaderCard resolveReaderCard, Pkcs11Broker::ResolveCardKeySeam resolveCardKey)
        : dir(fs::temp_directory_path() / (std::string{"libreagent-broker-core-"} + tag)),
          core(resolver, transport, authorizer, prompter, dir / "agent.conf", dir / "cache",
               std::move(resolveReaderCard), std::move(resolveCardKey))
    {}
    ~CoreHarness()
    {
        fs::remove_all(dir);
    }
};

ResolveReaderCard noCardReader()
{
    return [](const std::string&) -> std::optional<ReaderCard> { return std::nullopt; };
}

} // namespace

TEST(Pkcs11BrokerOwnedByAgentCore, UnknownCardWhenResolveCardKeyEmpty)
{
    // No card present per the broker's card gate -> UnknownCard, without ever
    // reaching AgentCore's certDer seam.
    CoreHarness h{"unknown", noCardReader(),
                  [](const std::string&) -> std::optional<ObjectId> { return std::nullopt; }};
    try {
        static_cast<void>(callCertDer(h.core.pkcs11(), kReader, kCertId, appCaller()));
        FAIL() << "expected UnknownCard";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::UnknownCard);
    }
}

TEST(Pkcs11BrokerOwnedByAgentCore, CertDerKeyNotFoundWhenReaderUnresolved)
{
    // Card present (broker gate passes) but AgentCore's certDer seam finds no
    // reader routing -> nullopt export -> KeyNotFound. Proves the certDer seam is
    // wired to the injected reader resolver.
    CoreHarness h{"certkeynf", noCardReader(), [](const std::string&) { return std::optional<ObjectId>{ObjectId{7}}; }};
    try {
        static_cast<void>(callCertDer(h.core.pkcs11(), kReader, kCertId, appCaller()));
        FAIL() << "expected KeyNotFound";
    } catch (Pkcs11Broker::CryptoOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::CryptoOutcome::KeyNotFound);
    }
}

TEST(Pkcs11BrokerOwnedByAgentCore, LoginCardErrorWhenReaderUnresolved)
{
    // Card present + authorized (broker gates pass) but AgentCore's login seam
    // finds no reader routing -> CardError. Proves the login seam is wired to the
    // injected reader resolver.
    CoreHarness h{"logincarderr", noCardReader(),
                  [](const std::string&) { return std::optional<ObjectId>{ObjectId{7}}; }};
    try {
        static_cast<void>(callLogin(h.core.pkcs11(), kReader, appCaller()));
        FAIL() << "expected CardError";
    } catch (Pkcs11Broker::LoginOutcome oc) {
        EXPECT_EQ(oc, Pkcs11Broker::LoginOutcome::CardError);
    }
}
