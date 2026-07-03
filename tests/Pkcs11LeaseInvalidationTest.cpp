// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pkcs11Broker lease invalidation: a granted lease must drop when the
// card is removed (CardKeyTracker onKeyRemoved -> onCardRemoved) and when the
// D-Bus client disconnects (NameOwnerChanged -> onClientDisconnected). These
// hooks are the PKCS#11 analogue of the credential/read-cache scrub-on-removal.
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "Pkcs11BrokerTestSupport.h"
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
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
const ObjectId kCard{7}; // the card's opaque per-insertion ObjectId
constexpr const char* kCertId = "abc123";
const std::vector<std::uint8_t> kInput{0x01, 0x02, 0x03};

Pkcs11Broker::Caller appCaller()
{
    return Pkcs11Broker::Caller{.busName = CallerToken{":1.42"}, .label = "firefox"};
}

struct Harness
{
    std::shared_ptr<Pkcs11::LeaseManager> lease = std::make_shared<Pkcs11::LeaseManager>(
        Pkcs11::LeaseConfig{.idleTimeout = minutes(10), .maxLifetime = hours(8)});
    AllowAllAuthorizer authz;
    steady_clock::time_point clockNow{};
    std::optional<ObjectId> cardKey{kCard};

    Pkcs11Broker make()
    {
        return Pkcs11Broker{Pkcs11Broker::Deps{
            .lease = lease,
            .authorizer = authz,
            .certDer =
                certDerSeam([](const std::string&, const std::string&) -> std::optional<std::vector<std::uint8_t>> {
                    return std::vector<std::uint8_t>{};
                }),
            .publicKey =
                publicKeySeam([](const std::string&, const std::string&) -> std::optional<Pkcs11Broker::PublicKey> {
                    return Pkcs11Broker::PublicKey{.modulus = {0xAB}, .exponent = {0x01, 0x00, 0x01}};
                }),
            .login = loginSeam([](const std::string&) { return Pkcs11Broker::LoginOutcome::Ok; }),
            .signRaw = cryptoSeam([](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                     const std::string&, const Pkcs11Broker::LeasePinState&) {
                return Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::Ok, {'S'}};
            }),
            .decrypt = cryptoSeam([](const std::string&, const std::string&, std::span<const std::uint8_t>,
                                     const std::string&, const Pkcs11Broker::LeasePinState&) {
                return Pkcs11Broker::CryptoResult{Pkcs11Broker::CryptoOutcome::Ok, {'P'}};
            }),
            .resolveCardKey = [this](const std::string&) { return cardKey; },
            .now = [this]() { return clockNow; },
        }};
    }

    [[nodiscard]] bool signOk(Pkcs11Broker& obj)
    {
        try {
            static_cast<void>(callSignRaw(obj, kReader, kCertId, kInput, appCaller()));
            return true;
        } catch (Pkcs11Broker::CryptoOutcome&) {
            return false;
        }
    }
};

} // namespace

TEST(Pkcs11LeaseInvalidation, CardRemovedRevokesLease)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    ASSERT_TRUE(h.signOk(obj)) << "lease active right after Login";

    obj.onCardRemoved(kCard);

    EXPECT_FALSE(h.signOk(obj)) << "card removal must revoke the lease";
}

TEST(Pkcs11LeaseInvalidation, ClientDisconnectRevokesLease)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));
    ASSERT_TRUE(h.signOk(obj));

    obj.onClientDisconnected(CallerToken{":1.42"});

    EXPECT_FALSE(h.signOk(obj)) << "client disconnect must revoke the caller's lease";
}

TEST(Pkcs11LeaseInvalidation, OtherCardRemovalDoesNotRevoke)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));

    obj.onCardRemoved(ObjectId{9}); // a different card

    EXPECT_TRUE(h.signOk(obj)) << "removing a different card must not touch this lease";
}

TEST(Pkcs11LeaseInvalidation, OtherClientDisconnectDoesNotRevoke)
{
    Harness h;
    auto obj = h.make();
    static_cast<void>(callLogin(obj, kReader, appCaller()));

    obj.onClientDisconnected(CallerToken{":1.99"}); // a different client

    EXPECT_TRUE(h.signOk(obj)) << "another client's disconnect must not touch this lease";
}
