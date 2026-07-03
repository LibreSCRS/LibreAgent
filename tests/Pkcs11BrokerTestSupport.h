// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Shared test support for the (now async) Pkcs11Broker surface. The production
// methods are async: each takes a Pkcs11Broker::Reply<Outcome,
// Results...> the worker fulfils. The agent's test seams complete their
// continuation INLINE (no worker, no bus), so a call resolves synchronously —
// these helpers drive a method, capture the single inline fulfilment into a
// result or a neutral Outcome, and return the value / throw the Outcome enum so
// the test bodies stay readable (they `catch` the enum, not a wire error).
#pragma once
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/Reply.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace LibreSCRS::Agent::testsupport {

// Records the single inline fulfilment: @p value on ok, @p outcome on fail (the
// neutral Outcome enum — no wire string). The drivers below throw @p outcome so
// test bodies catch Pkcs11Broker::CryptoOutcome / LoginOutcome directly.
template <typename Outcome, typename T>
struct Captured
{
    std::optional<T> value;
    std::optional<Outcome> outcome;
};

// --- Synchronous drivers over the async methods ---------------------------
// Each asserts (throws std::logic_error) if the seam did NOT complete inline —
// the test seams always do, so an un-fulfilled reply is a wiring bug worth a hard
// failure rather than a silent default.

inline std::vector<std::uint8_t> callCertDer(Pkcs11Broker& obj, const std::string& reader, const std::string& certId,
                                             const Pkcs11Broker::Caller& caller)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    auto cap = std::make_shared<Captured<CO, std::vector<std::uint8_t>>>();
    obj.certDer(reader, certId, caller,
                Reply<CO, std::vector<std::uint8_t>>{[cap](const std::vector<std::uint8_t>& v) { cap->value = v; },
                                                     [cap](CO oc) { cap->outcome = oc; }, CO::CardError});
    if (cap->outcome) {
        throw *cap->outcome;
    }
    if (!cap->value) {
        throw std::logic_error{"CertDer reply not fulfilled inline"};
    }
    return *cap->value;
}

inline Pkcs11Broker::PublicKey callPublicKey(Pkcs11Broker& obj, const std::string& reader, const std::string& certId,
                                             const Pkcs11Broker::Caller& caller)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    auto cap = std::make_shared<Captured<CO, std::tuple<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>>();
    obj.publicKey(reader, certId, caller,
                  Reply<CO, std::vector<std::uint8_t>, std::vector<std::uint8_t>>{
                      [cap](const std::vector<std::uint8_t>& m, const std::vector<std::uint8_t>& e) {
                          cap->value = std::make_tuple(m, e);
                      },
                      [cap](CO oc) { cap->outcome = oc; }, CO::CardError});
    if (cap->outcome) {
        throw *cap->outcome;
    }
    if (!cap->value) {
        throw std::logic_error{"PublicKey reply not fulfilled inline"};
    }
    return Pkcs11Broker::PublicKey{.modulus = std::get<0>(*cap->value), .exponent = std::get<1>(*cap->value)};
}

inline std::uint32_t callLogin(Pkcs11Broker& obj, const std::string& reader, const Pkcs11Broker::Caller& caller)
{
    using LO = Pkcs11Broker::LoginOutcome;
    auto cap = std::make_shared<Captured<LO, std::uint32_t>>();
    obj.login(reader, caller,
              Reply<LO, std::uint32_t>{[cap](const std::uint32_t& v) { cap->value = v; },
                                       [cap](LO oc) { cap->outcome = oc; }, LO::CardError});
    if (cap->outcome) {
        throw *cap->outcome;
    }
    if (!cap->value) {
        throw std::logic_error{"Login reply not fulfilled inline"};
    }
    return *cap->value;
}

inline std::vector<std::uint8_t> callSignRaw(Pkcs11Broker& obj, const std::string& reader, const std::string& certId,
                                             std::span<const std::uint8_t> input, const Pkcs11Broker::Caller& caller)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    auto cap = std::make_shared<Captured<CO, std::vector<std::uint8_t>>>();
    obj.signRaw(reader, certId, Mechanism::RsaPkcs1Sign, MechParamsEmpty{}, input, caller,
                Reply<CO, std::vector<std::uint8_t>>{[cap](const std::vector<std::uint8_t>& v) { cap->value = v; },
                                                     [cap](CO oc) { cap->outcome = oc; }, CO::CardError});
    if (cap->outcome) {
        throw *cap->outcome;
    }
    if (!cap->value) {
        throw std::logic_error{"SignRaw reply not fulfilled inline"};
    }
    return *cap->value;
}

inline std::vector<std::uint8_t> callDecrypt(Pkcs11Broker& obj, const std::string& reader, const std::string& certId,
                                             std::span<const std::uint8_t> ciphertext,
                                             const Pkcs11Broker::Caller& caller)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    auto cap = std::make_shared<Captured<CO, std::vector<std::uint8_t>>>();
    obj.decrypt(reader, certId, Mechanism::RsaPkcs1Decrypt, MechParamsEmpty{}, ciphertext, caller,
                Reply<CO, std::vector<std::uint8_t>>{[cap](const std::vector<std::uint8_t>& v) { cap->value = v; },
                                                     [cap](CO oc) { cap->outcome = oc; }, CO::CardError});
    if (cap->outcome) {
        throw *cap->outcome;
    }
    if (!cap->value) {
        throw std::logic_error{"Decrypt reply not fulfilled inline"};
    }
    return *cap->value;
}

// --- Inline async seam adapters from synchronous test lambdas -------------
// Wrap a synchronous test seam (the old "return the result" shape) into the new
// async seam shape that completes @p done inline. Keeps test harnesses terse.

inline Pkcs11Broker::CertDerSeam
certDerSeam(std::function<std::optional<std::vector<std::uint8_t>>(const std::string&, const std::string&)> fn)
{
    return [fn = std::move(fn)](const std::string& reader, const std::string& certId,
                                std::function<void(std::optional<std::vector<std::uint8_t>>)> done) {
        done(fn(reader, certId));
    };
}

inline Pkcs11Broker::PublicKeySeam
publicKeySeam(std::function<std::optional<Pkcs11Broker::PublicKey>(const std::string&, const std::string&)> fn)
{
    return [fn = std::move(fn)](const std::string& reader, const std::string& certId,
                                std::function<void(std::optional<Pkcs11Broker::PublicKey>)> done) {
        done(fn(reader, certId));
    };
}

inline Pkcs11Broker::LoginSeam loginSeam(std::function<Pkcs11Broker::LoginOutcome(const std::string&)> fn)
{
    return [fn = std::move(fn)](const std::string& reader, std::function<void(Pkcs11Broker::LoginOutcome)> done) {
        done(fn(reader));
    };
}

inline Pkcs11Broker::CryptoSeam cryptoSeam(
    std::function<Pkcs11Broker::CryptoResult(const std::string&, const std::string&, std::span<const std::uint8_t>,
                                             const std::string&, const Pkcs11Broker::LeasePinState&)>
        fn)
{
    return [fn = std::move(fn)](const std::string& reader, const std::string& certId, Mechanism /*mechanism*/,
                                const MechanismParams& /*params*/, std::span<const std::uint8_t> bytes,
                                const std::string& requester, const Pkcs11Broker::LeasePinState& pinState,
                                std::function<void(Pkcs11Broker::CryptoResult)> done) {
        done(fn(reader, certId, bytes, requester, pinState));
    };
}

} // namespace LibreSCRS::Agent::testsupport
