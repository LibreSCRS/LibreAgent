// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Isolation proof for tests/wire/CMakeLists.txt's WireHeaderPurityCheck
// target: this TU is compiled with an include path of ONLY this repo's
// include/ dir (see that file) and links nothing at all, so a passing build
// is direct evidence these headers pull in zero external dependencies — not
// even GTest's INTERFACE include dirs, which is what let a prior version of
// this proof (WireHeadersTest alone) go unnoticed when GTest::gtest's
// resolved package happened to add an LM install prefix to the compile line.
//
// PreReadAuth.h/CredentialWire.h are the std-only mirrors of LibreMiddleware's
// PreReadAuthMethod and this repo's own CredentialOutcome/CredentialRecord/
// CredentialOpResult — Messages.h's re-base target. The VALUE parity against
// those authoritative types is proved separately in the core-gated
// src/wire/WireParityChecks.cpp (which, unlike this TU, is allowed to see
// LM); the static_asserts below just self-pin this mirror's own declared
// values so a value edited here without touching WireParityChecks.cpp still
// shows up as a diff in this file's expectations.
//
// ClientCodec.h transitively includes Messages.h (and, through it, Cbor.h):
// with an include path of ONLY this repo's include/ dir and no linked
// libraries, a passing compile of THIS TU is the isolation proof for the
// whole request/reply/event model, both server-role (Messages.h) and
// client-role (ClientCodec.h) — an LM/Qt/OpenSSL include added to any header
// in that chain fails this target with a file-not-found error.
#include <LibreSCRS/Agent/FeatureTokens.h>
#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/wire/ErrorCode.h>
#include <LibreSCRS/Agent/OperationPhase.h>
#include <LibreSCRS/Agent/wire/CredentialWire.h>
#include <LibreSCRS/Agent/wire/PreReadAuth.h>
#include <LibreSCRS/Agent/wire/SyncError.h>
#include <LibreSCRS/Agent/wire/ClientCodec.h>

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Agent::Wire::CredentialOutcome;
using LibreSCRS::Agent::Wire::PreReadAuth;
using LibreSCRS::Agent::Wire::SyncError;

static_assert(static_cast<std::uint32_t>(ErrorCode::None) == 0u);
static_assert(static_cast<std::uint32_t>(ErrorCode::InvalidDocument) == 19u);
static_assert(static_cast<std::uint32_t>(ErrorCode::EntryExpired) == 20u);
static_assert(static_cast<std::uint32_t>(OperationStatus::Cancelled) == 1u);

static_assert(static_cast<std::uint8_t>(PreReadAuth::None) == 0u);
static_assert(static_cast<std::uint8_t>(PreReadAuth::Mrz) == 1u);
static_assert(static_cast<std::uint8_t>(PreReadAuth::Can) == 2u);

static_assert(static_cast<int>(CredentialOutcome::Unspecified) == 0);
static_assert(static_cast<int>(CredentialOutcome::CardRemoved) == 9);

// SyncError's integers are NOT a wire contract (the wire carries the name), so
// there is nothing here to pin the way the enums above are pinned — this only
// has to name the type, so that the header is reached and audited even if
// Messages.h ever stops including it.
static_assert(sizeof(SyncError) == 1);

static_assert(LibreSCRS::Agent::kAgentFeatures.size() == 11);

// The key-type and mechanism vocabularies are std-only and constexpr, so the
// facade -- which links no crypto and no core -- can read them. Pinned here,
// where only this repo's include/ is on the path.
static_assert(LibreSCRS::Agent::keyTypeFromToken("RSA") == LibreSCRS::Agent::KeyType::Rsa);
static_assert(LibreSCRS::Agent::keyTypeFromToken("EC") == LibreSCRS::Agent::KeyType::Ec);
static_assert(LibreSCRS::Agent::keyTypeFromToken("ED448") == LibreSCRS::Agent::KeyType::Other);
static_assert(LibreSCRS::Agent::keyTypeToken(LibreSCRS::Agent::KeyType::Rsa) == "RSA");
static_assert(LibreSCRS::Agent::keyTypeToken(LibreSCRS::Agent::KeyType::Ec) == "EC");
static_assert(LibreSCRS::Agent::keyTypeToken(LibreSCRS::Agent::KeyType::Other) == "OTHER");
// The one NIST curve table: every name of a curve finds the same row, a
// coordinate is ceil(bits/8) bytes, and nothing else is a curve.
static_assert([] {
    for (const auto& c : LibreSCRS::Agent::kNistCurves) {
        if (LibreSCRS::Agent::nistCurveByBits(c.keyBits) != &c || LibreSCRS::Agent::nistCurveByName(c.crv) != &c ||
            LibreSCRS::Agent::nistCurveByGroup(c.group) != &c || c.fieldBytes != (c.keyBits + 7) / 8 ||
            c.oidDer.size() != 2U + c.oidDer[1]) {
            return false;
        }
    }
    return true;
}());
static_assert(LibreSCRS::Agent::nistCurveByName("P-384")->group == "secp384r1");
static_assert(LibreSCRS::Agent::nistCurveByBits(521)->fieldBytes == 66);
static_assert(LibreSCRS::Agent::nistCurveByBits(255) == nullptr);
static_assert(LibreSCRS::Agent::nistCurveByName("brainpoolP384r1") == nullptr);
static_assert(LibreSCRS::Agent::nistCurveByGroup("secp256k1") == nullptr);
static_assert(LibreSCRS::Agent::signMechanismFromToken("ecdsa") == LibreSCRS::Agent::Mechanism::EcdsaSign);
static_assert(LibreSCRS::Agent::signMechanismFromToken("sha256-rsa-pkcs") ==
              LibreSCRS::Agent::Mechanism::Sha256RsaPkcs1Sign);
static_assert(!LibreSCRS::Agent::signMechanismFromToken("rsa-pss").has_value());
static_assert(!LibreSCRS::Agent::decryptMechanismFromToken("ecdsa").has_value());
static_assert(LibreSCRS::Agent::decryptMechanismFromToken("rsa-pkcs") == LibreSCRS::Agent::Mechanism::RsaPkcs1Decrypt);
static_assert(LibreSCRS::Agent::mechanismToken(LibreSCRS::Agent::Mechanism::RsaPkcs1Sign) == "rsa-pkcs");
static_assert(LibreSCRS::Agent::mechanismToken(LibreSCRS::Agent::Mechanism::Sha256RsaPkcs1Sign) == "sha256-rsa-pkcs");
static_assert(LibreSCRS::Agent::mechanismToken(LibreSCRS::Agent::Mechanism::EcdsaSign) == "ecdsa");
static_assert(LibreSCRS::Agent::mechanismToken(LibreSCRS::Agent::Mechanism::RsaPkcs1Decrypt) == "rsa-pkcs");
static_assert(LibreSCRS::Agent::mechanismToken(LibreSCRS::Agent::Mechanism::RsaPssSign).empty());
static_assert(LibreSCRS::Agent::kEcdhKdfNull == 1u); // CKD_NULL
