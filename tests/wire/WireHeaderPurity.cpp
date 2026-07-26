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
#include <LibreSCRS/Agent/wire/ErrorCode.h>
#include <LibreSCRS/Agent/OperationPhase.h>
#include <LibreSCRS/Agent/wire/CredentialWire.h>
#include <LibreSCRS/Agent/wire/PreReadAuth.h>
#include <LibreSCRS/Agent/wire/ClientCodec.h>

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Agent::Wire::CredentialOutcome;
using LibreSCRS::Agent::Wire::PreReadAuth;

static_assert(static_cast<std::uint32_t>(ErrorCode::None) == 0u);
static_assert(static_cast<std::uint32_t>(ErrorCode::InvalidDocument) == 19u);
static_assert(static_cast<std::uint32_t>(OperationStatus::Cancelled) == 1u);

static_assert(static_cast<std::uint8_t>(PreReadAuth::None) == 0u);
static_assert(static_cast<std::uint8_t>(PreReadAuth::Mrz) == 1u);
static_assert(static_cast<std::uint8_t>(PreReadAuth::Can) == 2u);

static_assert(static_cast<int>(CredentialOutcome::Unspecified) == 0);
static_assert(static_cast<int>(CredentialOutcome::CardRemoved) == 9);

static_assert(LibreSCRS::Agent::kAgentFeatures.size() == 9);
