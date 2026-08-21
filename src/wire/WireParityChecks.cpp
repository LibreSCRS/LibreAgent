// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-time-only lockstep proof between the std-only wire mirrors
// (include/LibreSCRS/Agent/wire/{PreReadAuth,CredentialWire}.h) and their
// authoritative sources:
//   - LibreMiddleware's LibreSCRS::Auth::PreReadAuthMethod for Wire::PreReadAuth.
//   - This repo's own LibreSCRS::Agent::{CredentialOutcome,CredentialRecord,
//     CredentialOpResult} (include/LibreSCRS/Agent/value/CredentialRecord.h)
//     for the credential wire mirrors.
//
// This TU is the only place in the repo entitled to see BOTH worlds: it is
// compiled ONLY when LIBREAGENT_BUILD_CORE is ON (see the root
// CMakeLists.txt — an OBJECT target linked against LibreAgent::Core, which
// is what makes LibreMiddleware's headers resolvable here), while the
// mirrors it checks stay reachable from a Core-less, LM-free
// LIBREAGENT_BUILD_WIRE-only build. It emits no runtime code: every check
// below is a static_assert, so a passing compile IS the test — there is
// nothing to run and therefore no ctest entry, mirroring
// tests/wire/WireHeaderPurity.cpp's compiled-guard pattern.
#include <LibreSCRS/Agent/value/CredentialRecord.h> // authoritative CredentialOutcome/Record/OpResult
#include <LibreSCRS/Agent/wire/CredentialWire.h>    // std-only mirror
#include <LibreSCRS/Agent/wire/PreReadAuth.h>       // std-only mirror
#include <LibreSCRS/Auth/AuthRequirement.h>         // authoritative PreReadAuthMethod

#include <type_traits>
#include <utility> // std::to_underlying

namespace {

namespace Wire = LibreSCRS::Agent::Wire;
using LibreSCRS::Auth::PreReadAuthMethod;
using AgentOpResult = LibreSCRS::Agent::CredentialOpResult;
using AgentOutcome = LibreSCRS::Agent::CredentialOutcome;
using AgentRecord = LibreSCRS::Agent::CredentialRecord;

// ---- Wire::PreReadAuth <-> LibreSCRS::Auth::PreReadAuthMethod --------------
// Every enumerator of the LM original, value-checked (not just the ones the
// wire currently sends) — an LM renumber must be caught even if this repo's
// wire code has not yet been touched to react to it.
static_assert(std::to_underlying(Wire::PreReadAuth::None) == std::to_underlying(PreReadAuthMethod::None));
static_assert(std::to_underlying(Wire::PreReadAuth::Mrz) == std::to_underlying(PreReadAuthMethod::Mrz));
static_assert(std::to_underlying(Wire::PreReadAuth::Can) == std::to_underlying(PreReadAuthMethod::Can));

// Underlying-type parity too: a value-only check would still pass if one
// side quietly changed from `int` to e.g. `std::uint8_t` while every
// existing value happened to still fit.
static_assert(std::is_same_v<std::underlying_type_t<Wire::PreReadAuth>, std::underlying_type_t<PreReadAuthMethod>>);

// ---- Wire::CredentialOutcome <-> LibreSCRS::Agent::CredentialOutcome -------
// Every enumerator Messages.cpp's credOutcomeToken() serializes, including
// CardRemoved (agent-assigned; LM's PINResultOutcome has no equivalent).
static_assert(std::to_underlying(Wire::CredentialOutcome::Unspecified) ==
              std::to_underlying(AgentOutcome::Unspecified));
static_assert(std::to_underlying(Wire::CredentialOutcome::Ok) == std::to_underlying(AgentOutcome::Ok));
static_assert(std::to_underlying(Wire::CredentialOutcome::UserCancelled) ==
              std::to_underlying(AgentOutcome::UserCancelled));
static_assert(std::to_underlying(Wire::CredentialOutcome::MissingFields) ==
              std::to_underlying(AgentOutcome::MissingFields));
static_assert(std::to_underlying(Wire::CredentialOutcome::InvalidPin) == std::to_underlying(AgentOutcome::InvalidPin));
static_assert(std::to_underlying(Wire::CredentialOutcome::Blocked) == std::to_underlying(AgentOutcome::Blocked));
static_assert(std::to_underlying(Wire::CredentialOutcome::PluginError) ==
              std::to_underlying(AgentOutcome::PluginError));
static_assert(std::to_underlying(Wire::CredentialOutcome::Unsupported) ==
              std::to_underlying(AgentOutcome::Unsupported));
static_assert(std::to_underlying(Wire::CredentialOutcome::KeyActivationFailed) ==
              std::to_underlying(AgentOutcome::KeyActivationFailed));
static_assert(std::to_underlying(Wire::CredentialOutcome::CardRemoved) ==
              std::to_underlying(AgentOutcome::CardRemoved));
static_assert(std::to_underlying(Wire::CredentialOutcome::EntryExpired) ==
              std::to_underlying(AgentOutcome::EntryExpired));

// Underlying-type parity too: a value-only check would still pass if one
// side quietly changed from `int` to e.g. `std::uint8_t` while every
// existing value happened to still fit.
static_assert(std::is_same_v<std::underlying_type_t<Wire::CredentialOutcome>, std::underlying_type_t<AgentOutcome>>);

// ---- Wire::CredentialOpResult <-> LibreSCRS::Agent::CredentialOpResult -----
// Field-presence/type parity (decltype on a non-static member id-expression
// needs no instance). `outcome` is deliberately excluded from a same-type
// check — its whole point is to be the OTHER enum type; the value-parity
// asserts above are what keep it in lockstep.
static_assert(std::is_same_v<decltype(Wire::CredentialOpResult::outcome), Wire::CredentialOutcome>);
static_assert(std::is_same_v<decltype(AgentOpResult::outcome), AgentOutcome>);
static_assert(std::is_same_v<decltype(Wire::CredentialOpResult::retriesLeft), decltype(AgentOpResult::retriesLeft)>);
static_assert(std::is_same_v<decltype(Wire::CredentialOpResult::blocked), decltype(AgentOpResult::blocked)>);
static_assert(std::is_same_v<decltype(Wire::CredentialOpResult::pinActivated), decltype(AgentOpResult::pinActivated)>);
static_assert(std::is_same_v<decltype(Wire::CredentialOpResult::keyActivated), decltype(AgentOpResult::keyActivated)>);

// ---- Wire::CredentialRecord <-> LibreSCRS::Agent::CredentialRecord --------
// All 23 wire keys Messages.cpp's encodeCredRecord() writes; every field is
// std-only on both sides (no enum-valued members here — kind/state/
// unblockStyle/recovery cross as pre-tokenized strings), so a straight
// same-type check is the right (and sufficient) parity proof per field.
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::id), decltype(AgentRecord::id)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::label), decltype(AgentRecord::label)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::kind), decltype(AgentRecord::kind)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::state), decltype(AgentRecord::state)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::retriesLeft), decltype(AgentRecord::retriesLeft)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::retriesMax), decltype(AgentRecord::retriesMax)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::usesLeft), decltype(AgentRecord::usesLeft)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::usesMax), decltype(AgentRecord::usesMax)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::unblocksLeft), decltype(AgentRecord::unblocksLeft)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::minLength), decltype(AgentRecord::minLength)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::maxLength), decltype(AgentRecord::maxLength)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::canChange), decltype(AgentRecord::canChange)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::unblockable), decltype(AgentRecord::unblockable)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::unblockStyle), decltype(AgentRecord::unblockStyle)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::activatable), decltype(AgentRecord::activatable)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::keyActivationPending),
                             decltype(AgentRecord::keyActivationPending)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::keyActivatable), decltype(AgentRecord::keyActivatable)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::recovery), decltype(AgentRecord::recovery)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::probeSafe), decltype(AgentRecord::probeSafe)>);
static_assert(
    std::is_same_v<decltype(Wire::CredentialRecord::blockedGuidanceKey), decltype(AgentRecord::blockedGuidanceKey)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::blockedGuidanceFallback),
                             decltype(AgentRecord::blockedGuidanceFallback)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::keyActivationGuidanceKey),
                             decltype(AgentRecord::keyActivationGuidanceKey)>);
static_assert(std::is_same_v<decltype(Wire::CredentialRecord::keyActivationGuidanceFallback),
                             decltype(AgentRecord::keyActivationGuidanceFallback)>);

} // namespace
