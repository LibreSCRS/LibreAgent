// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Cross-stack wire-contract drift guard.
//
// The socket wire contract (wire/librescrs-agent.cddl) mirrors, value-for-
// value, the canonical D-Bus agent surface; the CBOR message enums on the wire
// are re-typed by hand as CDDL literals, and again by the Swift client. Each
// mirror pins itself to hard-coded literals in its OWN stack but not to the
// upstream enum — so a renumber (or an append) would go silently stale on the
// wire and on the client.
//
// This fixture is the one place that ties those wire literals back to the
// upstream symbols. This test links both LibreAgent::Core (which re-exports
// the LibreMiddleware Plugin/Auth types) and LibreAgent::Wire (for wire::
// Messages' SyncError/syncErrorName), so a static_assert here breaks the
// build the instant a core enum renumbers — the half no client-side test can
// catch, because a client stack cannot link the middleware.
//
// === Mirror manifest — keep these in lockstep ===
//   ErrorCode        : LibreSCRS/Agent/value/ErrorTaxonomy.h (SOURCE)
//                      <-> CDDL `error-code` <-> the Swift client's ErrorCode
//   capability bits  : LibreSCRS/Plugin/PluginTypes.h CardCapabilities
//                      <-> CDDL `capability-bit` <-> the Swift client's Cap
//   pre-read auth    : LibreSCRS/Auth/AuthRequirement.h PreReadAuthMethod
//                      <-> CDDL `pre-read-auth`
//   op phase/status  : LibreSCRS/Agent/OperationPhase.h
//                      <-> CDDL `op-phase`/`op-status`
//   message tags     : CDDL request/event `t:` tags — count-pinned below
//   sync errors      : LibreSCRS/Agent/wire/Messages.h SyncError
//                      <-> CDDL `sync-error` (compared as a SET; name-carried)
//   cred outcome     : LibreSCRS/Agent/value/CredentialRecord.h CredentialOutcome
//                      <-> CDDL `cred-outcome`
//   cred record vocab: LibreSCRS/Plugin/PinStatusEntry.h PinKind/PinState/
//                      UnblockStyle/PinRecovery (via CredentialRecord.h detail::
//                      *Token) <-> CDDL `cred-kind`/`cred-state`/`unblock-style`/
//                      `cred-recovery`
//   cred record keys : CredentialRecord.h field names <-> CDDL `cred-record` keys
//   cred verbs       : CDDL `cred-verb` string literals (no upstream enum)

#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Agent/OperationPhase.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Auth/AuthRequirement.h>

#include <LibreSCRS/Agent/wire/Messages.h>

#include <gtest/gtest.h>

#include <CddlVocabulary.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

using LibreSCRS::Agent::CredentialOutcome;
using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Agent::Wire::decodeSyncError;
using LibreSCRS::Agent::Wire::QuiesceReason;
using LibreSCRS::Agent::Wire::SyncError;
using LibreSCRS::Agent::Wire::syncErrorName;
using LibreSCRS::Auth::PreReadAuthMethod;
using LibreSCRS::Plugin::CardCapabilities;
using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinRecovery;
using LibreSCRS::Plugin::PinState;
using LibreSCRS::Plugin::UnblockStyle;

using LibreSCRS::Wire::Tools::cddlMapKeys;
using LibreSCRS::Wire::Tools::cddlQuotedTokens;
using LibreSCRS::Wire::Tools::cddlRuleRhs;
using LibreSCRS::Wire::Tools::discoverClosedGroups;
using LibreSCRS::Wire::Tools::parseCddlErrorCode;
using LibreSCRS::Wire::Tools::parseCddlNumericGroup;
using LibreSCRS::Wire::Tools::slurp;

constexpr std::uint32_t u(CardCapabilities c)
{
    return static_cast<std::uint32_t>(c);
}
constexpr std::uint32_t u(ErrorCode e)
{
    return static_cast<std::uint32_t>(e);
}
constexpr std::uint32_t u(OperationPhase p)
{
    return static_cast<std::uint32_t>(p);
}
constexpr std::uint32_t u(OperationStatus s)
{
    return static_cast<std::uint32_t>(s);
}
constexpr std::uint32_t u(PreReadAuthMethod m)
{
    return static_cast<std::uint32_t>(m);
}
constexpr std::uint32_t u(CredentialOutcome o)
{
    return static_cast<std::uint32_t>(o);
}

// --- LM CardCapabilities <-> CDDL `capability-bit` (THE anchor) --------------
static_assert(u(CardCapabilities::None) == 0u, "wire contract: CardCapabilities::None drifted from 0");
static_assert(u(CardCapabilities::PKI) == (1u << 0),
              "wire contract: PKI bit drifted; CDDL capability-bit Pki now stale");
static_assert(u(CardCapabilities::IdentityData) == (1u << 1),
              "wire contract: IdentityData bit drifted; CDDL capability-bit IdentityData now stale");
static_assert(u(CardCapabilities::EmrtdCrypto) == (1u << 2),
              "wire contract: EmrtdCrypto bit drifted; CDDL capability-bit EmrtdCrypto now stale");
static_assert(u(CardCapabilities::PinManagement) == (1u << 3),
              "wire contract: PinManagement bit drifted; CDDL capability-bit PinManagement now stale");

// --- LM PreReadAuthMethod <-> CDDL `pre-read-auth` ---------------------------
static_assert(u(PreReadAuthMethod::None) == 0u, "wire contract: PreReadAuthMethod::None drifted from 0");
static_assert(u(PreReadAuthMethod::Mrz) == 1u, "wire contract: PreReadAuthMethod::Mrz drifted from 1");
static_assert(u(PreReadAuthMethod::Can) == 2u, "wire contract: PreReadAuthMethod::Can drifted from 2");

// --- LibreAgent OperationPhase / OperationStatus <-> CDDL `op-phase`/`op-status` ---
static_assert(u(OperationPhase::Created) == 0u, "wire contract: op-phase Created drifted from 0");
static_assert(u(OperationPhase::Connecting) == 1u, "wire contract: op-phase Connecting drifted from 1");
static_assert(u(OperationPhase::AwaitingConsent) == 2u, "wire contract: op-phase AwaitingConsent drifted from 2");
static_assert(u(OperationPhase::Authenticating) == 3u, "wire contract: op-phase Authenticating drifted from 3");
static_assert(u(OperationPhase::Reading) == 4u, "wire contract: op-phase Reading drifted from 4");
static_assert(u(OperationPhase::Signing) == 5u, "wire contract: op-phase Signing drifted from 5");
static_assert(u(OperationPhase::Timestamping) == 6u, "wire contract: op-phase Timestamping drifted from 6");
static_assert(u(OperationPhase::Done) == 7u,
              "wire contract: op-phase Done (last) drifted from 7; bump the CDDL op-phase");
static_assert(u(OperationStatus::Ok) == 0u, "wire contract: op-status Ok drifted from 0");
static_assert(u(OperationStatus::Cancelled) == 1u, "wire contract: op-status Cancelled drifted from 1");
static_assert(u(OperationStatus::Error) == 2u, "wire contract: op-status Error drifted from 2");

// The static_asserts above pin the raw C++ VALUES (catches a renumber) but
// never read the CDDL, so they cannot catch the grammar drifting away from
// the enum on its own. The switches below are the CDDL-reading half: each
// mirrors wireNameFor(ErrorCode)'s shape (no default case, so -Werror=switch
// turns an appended enumerator into a compile error here first) and backs a
// dedicated cross-check TEST further down that parses the matching CDDL
// group with parseCddlNumericGroup() and compares it entry by entry.

// --- LibreAgent OperationPhase <-> CDDL `op-phase` ---------------------------
constexpr const char* opPhaseWireName(OperationPhase p) noexcept
{
    switch (p) {
    case OperationPhase::Created:
        return "Created";
    case OperationPhase::Connecting:
        return "Connecting";
    case OperationPhase::AwaitingConsent:
        return "AwaitingConsent";
    case OperationPhase::Authenticating:
        return "Authenticating";
    case OperationPhase::Reading:
        return "Reading";
    case OperationPhase::Signing:
        return "Signing";
    case OperationPhase::Timestamping:
        return "Timestamping";
    case OperationPhase::Done:
        return "Done";
    }
    return nullptr; // not a phase value (used to probe past the end for the count)
}
constexpr std::uint32_t opPhaseCount() noexcept
{
    std::uint32_t count = 0;
    while (opPhaseWireName(static_cast<OperationPhase>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(opPhaseCount() == 8u, "wire contract: op-phase has 8 values; update the CDDL + this switch together");

// --- LibreAgent OperationStatus <-> CDDL `op-status` -------------------------
constexpr const char* opStatusWireName(OperationStatus s) noexcept
{
    switch (s) {
    case OperationStatus::Ok:
        return "Ok";
    case OperationStatus::Cancelled:
        return "Cancelled";
    case OperationStatus::Error:
        return "Error";
    }
    return nullptr;
}
constexpr std::uint32_t opStatusCount() noexcept
{
    std::uint32_t count = 0;
    while (opStatusWireName(static_cast<OperationStatus>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(opStatusCount() == 3u, "wire contract: op-status has 3 values; update the CDDL + this switch together");

// --- LM PreReadAuthMethod <-> CDDL `pre-read-auth` ---------------------------
constexpr const char* preReadAuthWireName(PreReadAuthMethod m) noexcept
{
    switch (m) {
    case PreReadAuthMethod::None:
        return "None";
    case PreReadAuthMethod::Mrz:
        return "Mrz";
    case PreReadAuthMethod::Can:
        return "Can";
    }
    return nullptr;
}
constexpr std::uint32_t preReadAuthCount() noexcept
{
    std::uint32_t count = 0;
    while (preReadAuthWireName(static_cast<PreReadAuthMethod>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(preReadAuthCount() == 3u,
              "wire contract: pre-read-auth has 3 values; update the CDDL + this switch together");

// --- LibreAgent Wire::QuiesceReason <-> CDDL `quiesce-reason` ----------------
// Socket-only lifecycle vocabulary (declared in wire/Messages.h, no core enum
// to anchor to besides itself), mirrored here the same way as the four above.
constexpr const char* quiesceReasonWireName(QuiesceReason r) noexcept
{
    switch (r) {
    case QuiesceReason::SystemSleep:
        return "SystemSleep";
    case QuiesceReason::ScreenLocked:
        return "ScreenLocked";
    case QuiesceReason::SessionInactive:
        return "SessionInactive";
    case QuiesceReason::Shutdown:
        return "Shutdown";
    }
    return nullptr;
}
constexpr std::uint32_t quiesceReasonCount() noexcept
{
    std::uint32_t count = 0;
    while (quiesceReasonWireName(static_cast<QuiesceReason>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(quiesceReasonCount() == 4u,
              "wire contract: quiesce-reason has 4 values; update the CDDL + this switch together");

// --- LM CardCapabilities (masks) <-> CDDL `capability-bit` (bit indices) -----
// CardCapabilities is a BITMASK enum (None=0, PKI=1, IdentityData=2,
// EmrtdCrypto=4, PinManagement=8) — a plugin ORs these together into one
// `caps` field. The CDDL `capability-bit` group instead names the BIT INDEX
// each capability occupies inside the `capabilities = uint .bits
// capability-bit` socket (Pki: 0, IdentityData: 1, ...): CDDL `.bits` sockets
// are indexed by bit position, not by the mask value itself. The two are
// related by index = log2(mask); this switch makes that conversion explicit,
// one enumerator at a time, rather than comparing a mask to an index as if
// they were the same number. (CardCapabilities::None occupies no bit and has
// no CDDL entry; capabilityBitCount() below therefore counts from bit 0 and
// never visits it.)
constexpr std::uint32_t capabilityBitIndex(CardCapabilities c) noexcept
{
    switch (c) {
    case CardCapabilities::None:
        return 0xffffffffu; // sentinel: None is not a bit, never looked up
    case CardCapabilities::PKI:
        return 0u; // mask 1u << 0
    case CardCapabilities::IdentityData:
        return 1u; // mask 1u << 1
    case CardCapabilities::EmrtdCrypto:
        return 2u; // mask 1u << 2
    case CardCapabilities::PinManagement:
        return 3u; // mask 1u << 3
    }
    return 0xffffffffu;
}
// The CDDL wire name of each bit. Note the grammar spells the PKI bit "Pki"
// (CamelCase, like its neighbours), not the C++ enumerator's "PKI" acronym
// spelling — the wire name is its own vocabulary, not required to letter-
// match the C++ identifier it mirrors.
constexpr const char* capabilityWireName(CardCapabilities c) noexcept
{
    switch (c) {
    case CardCapabilities::None:
        return nullptr; // no CDDL entry
    case CardCapabilities::PKI:
        return "Pki";
    case CardCapabilities::IdentityData:
        return "IdentityData";
    case CardCapabilities::EmrtdCrypto:
        return "EmrtdCrypto";
    case CardCapabilities::PinManagement:
        return "PinManagement";
    }
    return nullptr;
}
// How many bits the enum actually declares, DERIVED from the switch above by
// walking bit positions — the bitmask counterpart of opPhaseCount() and
// friends. CardCapabilities is a bitmask rather than a contiguous 0..N
// enumeration, so the walk probes `1u << i` instead of `i`.
//
// Deriving this matters; a hand-written list of the four bits would leave
// capability-bit as the ONE vocabulary here with no cardinality anchor. Add
// `CardCapabilities::Biometric = 16` and -Werror=switch forces it into both
// switches above — but a hand-written list would still say four, the CDDL
// would still say four, and this guard would compare four against four and
// pass, while the agent reports a capability the contract never declares.
// Derived, the count becomes five and the static_assert below stops the build
// until the CDDL is updated too — the same way an appended op-phase is caught.
//
// The `i < 32` bound keeps the walk total: without it, a (hypothetical) enum
// occupying every bit would evaluate `1u << 32` and make this ill-formed.
constexpr std::uint32_t capabilityBitCount() noexcept
{
    std::uint32_t count = 0;
    while (count < 32u && capabilityWireName(static_cast<CardCapabilities>(1u << count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(capabilityBitCount() == 4u,
              "wire contract: capability-bit has 4 bits; update the CDDL + these switches together");

// --- agent ErrorCode <-> CDDL `error-code` (THE anchor) ----------------------
// Canonical wire name per enumerator. NO default case: with -Werror=switch on
// this target an appended enumerator is a compile error until it is named here,
// and the runtime comparison below then fails until the CDDL enumerates it too.
constexpr const char* wireNameFor(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::None:
        return "None";
    case ErrorCode::CardRemoved:
        return "CardRemoved";
    case ErrorCode::CredentialWrong:
        return "CredentialWrong";
    case ErrorCode::CredentialBlocked:
        return "CredentialBlocked";
    case ErrorCode::CommunicationError:
        return "CommunicationError";
    case ErrorCode::ParseError:
        return "ParseError";
    case ErrorCode::UnsupportedCard:
        return "UnsupportedCard";
    case ErrorCode::AuthFailed:
        return "AuthFailed";
    case ErrorCode::PrompterError:
        return "PrompterError";
    case ErrorCode::CapabilityMissing:
        return "CapabilityMissing";
    case ErrorCode::WatchdogTimeout:
        return "WatchdogTimeout";
    case ErrorCode::KeyNotFound:
        return "KeyNotFound";
    case ErrorCode::KeyAmbiguous:
        return "KeyAmbiguous";
    case ErrorCode::CertExpiredBlocked:
        return "CertExpiredBlocked";
    case ErrorCode::ChainIncomplete:
        return "ChainIncomplete";
    case ErrorCode::TsaUnreachable:
        return "TsaUnreachable";
    case ErrorCode::SigningEngineError:
        return "SigningEngineError";
    case ErrorCode::RateLimited:
        return "RateLimited";
    case ErrorCode::EngineUnavailable:
        return "EngineUnavailable";
    case ErrorCode::InvalidDocument:
        return "InvalidDocument";
    }
    return nullptr; // not a taxonomy value (used to probe past the end)
}

// Size derived from the switch itself (values outside it fall through to
// nullptr), so the count tracks the switch automatically and no separate
// constant can go stale — the failure mode of the count pin this replaced.
constexpr std::uint32_t taxonomyCount() noexcept
{
    std::uint32_t count = 0;
    while (wireNameFor(static_cast<ErrorCode>(count)) != nullptr) {
        ++count;
    }
    return count;
}

constexpr std::uint32_t kTaxonomyCount = taxonomyCount();
static_assert(u(ErrorCode::None) == 0u, "wire contract: ErrorCode::None drifted from 0");
static_assert(kTaxonomyCount >= 19u, "the taxonomy is append-only; it can only grow");

// --- wire::SyncError <-> CDDL `sync-error` ------------------------------------
// Named synchronous-method errors. Order is NOT wire-significant (the wire
// carries the NAME), so the runtime guard compares the CDDL group and this enum
// as SETS. This local switch mirrors the shipping wire::syncErrorName(): with
// -Werror=switch on this target an APPENDED SyncError member is a compile error
// here until it is named (and the CDDL enumerates it).
//
// SyncError::UnknownCredential / ::InvalidRequest are the credential-management
// members of wire::SyncError; they are named below like every other enumerator,
// so this switch (and the CDDL `sync-error` group) must be extended in lockstep
// with any future append to wire::SyncError.
constexpr const char* syncErrorWireName(SyncError e) noexcept
{
    switch (e) {
    case SyncError::UnknownCard:
        return "UnknownCard";
    case SyncError::KeyNotFound:
        return "KeyNotFound";
    case SyncError::NotAuthorized:
        return "NotAuthorized";
    case SyncError::UserNotLoggedIn:
        return "UserNotLoggedIn";
    case SyncError::UnknownConfigKey:
        return "UnknownConfigKey";
    case SyncError::ReadOnlyConfig:
        return "ReadOnlyConfig";
    case SyncError::InvalidConfigValue:
        return "InvalidConfigValue";
    case SyncError::UnsupportedProtocol:
        return "UnsupportedProtocol";
    case SyncError::AuthFailed:
        return "AuthFailed";
    case SyncError::CommunicationError:
        return "CommunicationError";
    case SyncError::NotSupported:
        return "NotSupported";
    case SyncError::UnsupportedOnThisCard:
        return "UnsupportedOnThisCard";
    case SyncError::UnsupportedSignatureParameter:
        return "UnsupportedSignatureParameter";
    case SyncError::InputTooLarge:
        return "InputTooLarge";
    case SyncError::RateLimited:
        return "RateLimited";
    case SyncError::UnknownCredential: // appended for credential management
        return "UnknownCredential";
    case SyncError::InvalidRequest: // appended for credential management
        return "InvalidRequest";
    case SyncError::NoResult: // appended: GetSignResult's dedicated dead-end name
        return "NoResult";
    }
    return nullptr; // not a SyncError value (used to probe past the end for the count)
}
constexpr std::uint32_t syncErrorCount() noexcept
{
    std::uint32_t count = 0;
    while (syncErrorWireName(static_cast<SyncError>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(syncErrorCount() >= 15u, "the sync-error vocabulary is append-only; it can only grow");

// --- LibreAgent CredentialOutcome <-> CDDL `cred-outcome` ---------------------
// Mutation outcome vocabulary. The CDDL group is authored in enum order, so the
// runtime guard compares value-for-value (append-only, like error-code). No
// default case: -Werror=switch breaks the build on an appended member.
constexpr const char* credOutcomeToken(CredentialOutcome o) noexcept
{
    switch (o) {
    case CredentialOutcome::Unspecified:
        return "unspecified";
    case CredentialOutcome::Ok:
        return "ok";
    case CredentialOutcome::UserCancelled:
        return "userCancelled";
    case CredentialOutcome::MissingFields:
        return "missingFields";
    case CredentialOutcome::InvalidPin:
        return "invalidPin";
    case CredentialOutcome::Blocked:
        return "blocked";
    case CredentialOutcome::PluginError:
        return "pluginError";
    case CredentialOutcome::Unsupported:
        return "unsupported";
    case CredentialOutcome::KeyActivationFailed:
        return "keyActivationFailed";
    case CredentialOutcome::CardRemoved:
        return "cardRemoved";
    }
    return nullptr;
}
constexpr std::uint32_t credOutcomeCount() noexcept
{
    std::uint32_t count = 0;
    while (credOutcomeToken(static_cast<CredentialOutcome>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(u(CredentialOutcome::Unspecified) == 0u, "wire contract: CredentialOutcome::Unspecified drifted from 0");
static_assert(credOutcomeCount() == 10u,
              "wire contract: cred-outcome has 10 tokens; update the CDDL + this switch together");

// --- LM credential-record vocab <-> CDDL record token groups -----------------
// Local exhaustive switches (append-guarded, no default) for the four enum-
// valued record fields, each pinned at runtime against the shipping
// detail::credential*Token helper the list flow emits. Order is NOT wire-
// significant here (cred-kind deliberately lists "unknown" LAST while the enum
// lists it FIRST), so the runtime guard set-compares each CDDL group.
constexpr const char* credKindToken(PinKind k) noexcept
{
    switch (k) {
    case PinKind::Unknown:
        return "unknown";
    case PinKind::UserPin:
        return "user";
    case PinKind::SignPin:
        return "sign";
    case PinKind::Puk:
        return "puk";
    case PinKind::Can:
        return "can";
    }
    return nullptr;
}
constexpr const char* credStateToken(PinState s) noexcept
{
    switch (s) {
    case PinState::Unknown:
        return "unknown";
    case PinState::Transport:
        return "transport";
    case PinState::Operational:
        return "operational";
    case PinState::NeedsChange:
        return "needsChange";
    case PinState::Blocked:
        return "blocked";
    }
    return nullptr;
}
constexpr const char* unblockStyleToken(UnblockStyle st) noexcept
{
    switch (st) {
    case UnblockStyle::Unknown:
        return "unknown";
    case UnblockStyle::ResetOnly:
        return "resetOnly";
    case UnblockStyle::SetsNewPin:
        return "setsNewPin";
    case UnblockStyle::UnblockAndChange:
        return "unblockAndChange";
    }
    return nullptr;
}
constexpr const char* credRecoveryToken(PinRecovery r) noexcept
{
    switch (r) {
    case PinRecovery::Unknown:
        return "unknown";
    case PinRecovery::HolderViaPuk:
        return "holderViaPuk";
    case PinRecovery::IssuerProcess:
        return "issuerProcess";
    case PinRecovery::None:
        return "none";
    }
    return nullptr;
}
constexpr std::uint32_t credKindCount() noexcept
{
    std::uint32_t count = 0;
    while (credKindToken(static_cast<PinKind>(count)) != nullptr) {
        ++count;
    }
    return count;
}
constexpr std::uint32_t credStateCount() noexcept
{
    std::uint32_t count = 0;
    while (credStateToken(static_cast<PinState>(count)) != nullptr) {
        ++count;
    }
    return count;
}
constexpr std::uint32_t unblockStyleCount() noexcept
{
    std::uint32_t count = 0;
    while (unblockStyleToken(static_cast<UnblockStyle>(count)) != nullptr) {
        ++count;
    }
    return count;
}
constexpr std::uint32_t credRecoveryCount() noexcept
{
    std::uint32_t count = 0;
    while (credRecoveryToken(static_cast<PinRecovery>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(credKindCount() == 5u, "wire contract: cred-kind has 5 tokens");
static_assert(credStateCount() == 5u, "wire contract: cred-state has 5 tokens");
static_assert(unblockStyleCount() == 4u, "wire contract: unblock-style has 4 tokens");
static_assert(credRecoveryCount() == 4u, "wire contract: cred-recovery has 4 tokens");

// --- CDDL `cred-verb` string literals (no upstream enum — pinned as a set) ----
constexpr std::array<std::string_view, 3> kCredVerbs{"change", "unblock", "activate_pin"};
static_assert(kCredVerbs.size() == 3u, "wire contract: cred-verb has 3 tokens");

// --- CDDL `cred-record` map keys (camelCase; == CredentialRecord field names) -
// The full ordered key set, shared with the codec test's cred-record
// expectations. NOTE: this is 23 keys — CredentialRecord has 23 fields and the
// D-Bus a{sv} lists 23 keys.
constexpr std::array<std::string_view, 23> kCredRecordKeys{"id",
                                                           "label",
                                                           "kind",
                                                           "state",
                                                           "retriesLeft",
                                                           "retriesMax",
                                                           "usesLeft",
                                                           "usesMax",
                                                           "unblocksLeft",
                                                           "minLength",
                                                           "maxLength",
                                                           "canChange",
                                                           "unblockable",
                                                           "unblockStyle",
                                                           "activatable",
                                                           "keyActivationPending",
                                                           "keyActivatable",
                                                           "recovery",
                                                           "probeSafe",
                                                           "blockedGuidanceKey",
                                                           "blockedGuidanceFallback",
                                                           "keyActivationGuidanceKey",
                                                           "keyActivationGuidanceFallback"};
static_assert(kCredRecordKeys.size() == 23u, "wire contract: cred-record has 23 keys");

// --- CDDL message `t:` tags: presence + count drift guard --------------------
// The socket message vocabulary (request + event `t:` tags) has no upstream enum
// to anchor to (the tags are CDDL string literals), so this table pins the SET.
// Adding/removing a message MUST update: the CDDL (agent/wire/librescrs-agent.cddl),
// wire/Messages.{h,cpp}, and this table (bump kMessageTagCount). The
// MessagesRoundTripTest proves each tag actually encodes/decodes; this only pins
// that the vocabulary did not silently change size.
constexpr std::array<std::string_view, 35> kMessageTags{
    // requests (24)
    "Hello", "GetState", "ReadIdentity", "GetPhoto", "ReadCertificates", "ReadTokenInfo", "Sign", "SignBatch",
    "GetCertDer", "GetConfig", "SetConfig", "ResetConfig", "CancelOp", "GetSignResult", "Pkcs11.Login", "Pkcs11.Logout",
    "Pkcs11.PublicKey", "Pkcs11.SignRaw", "Pkcs11.Decrypt", "ListCredentials", "ManagePin", "ActivateSigningKey",
    "LayoutVisual", "GetAppearanceFont",
    // events (11)
    "ReaderAdded", "ReaderRemoved", "CardAdded", "CardRemoved", "PropertyChanged", "ConfigChanged", "OpProgress",
    "OpIdentityGroup", "OpResultReady", "OpFinished", "AgentQuiesced"};
constexpr std::size_t kMessageTagCount = 35; // 24 requests + 11 events
static_assert(kMessageTags.size() == kMessageTagCount,
              "wire contract: socket message vocabulary changed; update the CDDL + wire/Messages + this guard");

// Sorted-set equality of two token lists, with a labeled failure. Order-
// insensitive: for the record vocab groups (and sync-error) the wire carries the
// NAME, so only the SET of tokens is contractually pinned.
void expectSameTokenSet(std::vector<std::string> cddlTokens, std::vector<std::string> enumTokens,
                        std::string_view group)
{
    std::sort(cddlTokens.begin(), cddlTokens.end());
    std::sort(enumTokens.begin(), enumTokens.end());
    EXPECT_EQ(cddlTokens, enumTokens) << "the CDDL `" << group << "` group and its upstream enum drifted";
}

} // namespace

// A compiled TU is required to evaluate the static_asserts; the runtime body is
// a formality (matches the Linux WireContractGuard). The exhaustiveness switches
// below carry the append-detection the value pins above cannot: with
// -Werror=switch on this target, an upstream APPEND to any anchored enum adds an
// unhandled enumerator and breaks the build (forcing a matching CDDL + LibreMac
// mirror update). The value pins catch a RENUMBER; these catch an APPEND.
TEST(WireContractGuard, MacOsAnchorsHold)
{
    // Spot-check the tag table is populated (defends against an all-empty init).
    EXPECT_EQ(kMessageTags.front(), "Hello");
    EXPECT_EQ(kMessageTags.back(), "AgentQuiesced");

    for (const auto phase : {OperationPhase::Created, OperationPhase::Connecting, OperationPhase::AwaitingConsent,
                             OperationPhase::Authenticating, OperationPhase::Reading, OperationPhase::Signing,
                             OperationPhase::Timestamping, OperationPhase::Done}) {
        switch (phase) { // no default: -Werror=switch fires on an appended phase
        case OperationPhase::Created:
        case OperationPhase::Connecting:
        case OperationPhase::AwaitingConsent:
        case OperationPhase::Authenticating:
        case OperationPhase::Reading:
        case OperationPhase::Signing:
        case OperationPhase::Timestamping:
        case OperationPhase::Done:
            break;
        }
    }
    for (const auto status : {OperationStatus::Ok, OperationStatus::Cancelled, OperationStatus::Error}) {
        switch (status) { // no default
        case OperationStatus::Ok:
        case OperationStatus::Cancelled:
        case OperationStatus::Error:
            break;
        }
    }
    for (const auto method : {PreReadAuthMethod::None, PreReadAuthMethod::Mrz, PreReadAuthMethod::Can}) {
        switch (method) { // no default
        case PreReadAuthMethod::None:
        case PreReadAuthMethod::Mrz:
        case PreReadAuthMethod::Can:
            break;
        }
    }
    for (const auto cap : {CardCapabilities::None, CardCapabilities::PKI, CardCapabilities::IdentityData,
                           CardCapabilities::EmrtdCrypto, CardCapabilities::PinManagement}) {
        switch (cap) { // no default: an appended capability bit breaks the build
        case CardCapabilities::None:
        case CardCapabilities::PKI:
        case CardCapabilities::IdentityData:
        case CardCapabilities::EmrtdCrypto:
        case CardCapabilities::PinManagement:
            break;
        }
    }
    SUCCEED();
}

// The CDDL is the wire contract of record and the Swift client mirrors it by
// hand; neither links LM, so this is the only place they can be tied back to the
// upstream taxonomy. wireNameFor()'s switch makes an APPEND a compile error, and
// this test makes a stale CDDL a test failure.
//
// What a missing code actually costs, precisely: it still reaches the wire, and
// the client decodes it into its tolerant `.unknown(UInt32)` arm rather than
// refusing the message. So nothing breaks loudly — the value is carried through
// unnamed, the client cannot map it to its own localized text, and the user is
// shown the agent's fallback string instead. Quiet degradation, which is why it
// needs a test rather than a runtime failure to surface it.
TEST(WireContractGuard, CddlErrorCodeMatchesAgentEnumValueForValue)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlErrorCode(cddl);
    ASSERT_FALSE(entries.empty()) << "could not locate the `error-code = &( ... )` group in librescrs-agent.cddl — "
                                     "if it was reformatted, keep the `Name: <value>` entries this guard parses";

    EXPECT_EQ(entries.size(), kTaxonomyCount)
        << "the CDDL enumerates " << entries.size() << " error codes but the agent ErrorCode enum has "
        << kTaxonomyCount << " — the CDDL is the macOS wire contract of record, keep the two identical (append-only). "
        << "A code the CDDL omits still reaches the wire; the client decodes it as unknown and shows the agent's "
           "fallback text instead of its own";

    const std::size_t common = std::min<std::size_t>(entries.size(), kTaxonomyCount);
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].first, static_cast<std::uint32_t>(i))
            << "the CDDL error-code group is not contiguous at entry " << i
            << " — the taxonomy is append-only from 0, never renumbered";
        EXPECT_EQ(entries[i].second, wireNameFor(static_cast<ErrorCode>(i)))
            << "the CDDL names error-code " << i << " '" << entries[i].second << "' but the agent enum calls it '"
            << wireNameFor(static_cast<ErrorCode>(i)) << "'";
    }
}

// The CDDL `capability-bit` group mirrors CardCapabilities bit for bit. The
// CDDL entry is a BIT INDEX (0, 1, 2, 3); CardCapabilities carries a MASK (1,
// 2, 4, 8) — capabilityBitIndex() above does the explicit index<->mask
// conversion, so this test never compares a mask to an index directly.
TEST(WireContractGuard, CddlCapabilityBitMatchesAgentEnumBitForBit)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlNumericGroup(cddl, "capability-bit");
    ASSERT_FALSE(entries.empty()) << "could not locate the `capability-bit = ( ... )` group in librescrs-agent.cddl";
    EXPECT_EQ(entries.size(), capabilityBitCount())
        << "the CDDL `capability-bit` group has " << entries.size() << " entries but CardCapabilities has "
        << capabilityBitCount() << " non-None bits";

    const std::size_t common = std::min<std::size_t>(entries.size(), capabilityBitCount());
    for (std::size_t i = 0; i < common; ++i) {
        // Bit i's mask, so the walk visits the enumerators in CDDL bit order.
        const CardCapabilities cap = static_cast<CardCapabilities>(1u << i);
        EXPECT_EQ(entries[i].value, capabilityBitIndex(cap))
            << "the CDDL capability-bit group is not contiguous at entry " << i;
        EXPECT_EQ(entries[i].name, capabilityWireName(cap))
            << "the CDDL names capability-bit " << i << " '" << entries[i].name << "' but the agent enum calls it '"
            << capabilityWireName(cap) << "'";
        EXPECT_EQ(u(cap), (1u << capabilityBitIndex(cap)))
            << "CardCapabilities " << capabilityWireName(cap)
            << " mask no longer matches 1u << its CDDL capability-bit index";
    }
}

// The CDDL `pre-read-auth` socket mirrors PreReadAuthMethod value for value
// (both authored in enum order, append-only, wire-frozen per the CDDL's own
// tolerance comment).
TEST(WireContractGuard, CddlPreReadAuthMatchesAgentEnumValueForValue)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlNumericGroup(cddl, "pre-read-auth");
    ASSERT_FALSE(entries.empty()) << "could not locate the `pre-read-auth = &( ... )` group in librescrs-agent.cddl";
    EXPECT_EQ(entries.size(), preReadAuthCount()) << "the CDDL `pre-read-auth` group has " << entries.size()
                                                  << " entries but PreReadAuthMethod has " << preReadAuthCount();

    const std::size_t common = std::min<std::size_t>(entries.size(), preReadAuthCount());
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].value, static_cast<std::uint32_t>(i))
            << "the CDDL pre-read-auth group is not contiguous at entry " << i;
        EXPECT_EQ(entries[i].name, preReadAuthWireName(static_cast<PreReadAuthMethod>(i)))
            << "the CDDL names pre-read-auth " << i << " '" << entries[i].name << "' but the agent enum calls it '"
            << preReadAuthWireName(static_cast<PreReadAuthMethod>(i)) << "'";
    }
}

// The CDDL `op-phase` socket mirrors OperationPhase value for value (both
// authored in enum order, append-only, wire-frozen per the CDDL's own
// tolerance comment).
TEST(WireContractGuard, CddlOpPhaseMatchesAgentEnumValueForValue)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlNumericGroup(cddl, "op-phase");
    ASSERT_FALSE(entries.empty()) << "could not locate the `op-phase = &( ... )` group in librescrs-agent.cddl";
    EXPECT_EQ(entries.size(), opPhaseCount())
        << "the CDDL `op-phase` group has " << entries.size() << " entries but OperationPhase has " << opPhaseCount();

    const std::size_t common = std::min<std::size_t>(entries.size(), opPhaseCount());
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].value, static_cast<std::uint32_t>(i))
            << "the CDDL op-phase group is not contiguous at entry " << i;
        EXPECT_EQ(entries[i].name, opPhaseWireName(static_cast<OperationPhase>(i)))
            << "the CDDL names op-phase " << i << " '" << entries[i].name << "' but the agent enum calls it '"
            << opPhaseWireName(static_cast<OperationPhase>(i)) << "'";
    }
}

// The CDDL `op-status` socket mirrors OperationStatus value for value, same
// shape as op-phase above.
TEST(WireContractGuard, CddlOpStatusMatchesAgentEnumValueForValue)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlNumericGroup(cddl, "op-status");
    ASSERT_FALSE(entries.empty()) << "could not locate the `op-status = &( ... )` group in librescrs-agent.cddl";
    EXPECT_EQ(entries.size(), opStatusCount()) << "the CDDL `op-status` group has " << entries.size()
                                               << " entries but OperationStatus has " << opStatusCount();

    const std::size_t common = std::min<std::size_t>(entries.size(), opStatusCount());
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].value, static_cast<std::uint32_t>(i))
            << "the CDDL op-status group is not contiguous at entry " << i;
        EXPECT_EQ(entries[i].name, opStatusWireName(static_cast<OperationStatus>(i)))
            << "the CDDL names op-status " << i << " '" << entries[i].name << "' but the agent enum calls it '"
            << opStatusWireName(static_cast<OperationStatus>(i)) << "'";
    }
}

// The CDDL `quiesce-reason` socket mirrors wire::QuiesceReason value for
// value. No LM/core enum backs this one (it is socket-only lifecycle state),
// but the same drift risk applies: the grammar could rename or renumber a
// reason with nothing to notice besides this guard.
TEST(WireContractGuard, CddlQuiesceReasonMatchesWireEnumValueForValue)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlNumericGroup(cddl, "quiesce-reason");
    ASSERT_FALSE(entries.empty()) << "could not locate the `quiesce-reason = &( ... )` group in librescrs-agent.cddl";
    EXPECT_EQ(entries.size(), quiesceReasonCount()) << "the CDDL `quiesce-reason` group has " << entries.size()
                                                    << " entries but QuiesceReason has " << quiesceReasonCount();

    const std::size_t common = std::min<std::size_t>(entries.size(), quiesceReasonCount());
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].value, static_cast<std::uint32_t>(i))
            << "the CDDL quiesce-reason group is not contiguous at entry " << i;
        EXPECT_EQ(entries[i].name, quiesceReasonWireName(static_cast<QuiesceReason>(i)))
            << "the CDDL names quiesce-reason " << i << " '" << entries[i].name << "' but the agent enum calls it '"
            << quiesceReasonWireName(static_cast<QuiesceReason>(i)) << "'";
    }
}

// The CDDL `sync-error` names mirror wire::SyncError, compared as a SET (the wire
// carries the name, so order is not significant). The syncErrorWireName() switch
// makes an APPEND a compile error; this makes a stale CDDL a test failure and
// pins the guard's expectation to the shipping wire::syncErrorName() so the two
// appended names actually reach the wire.
TEST(WireContractGuard, CddlSyncErrorMatchesWireEnum)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto cddlTokens = cddlQuotedTokens(cddlRuleRhs(cddl, "sync-error"));
    ASSERT_FALSE(cddlTokens.empty()) << "could not locate the `sync-error = ...` group in librescrs-agent.cddl";
    EXPECT_EQ(cddlTokens.size(), syncErrorCount()) << "the CDDL `sync-error` group enumerates " << cddlTokens.size()
                                                   << " names but wire::SyncError has " << syncErrorCount();

    std::vector<std::string> enumTokens;
    for (std::uint32_t i = 0; i < syncErrorCount(); ++i) {
        const auto e = static_cast<SyncError>(i);
        enumTokens.emplace_back(syncErrorWireName(e));
        EXPECT_EQ(syncErrorName(e), std::string_view(syncErrorWireName(e)))
            << "wire::syncErrorName() disagrees with the guard at SyncError " << i;
        // The INVERSE half, walked over the same append-protected bound. Both
        // halves are on the public surface now (a Qt client turns an error name
        // back into an enumerator at its own classification seam), and the
        // decoder's candidate list is the one piece of this vocabulary with no
        // compile-time append protection of its own — syncErrorName()'s switch
        // is exhaustive, but a member missing from the decoder's list only
        // shows up as a token that silently degrades to CommunicationError.
        // This is that check, and it is not a tautology: the expectation comes
        // from THIS file's independent name table, not from either function.
        EXPECT_EQ(decodeSyncError(syncErrorWireName(e)), e)
            << "wire::decodeSyncError() does not round-trip SyncError " << i << " ('" << syncErrorWireName(e)
            << "') — is it missing from the decoder's candidate list?";
    }
    expectSameTokenSet(cddlTokens, enumTokens, "sync-error");
}

// The CDDL `cred-outcome` group mirrors LibreAgent CredentialOutcome value-for-
// value (both authored in enum order, append-only).
TEST(WireContractGuard, CddlCredentialOutcomeMatchesAgentEnum)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto tokens = cddlQuotedTokens(cddlRuleRhs(cddl, "cred-outcome"));
    ASSERT_EQ(tokens.size(), credOutcomeCount()) << "the CDDL `cred-outcome` group has " << tokens.size()
                                                 << " tokens but CredentialOutcome has " << credOutcomeCount();
    for (std::uint32_t i = 0; i < credOutcomeCount(); ++i) {
        EXPECT_EQ(tokens[i], credOutcomeToken(static_cast<CredentialOutcome>(i)))
            << "cred-outcome token " << i << " drifted from CredentialOutcome";
    }
}

// The CDDL `cred-verb` closed set matches the three management verbs. No upstream
// enum — the verbs are wire string literals, pinned here (and by the credential
// codec tests).
TEST(WireContractGuard, CddlCredentialVerbsMatchTokens)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto tokens = cddlQuotedTokens(cddlRuleRhs(cddl, "cred-verb"));
    ASSERT_EQ(tokens.size(), kCredVerbs.size()) << "the CDDL `cred-verb` group changed size";
    for (std::size_t i = 0; i < kCredVerbs.size(); ++i) {
        EXPECT_EQ(tokens[i], kCredVerbs[i]) << "cred-verb token " << i << " drifted";
    }
}

// The four enum-valued record vocabularies (kind/state/unblock-style/recovery)
// match the shipping detail::credential*Token helpers, and the CDDL groups match
// them as SETS (cred-kind's source order deliberately differs from the enum's).
TEST(WireContractGuard, CddlCredentialRecordVocabMatchesAgentHelpers)
{
    namespace detail = LibreSCRS::Agent::detail;
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    std::vector<std::string> kinds;
    for (std::uint32_t i = 0; i < credKindCount(); ++i) {
        const auto k = static_cast<PinKind>(i);
        EXPECT_EQ(std::string(credKindToken(k)), detail::credentialKindToken(k)) << "cred-kind helper drift at " << i;
        kinds.emplace_back(credKindToken(k));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "cred-kind")), kinds, "cred-kind");

    std::vector<std::string> states;
    for (std::uint32_t i = 0; i < credStateCount(); ++i) {
        const auto s = static_cast<PinState>(i);
        EXPECT_EQ(std::string(credStateToken(s)), detail::credentialStateToken(s))
            << "cred-state helper drift at " << i;
        states.emplace_back(credStateToken(s));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "cred-state")), states, "cred-state");

    std::vector<std::string> styles;
    for (std::uint32_t i = 0; i < unblockStyleCount(); ++i) {
        const auto st = static_cast<UnblockStyle>(i);
        EXPECT_EQ(std::string(unblockStyleToken(st)), detail::unblockStyleToken(st))
            << "unblock-style helper drift at " << i;
        styles.emplace_back(unblockStyleToken(st));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "unblock-style")), styles, "unblock-style");

    std::vector<std::string> recoveries;
    for (std::uint32_t i = 0; i < credRecoveryCount(); ++i) {
        const auto r = static_cast<PinRecovery>(i);
        EXPECT_EQ(std::string(credRecoveryToken(r)), detail::recoveryToken(r)) << "cred-recovery helper drift at " << i;
        recoveries.emplace_back(credRecoveryToken(r));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "cred-recovery")), recoveries, "cred-recovery");
}

// The CDDL `cred-record` map keys match the credential-record contract key set
// (camelCase, in declaration order). Shared with the credential codec test
// expectations.
TEST(WireContractGuard, CddlCredentialRecordKeysMatchContract)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto keys = cddlMapKeys(cddlRuleRhs(cddl, "cred-record"));
    ASSERT_EQ(keys.size(), kCredRecordKeys.size()) << "the CDDL `cred-record` group has " << keys.size()
                                                   << " keys but the contract fixes " << kCredRecordKeys.size();
    for (std::size_t i = 0; i < kCredRecordKeys.size(); ++i) {
        EXPECT_EQ(keys[i], kCredRecordKeys[i]) << "cred-record key " << i << " drifted";
    }
}

// A vocabulary added to the grammar and NOT mirrored downstream is the failure
// this whole gate exists to prevent, and the clients mirror it by hand in a
// repository this test cannot see. Asserting the SET is what makes the addition
// impossible to miss: a new closed group turns this red and forces a decision --
// mirror it in the clients, or record it here as knowingly unmirrored. Without
// this, a new vocabulary simply would not be checked anywhere, which is the
// quietest way for a gate to stop covering what people believe it covers.
TEST(WireContractGuard, ClosedVocabulariesAreTheExpectedSet)
{
    const std::string cddl = slurp(LIBRESCRS_AGENT_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const std::set<std::string> expected = {
        "capability-bit", "cred-kind",           "cred-outcome", "cred-recovery", "cred-state",
        "cred-verb",      "error-code",          "op-phase",     "op-status",     "pre-read-auth",
        "quiesce-reason", "settable-config-key", "sync-error",   "unblock-style",
    };

    std::set<std::string> found;
    for (const auto& g : discoverClosedGroups(cddl)) {
        found.insert(g.rule);
    }

    EXPECT_EQ(found, expected) << "the closed vocabularies in the grammar are not the ones this guard expects. "
                                  "If one was added, mirror it in the clients and list it here in the same change; "
                                  "silence here is what lets a client fall behind unnoticed.";
}
