// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <optional>
#include <string>

// Std-only mirror of the credential wire shapes Messages.h serializes:
// LibreSCRS::Agent::CredentialOutcome, ::CredentialRecord and
// ::CredentialOpResult (see this repo's value/CredentialRecord.h). That
// header's STRUCT/ENUM definitions are themselves all-std, but the same
// translation unit also declares LM-dependent conversion helpers
// (toCredentialRecord() et al.) and therefore includes two of the
// middleware's plugin headers for the entry-type it converts FROM — pulling
// LM into any TU that just wants the wire shapes. Messages.h wants the
// shapes only (the codec maps fields to wire tokens/keys itself; it never
// calls the LM-facing conversion helpers), so it re-bases onto this
// LM-free mirror instead.
//
// This mirror is NOT self-certifying: src/wire/WireParityChecks.cpp
// (core-gated, so it sees both this header and the authoritative
// LibreSCRS::Agent types) statically asserts CredentialOutcome's enumerator
// values and every CredentialRecord/CredentialOpResult field's type stay in
// lockstep with the authoritative definitions. Never edit one side without
// the other.

namespace LibreSCRS::Agent::Wire {

// Mirror of LibreSCRS::Agent::CredentialOutcome. On the wire each member
// crosses as its camelCase STRING token (see Messages.cpp's
// credOutcomeToken): unspecified|ok|userCancelled|missingFields|invalidPin|
// blocked|pluginError|unsupported|keyActivationFailed|cardRemoved|entryExpired.
enum class CredentialOutcome {
    Unspecified,
    Ok,
    UserCancelled,
    MissingFields,
    InvalidPin,
    Blocked,
    PluginError,
    Unsupported,
    KeyActivationFailed,
    CardRemoved, // agent-assigned; never produced by LM
    // The credential window closed because the holder's entry time ran out.
    // Agent-assigned; never produced by LM.
    EntryExpired,
};

// Mirror of LibreSCRS::Agent::CredentialRecord. Field names ARE the wire
// keys (camelCase, matching Messages.cpp's encodeCredRecord() verbatim);
// every field below is written unconditionally or, for the std::optional
// ones, omitted when nullopt — never derived/computed on the wire side.
struct CredentialRecord
{
    std::string id;
    std::string label;
    std::string kind;
    std::string state;
    std::optional<int> retriesLeft, retriesMax, usesLeft, usesMax, unblocksLeft;
    std::optional<int> minLength, maxLength;
    bool canChange = false, unblockable = false;
    std::string unblockStyle;
    bool activatable = false, keyActivationPending = false, keyActivatable = false;
    std::string recovery;
    bool probeSafe = false;
    std::optional<std::string> blockedGuidanceKey, blockedGuidanceFallback;
    std::optional<std::string> keyActivationGuidanceKey, keyActivationGuidanceFallback;
    [[nodiscard]] bool operator==(const CredentialRecord&) const = default;
};

// Mirror of LibreSCRS::Agent::CredentialOpResult. Wire shape (see
// Messages.cpp's encodeCredResult()):
// cred-result = { outcome, ? retriesLeft, blocked, ? pinActivated, ? keyActivated }.
struct CredentialOpResult
{
    CredentialOutcome outcome = CredentialOutcome::Unspecified;
    std::optional<int> retriesLeft;
    bool blocked = false;
    std::optional<bool> pinActivated, keyActivated;
    [[nodiscard]] bool operator==(const CredentialOpResult&) const = default;
};

} // namespace LibreSCRS::Agent::Wire
