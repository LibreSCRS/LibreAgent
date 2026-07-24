// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/Export.h>

#include <QList>
#include <QString>
#include <QVariantMap>

#include <optional>

/// @file
/// @brief Client-side mirror of the frozen agent credential-management wire
///        vocabulary (the ListCredentials record set and the uniform ManagePin
///        mutation result — see `cred-record` / `cred-result` in
///        wire/librescrs-agent.cddl and the Credentials1 /
///        Operation.Credentials1 D-Bus contracts, which carry the same
///        snake_case key spellings). Pure Qt value types; no middleware, no
///        transport types, no secrets.

namespace LibreSCRS::AgentClient {

enum class CredentialKind { User, Sign, Puk, Can, Unknown };
enum class CredentialState { Unknown, Transport, Operational, NeedsChange, Blocked };
enum class UnblockStyle { Unknown, ResetOnly, SetsNewPin, UnblockAndChange };
enum class RecoveryPath { Unknown, HolderViaPuk, IssuerProcess, None };
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
    CardRemoved
};

/// One ListCredentials record (one wire record-map entry). Optional ints are
/// absent when the wire omits the key (never a sentinel); bools default false.
struct LIBRESCRS_AGENTCLIENT_EXPORT CredentialRecord
{
    QString id;
    QString label;
    CredentialKind kind = CredentialKind::Unknown;
    CredentialState state = CredentialState::Unknown;
    std::optional<int> retriesLeft, retriesMax, usesLeft, usesMax, unblocksLeft, minLength, maxLength;
    bool canChange = false, unblockable = false, activatable = false;
    bool keyActivationPending = false, keyActivatable = false, probeSafe = false;
    UnblockStyle unblockStyle = UnblockStyle::Unknown;
    RecoveryPath recovery = RecoveryPath::Unknown;
    std::optional<QString> blockedGuidanceKey, blockedGuidanceFallback;
    std::optional<QString> keyActivationGuidanceKey, keyActivationGuidanceFallback;
    QVariantMap extra; ///< Forward-compatible pass-through, as on every result struct.

    [[nodiscard]] static CredentialRecord fromVariantMap(const QVariantMap& m);
};
using CredentialList = QList<CredentialRecord>;

/// The uniform mutation result of a ManagePin / ActivateSigningKey attempt.
/// Unlike the Ok-only read results, this is delivered for EVERY completed
/// attempt — including the soft-fail outcomes (invalidPin / blocked) that
/// finish Error — so `outcome` is meaningful even when the operation's
/// status is Error.
struct LIBRESCRS_AGENTCLIENT_EXPORT PinResult
{
    CredentialOutcome outcome = CredentialOutcome::Unspecified;
    std::optional<int> retriesLeft;
    bool blocked = false;
    std::optional<bool> pinActivated, keyActivated;
    QVariantMap extra; ///< Forward-compatible pass-through, as on every result struct.

    [[nodiscard]] static PinResult fromVariantMap(const QVariantMap& m);
};

} // namespace LibreSCRS::AgentClient
