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

/// @brief What a credential secures (wire `kind`: "user" / "sign" / "puk" / "can").
enum class CredentialKind {
    User,    ///< Card-holder/global PIN gating identity or general operations.
    Sign,    ///< Signing-key PIN, distinct from the user PIN on cards that separate them.
    Puk,     ///< PUK — recovery secret for a blocked PIN.
    Can,     ///< Card Access Number — pre-read PACE unlock, not a holder-chosen secret.
    Unknown, ///< An unrecognised wire `kind` token (forward-compat).
};

/// @brief Lifecycle state of a credential (wire `state`: "transport" /
///        "operational" / "needsChange" / "blocked").
enum class CredentialState {
    Unknown,     ///< An unrecognised wire `state` token (forward-compat).
    Transport,   ///< Factory/issuance default secret, not yet activated by the holder.
    Operational, ///< Holder-set secret, normal operating state.
    NeedsChange, ///< Usable but the issuer/agent flags it for a mandatory change.
    Blocked,     ///< Retry counter exhausted; needs `RecoveryPath` before further use.
};

/// @brief How a blocked credential can be unblocked (wire `unblock_style`:
///        "resetOnly" / "setsNewPin" / "unblockAndChange").
enum class UnblockStyle {
    Unknown,          ///< An unrecognised wire token, or not applicable (unblockable == false).
    ResetOnly,        ///< Unblock resets the retry counter only; the PIN value is unchanged.
    SetsNewPin,       ///< Unblock requires and sets a brand-new PIN value.
    UnblockAndChange, ///< Unblock resets the counter AND the holder must then change the PIN.
};

/// @brief Where the recovery secret/process for a blocked credential lives
///        (wire `recovery`: "holderViaPuk" / "issuerProcess" / "none").
enum class RecoveryPath {
    Unknown,       ///< An unrecognised wire token.
    HolderViaPuk,  ///< The holder can self-recover with the card's PUK via `managePin(Unblock)`.
    IssuerProcess, ///< Recovery requires an out-of-band issuer process; this library cannot perform it.
    None,          ///< No recovery path exists (or none applicable while unblockable == false).
};

/// @brief Per-attempt outcome of a `managePin()` / `activateSigningKey()`
///        mutation (wire `outcome`).
enum class CredentialOutcome {
    Unspecified,         ///< No outcome reported (e.g. a recovered/synthesized terminal).
    Ok,                  ///< The mutation succeeded.
    UserCancelled,       ///< The holder cancelled a prompt mid-attempt.
    MissingFields,       ///< The request omitted a field the verb requires.
    InvalidPin,          ///< The supplied secret was wrong.
    Blocked,             ///< The credential is blocked; the attempt did not proceed.
    PluginError,         ///< The card plugin reported an internal failure.
    Unsupported,         ///< The card/plugin does not support this verb.
    KeyActivationFailed, ///< The associated signing-key activation step failed.
    CardRemoved,         ///< The card was removed mid-attempt.
};

/// @brief One ListCredentials record (one wire record-map entry). Optional
///        ints/strings are absent when the wire omits the key (never a
///        sentinel); bools default false.
struct LIBRESCRS_AGENTCLIENT_EXPORT CredentialRecord
{
    QString id;                                       ///< Opaque credential id — pass back as-is to `managePin()`.
    QString label;                                    ///< Agent-authored display label.
    CredentialKind kind = CredentialKind::Unknown;    ///< What this credential secures.
    CredentialState state = CredentialState::Unknown; ///< Current lifecycle state.
    std::optional<int> retriesLeft;    ///< Remaining verify attempts before blocking, if the card reports it.
    std::optional<int> retriesMax;     ///< Verify-attempt ceiling, if the card reports it.
    std::optional<int> usesLeft;       ///< Remaining uses for a use-limited credential (e.g. a PUK), if applicable.
    std::optional<int> usesMax;        ///< Use ceiling for a use-limited credential, if applicable.
    std::optional<int> unblocksLeft;   ///< Remaining unblock attempts, if the card reports it.
    std::optional<int> minLength;      ///< Minimum accepted secret length, if the card reports it.
    std::optional<int> maxLength;      ///< Maximum accepted secret length, if the card reports it.
    bool canChange = false;            ///< Whether `managePin(Change)` is available for this credential.
    bool unblockable = false;          ///< Whether a `RecoveryPath` exists for this credential.
    bool activatable = false;          ///< Whether `managePin(ActivatePin)` applies to this credential.
    bool keyActivationPending = false; ///< Whether a signing key behind this credential awaits activation.
    bool keyActivatable = false;       ///< Whether `activateSigningKey()` can be called for this credential now.
    bool probeSafe = false; ///< Whether verifying this credential is safe to probe without consuming a retry.
    UnblockStyle unblockStyle = UnblockStyle::Unknown; ///< How unblocking behaves, when `unblockable` is true.
    RecoveryPath recovery = RecoveryPath::Unknown;     ///< Where the recovery secret/process lives.
    std::optional<QString>
        blockedGuidanceKey; ///< i18n key for holder guidance when blocked, if the agent supplies one.
    std::optional<QString> blockedGuidanceFallback;       ///< English fallback for `blockedGuidanceKey`.
    std::optional<QString> keyActivationGuidanceKey;      ///< i18n key for key-activation guidance, if supplied.
    std::optional<QString> keyActivationGuidanceFallback; ///< English fallback for `keyActivationGuidanceKey`.
    QVariantMap extra; ///< Forward-compatible pass-through, as on every result struct.

    /// @brief Parse one wire record-map entry (snake_case keys, e.g.
    ///        "retries_left") into a `CredentialRecord`. Keys not consumed by
    ///        a named field land in `extra`.
    [[nodiscard]] static CredentialRecord fromVariantMap(const QVariantMap& m);
};
/// @brief The `listCredentials()` result: one `CredentialRecord` per
///        credential the card reports.
using CredentialList = QList<CredentialRecord>;

/// @brief The uniform mutation result of a `managePin()` / `activateSigningKey()`
///        attempt. Unlike the Ok-only read results, this is delivered for
///        EVERY completed attempt — including the soft-fail outcomes
///        (`InvalidPin` / `Blocked`) that finish `OperationStatus::Error` —
///        so `outcome` is meaningful even when the operation's status is
///        Error.
struct LIBRESCRS_AGENTCLIENT_EXPORT PinResult
{
    CredentialOutcome outcome = CredentialOutcome::Unspecified; ///< What happened.
    std::optional<int> retriesLeft;   ///< Remaining verify attempts after this attempt, if the card reports it.
    bool blocked = false;             ///< Whether the credential is now blocked as a result of this attempt.
    std::optional<bool> pinActivated; ///< Whether an `ActivatePin` attempt activated the PIN, if applicable.
    std::optional<bool> keyActivated; ///< Whether the associated signing key was activated, if applicable.
    QVariantMap extra;                ///< Forward-compatible pass-through, as on every result struct.

    /// @brief Parse one wire mutation-result map (snake_case keys, e.g.
    ///        "retries_left") into a `PinResult`. Keys not consumed by a
    ///        named field land in `extra`.
    [[nodiscard]] static PinResult fromVariantMap(const QVariantMap& m);
};

} // namespace LibreSCRS::AgentClient
