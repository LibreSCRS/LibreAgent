// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

// Agent-side outcome vocabulary for credential mutations: LM
// Plugin::PINResultOutcome verbatim (nine members, ending at
// KeyActivationFailed) plus an appended CardRemoved that only the agent
// assigns — the mutation flows map the seam signal they classify as
// ChannelActivationError::CardRemoved onto CredentialOutcome::CardRemoved;
// LM never produces it. On the wire each member crosses as its camelCase
// STRING token: unspecified|ok|userCancelled|missingFields|invalidPin|
// blocked|pluginError|unsupported|keyActivationFailed|cardRemoved.
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
};

// Wire-facing credential record. Field names ARE the wire keys: the D-Bus
// `a{sv}` keys are the snake_case spellings; the CDDL/socket keys are their
// camelCase transposition.
// Every enum-valued field crosses the wire as one of the camelCase STRING
// tokens listed on its comment; outcome tokens are listed on
// CredentialOutcome. This definition (together with the introspection-XML
// doc comments) is the authoritative wire doc the future CDDL / KDE /
// Swift mirrors derive from.
//
// LM's `initialized`/`blocked` flags are deliberately NOT represented:
// lifecycle crosses only via `state`, which is safe because LM keeps the
// invariant state==Blocked <=> blocked==true.
struct CredentialRecord
{
    std::string id; // agent-synthesized "<kind>:<reference>", stable per card session (see disambiguateCredentialIds)
    std::string label;
    std::string kind;  // "user"|"sign"|"puk"|"can"|"unknown"
    std::string state; // "unknown"|"transport"|"operational"|"needsChange"|"blocked"
    std::optional<int> retriesLeft, retriesMax, usesLeft, unblocksLeft;
    std::optional<int> minLength, maxLength; // CHECKED narrowing from LM's std::optional<std::size_t>
    bool canChange = false, unblockable = false;
    std::string unblockStyle; // "unknown"|"resetOnly"|"setsNewPin"|"unblockAndChange"
    bool activatable = false, keyActivationPending = false, keyActivatable = false;
    std::string recovery; // "unknown"|"holderViaPuk"|"issuerProcess"|"none"
    bool probeSafe = false;
    std::optional<std::string> blockedGuidanceKey, blockedGuidanceFallback;
    std::optional<std::string> keyActivationGuidanceKey, keyActivationGuidanceFallback;
    [[nodiscard]] bool operator==(const CredentialRecord&) const = default;
};

// Snapshot the list flow produces and mutation validation consumes.
struct CredentialSnapshot
{
    std::vector<CredentialRecord> records;
    std::uint64_t version = 0; // monotonic; bumped by the credential cache
    // Identity (CardPlugin::pluginId) of the candidate whose non-empty
    // getPINList produced this listing; empty for an empty listing. AGENT-
    // INTERNAL like `version` — never crosses the wire. The mutation flows
    // route to this plugin FIRST (prioritizeCandidate), so the plugin that
    // minted the id/label namespace answers a mutation addressed against it
    // and another candidate cannot intercept a mutation for a card it listed
    // nothing for.
    std::string listPluginId;
};

// Closed entry-validation error vocabulary: entry gating produces these and
// the D-Bus layer maps each member onto a named error. Extend only together
// with that mapping. AmbiguousCredential rejects a mutation whose addressed
// record's LABEL is not unique within the snapshot: ids were disambiguated
// for kind:reference collisions, but the seam addresses the card by label,
// so the plugin would have to guess which of two same-label PINs the user
// meant. Maps to the InvalidRequest wire error.
enum class EntryError { UnknownVerb, UnknownOption, UnknownCredential, InvalidCombination, AmbiguousCredential };

// Uniform result for every credential mutation verb; rides the Result
// channel of the operation that ran the mutation.
struct CredentialOpResult
{
    CredentialOutcome outcome = CredentialOutcome::Unspecified;
    std::optional<int> retriesLeft;
    bool blocked = false;
    std::optional<bool> pinActivated, keyActivated;
};

// The mappings below are exhaustive switches with NO default case, so that
// a newly appended LM enum member forces a decision here (the mirror
// guard). The pragma promotes -Wswitch to a hard error in EVERY including
// TU — the guard holds regardless of the including target's warning flags
// (this header is header-only; there is no -Werror lib TU to rely on).
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"

namespace detail {

// Wire tokens for the four LM credential enums (mirror guard: exhaustive,
// no default case — see the pragma above).
[[nodiscard]] inline std::string credentialKindToken(LibreSCRS::Plugin::PinKind kind)
{
    using LibreSCRS::Plugin::PinKind;
    switch (kind) {
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
    return "unknown";
}

[[nodiscard]] inline std::string credentialStateToken(LibreSCRS::Plugin::PinState state)
{
    using LibreSCRS::Plugin::PinState;
    switch (state) {
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
    return "unknown";
}

[[nodiscard]] inline std::string unblockStyleToken(LibreSCRS::Plugin::UnblockStyle style)
{
    using LibreSCRS::Plugin::UnblockStyle;
    switch (style) {
    case UnblockStyle::Unknown:
        return "unknown";
    case UnblockStyle::ResetOnly:
        return "resetOnly";
    case UnblockStyle::SetsNewPin:
        return "setsNewPin";
    case UnblockStyle::UnblockAndChange:
        return "unblockAndChange";
    }
    return "unknown";
}

[[nodiscard]] inline std::string recoveryToken(LibreSCRS::Plugin::PinRecovery recovery)
{
    using LibreSCRS::Plugin::PinRecovery;
    switch (recovery) {
    case PinRecovery::Unknown:
        return "unknown";
    case PinRecovery::HolderViaPuk:
        return "holderViaPuk";
    case PinRecovery::IssuerProcess:
        return "issuerProcess";
    case PinRecovery::None:
        return "none";
    }
    return "unknown";
}

// Named, checked narrowing of an LM length bound (std::size_t domain) onto
// the wire's int domain. A bound beyond int range is a plugin contract
// violation — fail loudly instead of silently truncating.
[[nodiscard]] inline std::optional<int> narrowLengthToInt(const std::optional<std::size_t>& length)
{
    if (!length)
        return std::nullopt;
    if (*length > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw std::overflow_error("PinStatusEntry length bound exceeds the wire's int range");
    return static_cast<int>(*length);
}

// Split optional guidance into wire key + fallback by copying
// .key/.defaultText directly. The wire record has no placeholder
// representation; guidance carrying placeholders would render with holes,
// so it is rejected loudly rather than silently truncated. Throws the SAME
// runtime-exception family as narrowLengthToInt (both are unrepresentable-
// plugin-data conditions) so a single catch(const std::runtime_error&) in the
// list flow catches either.
[[nodiscard]] inline std::pair<std::optional<std::string>, std::optional<std::string>>
splitGuidance(const std::optional<LocalizedText>& guidance, std::string_view fieldName)
{
    if (!guidance)
        return {std::nullopt, std::nullopt};
    if (!guidance->placeholders.empty())
        throw std::runtime_error(std::format(
            "credential guidance '{}' carries placeholders; the wire record cannot represent them", fieldName));
    return {guidance->key, guidance->defaultText};
}

} // namespace detail

// LM outcome -> agent outcome, name for name. Exhaustive switch, no
// default case — a new LM enum member breaks the build here (mirror
// guard #1) and forces the agent-side vocabulary decision.
[[nodiscard]] inline CredentialOutcome toCredentialOutcome(LibreSCRS::Plugin::PINResultOutcome o)
{
    using LibreSCRS::Plugin::PINResultOutcome;
    switch (o) {
    case PINResultOutcome::Unspecified:
        return CredentialOutcome::Unspecified;
    case PINResultOutcome::Ok:
        return CredentialOutcome::Ok;
    case PINResultOutcome::UserCancelled:
        return CredentialOutcome::UserCancelled;
    case PINResultOutcome::MissingFields:
        return CredentialOutcome::MissingFields;
    case PINResultOutcome::InvalidPin:
        return CredentialOutcome::InvalidPin;
    case PINResultOutcome::Blocked:
        return CredentialOutcome::Blocked;
    case PINResultOutcome::PluginError:
        return CredentialOutcome::PluginError;
    case PINResultOutcome::Unsupported:
        return CredentialOutcome::Unsupported;
    case PINResultOutcome::KeyActivationFailed:
        return CredentialOutcome::KeyActivationFailed;
    }
    return CredentialOutcome::Unspecified;
}

#pragma GCC diagnostic pop

// Build a record from LM's extended PinStatusEntry. Single-argument pure
// mapping; synthesizes the BARE id "<kind>:<reference>" with the reference
// in zero-padded lowercase hex (e.g. "sign:0x92").
// @throws a std::runtime_error subclass on unrepresentable plugin data:
//         std::overflow_error on a length bound beyond int range, and a
//         std::runtime_error on placeholder-bearing guidance (see detail).
//         Both share the runtime_error family, so one catch handles either.
[[nodiscard]] inline CredentialRecord toCredentialRecord(const LibreSCRS::Plugin::PinStatusEntry& e)
{
    CredentialRecord record;
    record.kind = detail::credentialKindToken(e.kind);
    record.id = std::format("{}:0x{:02x}", record.kind, e.reference);
    record.label = e.label;
    record.state = detail::credentialStateToken(e.state);
    record.retriesLeft = e.retriesLeft;
    record.retriesMax = e.retriesMax;
    record.usesLeft = e.usesLeft;
    record.unblocksLeft = e.unblocksLeft;
    record.minLength = detail::narrowLengthToInt(e.minLength);
    record.maxLength = detail::narrowLengthToInt(e.maxLength);
    record.canChange = e.canChange;
    record.unblockable = e.unblockable;
    record.unblockStyle = detail::unblockStyleToken(e.unblockStyle);
    record.activatable = e.activatable;
    record.keyActivationPending = e.keyActivationPending;
    record.keyActivatable = e.keyActivatable;
    record.recovery = detail::recoveryToken(e.recovery);
    record.probeSafe = e.probeSafe;
    auto [blockedKey, blockedFallback] = detail::splitGuidance(e.blockedGuidance, "blockedGuidance");
    record.blockedGuidanceKey = std::move(blockedKey);
    record.blockedGuidanceFallback = std::move(blockedFallback);
    auto [activationKey, activationFallback] = detail::splitGuidance(e.keyActivationGuidance, "keyActivationGuidance");
    record.keyActivationGuidanceKey = std::move(activationKey);
    record.keyActivationGuidanceFallback = std::move(activationFallback);
    return record;
}

// Id uniqueness rule (ids are unique within one card session): the bare id
// is "<kind>:<reference>". When two or more records on one card collide on
// kind+reference (e.g. kind=unknown, reference=0), EVERY member of the
// colliding group gets a deterministic ":<index>" suffix in zero-based
// list order ("unknown:0x00:0", "unknown:0x00:1"); non-colliding ids stay
// bare. Called by the list flow after mapping; the same input order always
// yields the same ids. A suffixed id can never collide with a bare one —
// a bare id contains exactly one ':'.
inline void disambiguateCredentialIds(std::vector<CredentialRecord>& records)
{
    std::unordered_map<std::string, std::size_t> population;
    for (const auto& record : records)
        ++population[record.id];
    std::unordered_map<std::string, std::size_t> nextIndex;
    for (auto& record : records) {
        if (population[record.id] < 2)
            continue;
        const std::size_t index = nextIndex[record.id]++;
        record.id += std::format(":{}", index);
    }
}

} // namespace LibreSCRS::Agent
