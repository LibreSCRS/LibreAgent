// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/ReaderLabels.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Secure/String.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

// Caller-supplied prompt metadata, mapped onto the {sv} "options" dictionary
// of the org.librescrs.Prompter1.RequestSecret method. Empty / zero fields
// are simply omitted from the wire dictionary.
struct PromptOptions
{
    std::string title;       // prompt heading
    std::string description; // explanatory text
    std::string requester;   // human-readable client id
    std::string artifact;    // file name / hash being acted on
    // Display-only labels of the multi-secret change-PIN modal (the wire's
    // card_label / pin_label RequestSecrets option keys): the card/token the
    // change applies to and the human-readable name of the PIN role being
    // changed. Ignored by the single-secret kinds; leave title empty for the
    // change modal so the prompter renders its own localized action title.
    std::string cardLabel;
    std::string pinLabel;
    std::uint32_t minLength = 0;
    std::uint32_t maxLength = 0;
    // Client-supplied display names of every document a batch sign covers
    // (BatchSignFlow's consent prompt). UNTRUSTED, unlike `artifact` above,
    // which stays the agent-owned trusted category token for the whole
    // request ("signature-batch" for a batch) -- this list is rendered in
    // the prompter's description zone alongside it, never used as the
    // trusted label itself. Empty for every single-secret prompt that is not
    // a batch sign. The prompter-facing wire plumbing for this list (the
    // RequestSecret option carrying it) is added alongside the consent
    // surface that renders it; this field is the dependency seam a flow
    // populates today.
    std::vector<std::string> artifacts;
    // Retry context for a CAN/MRZ prompt re-issued after the card rejected
    // the value collected last time for the SAME card: `attempt` numbers
    // this prompt (2 = second attempt, ...) and `lastError` carries the
    // msgKey of the failure that triggered the retry (e.g.
    // LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key). Both stay at
    // their default (0 / empty) on the first-ever prompt for a card --
    // CredentialCache::requestCredential populates them only on a genuine
    // re-prompt (see CredentialCache::markCredentialWrong). PIN prompts
    // never set these; the pre-read PACE secret is the only surface this
    // seam covers today.
    std::uint32_t attempt = 0;
    std::string lastError;
    // Alternative secret kinds the caller can consume if the user switches
    // in-dialog (Prompter1 option "alt_kinds"). Empty for every caller that
    // does not opt in; the only value the stack emits today is {"mrz"} on a
    // kind-"can" request. Backends that predate the option ignore it.
    std::vector<std::string> altKinds;
    // Identifies THIS prompt end to end, so a cancel can name which window it
    // means. Opaque; minted by PromptIdMinter and never parsed by a prompter.
    // Empty on any path that has not been stamped.
    std::string promptId;
    // The reader that raised this prompt. EMBEDDED rather than flattened into
    // three parallel members: the model, the interface qualifier and the raw
    // name are one fact, and splitting them would let a caller set the model
    // while leaving the qualifier unset -- on a dual-interface unit that is
    // exactly the ambiguity the qualifier exists to remove. The wire carries
    // three flat keys; flattening is the hosts' marshalling concern.
    LibreSCRS::Agent::ReaderIdentity reader;
    // How long the holder gets, from the moment the window is shown. A
    // DURATION, not an absolute time, so the two processes need no shared
    // clock. 0 means "no deadline set" -- a prompter must not read that as an
    // instant expiry.
    std::uint32_t deadlineMs = 0;
    // How long the holder gets if they take the switch this prompt offered, as
    // the same kind of DURATION from the moment the window is shown -- NOT an
    // increment on deadlineMs. 0 whenever no alternative was offered, or none
    // of the offered ones has a budget, which is every prompt but a CAN that
    // opted into the MRZ form.
    std::uint32_t altDeadlineMs = 0;
};

enum class PromptStatus : std::uint8_t {
    Ok,
    Cancelled,
    Error,
    // The prompter closed the window because the holder's entry time ran out.
    // Distinct from Cancelled deliberately: telling someone they cancelled what
    // the clock took from them is the confusion this design removes. APPENDED,
    // never inserted -- the values above are compiled into every consumer.
    Timeout,
    // The prompter is present and serving, but too old to be told WHICH window
    // to dismiss -- so the agent refuses to raise one it could not close. A
    // missing capability, not a fault: reporting it as a prompter failure would
    // describe a helper that broke, when it is running fine and merely predates
    // the addressed cancel. APPENDED, never inserted.
    HelperTooOld,
};

struct PromptResult
{
    PromptStatus status = PromptStatus::Error;
    // Present iff status == Ok. The Secure::String is empty-but-present for
    // the (legitimate) case of a zero-length confirmed entry.
    std::optional<LibreSCRS::Secure::String> secret;
    // Localised explanation supplied by the prompter (empty on Ok), or a
    // diagnostic supplied by this client when D-Bus / memfd I/O fails.
    std::string userMessage;
    // Engaged iff the prompter honoured an alt_kinds switch: the secret
    // above is of THIS kind, not the requested one (e.g. an MRZ payload on
    // a CAN request). Disengaged on every legacy/ordinary reply. The explicit
    // default keeps every pre-existing positional brace-init of this aggregate
    // (which lists the three members above it) free of
    // -Wmissing-field-initializers, so appending here stays source-compatible.
    std::optional<LibreSCRS::Auth::PaceSecretKind> chosenKind = std::nullopt;
};

// Result of a two-secret PIN-change prompt: the current and the new PIN are
// captured in ONE modal; the confirm re-entry never leaves the prompter.
// Mirrors PromptResult: both secrets are present iff status == Ok, as
// independently-cleansed Secure::Strings — the transport never crosses into
// the core (never an fd/memfd).
struct PinChangePromptResult
{
    PromptStatus status = PromptStatus::Error;
    // Present iff status == Ok.
    std::optional<LibreSCRS::Secure::String> current;
    std::optional<LibreSCRS::Secure::String> newPin;
    // Localised explanation supplied by the prompter (empty on Ok), or a
    // diagnostic supplied by this client when transport I/O fails.
    std::string userMessage;
};

} // namespace LibreSCRS::Agent
