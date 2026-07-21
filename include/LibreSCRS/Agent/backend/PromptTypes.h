// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Secure/String.h>
#include <cstdint>
#include <optional>
#include <string>

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
};

enum class PromptStatus : std::uint8_t {
    Ok,
    Cancelled,
    Error,
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
