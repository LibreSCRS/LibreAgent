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

} // namespace LibreSCRS::Agent
