// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/CallError.h>
#include <LibreSCRS/AgentClient/ErrorCode.h>
#include <LibreSCRS/AgentClient/Export.h>

#include <QLatin1StringView>
#include <QString>

#include <array>
#include <cstdint>

/// @file
/// @brief Which part of a failed operation's report a user should read.
///
/// A failure arrives as four facts (`AgentOperation::errorCode()`,
/// `callError()`, `messageKey()`, `messageFallback()`), and deciding which of
/// them to put in front of the user is the same decision in every client. It
/// is made here, once; a client keeps only its catalog, the sentences in its
/// own language for each key, code and call class.

namespace LibreSCRS::AgentClient {

/// @brief The agent's message keys a client gives a sentence of its own.
///
/// Each names a failure more precisely than its code does, or one that carries
/// no code at all (`op.cancelled`). A client's catalog has an entry for every
/// key here; `describeFailure()` returns `FailureSource::MessageKey` for no
/// other.
inline constexpr std::array<QLatin1StringView, 5> kLocalizedMessageKeys{
    QLatin1StringView("op.cancelled"),        QLatin1StringView("op.card_removed"),
    QLatin1StringView("op.entry_expired"),    QLatin1StringView("op.helper_too_old"),
    QLatin1StringView("op.watchdog_timeout"),
};

/// @brief What to show for a failure; see `describeFailure()`.
enum class FailureSource : std::uint8_t {
    MessageKey,   ///< The client's sentence for `FailureCopy::messageKey`, alone.
    ErrorCode,    ///< The client's sentence for `FailureCopy::errorCode` as the headline, `detail` below it.
    AgentMessage, ///< `FailureCopy::detail`, the agent's own words: nothing more specific is known.
    Transport,    ///< The client's sentence for `FailureCopy::callError`: the request never reached the agent.
    Generic,      ///< The client's sentence for "something failed": nothing usable was reported.
};

/// @brief The decision `describeFailure()` returns.
struct FailureCopy
{
    FailureSource source = FailureSource::Generic;
    QString messageKey;                    ///< Set for `MessageKey`.
    ErrorCode errorCode = ErrorCode::None; ///< Set for `ErrorCode`.
    CallError callError = CallError::None; ///< Set for `Transport`.
    /// The agent's prose. For `ErrorCode` a detail line, empty when the agent
    /// said nothing (it is in English: it names WHICH failure a coarse code
    /// covers, and is often the only record of that); for `AgentMessage` the
    /// text itself. Never whitespace only.
    QString detail;
};

/// @brief Decide what a user reads for a failure. First match wins:
///
///   1. a key in `kLocalizedMessageKeys` -- the most specific report, in the
///      user's language;
///   2. an error code the agent named -- the client's sentence for it as the
///      headline, the agent's message (if any) as the detail;
///   3. a refusal the agent answered (`InvalidArguments`, `AccessDenied`,
///      `ProtocolError`) that carries a message -- the agent's prose is the
///      only precise record of why;
///   4. any other call failure -- the request never reached the agent, and
///      its raw text is written for a developer;
///   5. a message with nothing else to go on -- untranslated, but about the
///      actual failure;
///   6. nothing usable.
///
/// A code this build does not know is treated like a known one: the client's
/// catalog falls back to its generic sentence for it, and the agent's detail
/// still says what happened.
[[nodiscard]] LIBRESCRS_AGENTCLIENT_EXPORT FailureCopy describeFailure(ErrorCode code, CallError call,
                                                                       const QString& messageKey,
                                                                       const QString& messageFallback);

} // namespace LibreSCRS::AgentClient
