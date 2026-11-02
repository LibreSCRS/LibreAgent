// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Which part of a failure's report a user reads: one table, every client.

#include <LibreSCRS/AgentClient/FailureCopy.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

namespace {

struct Case
{
    const char* name;
    ErrorCode code;
    CallError call;
    const char* key;
    const char* fallback;
    FailureSource source;
    const char* detail;
};

TEST(FailureCopy, ResolutionOrder)
{
    const Case cases[] = {
        // A cancellation carries no code: without its key the agent's English
        // line was what a user read.
        {"cancelled", ErrorCode::None, CallError::None, "op.cancelled", "Operation cancelled",
         FailureSource::MessageKey, ""},
        {"helper too old", ErrorCode::PrompterError, CallError::None, "op.helper_too_old",
         "The prompt helper is too old", FailureSource::MessageKey, ""},
        {"entry expired beats its code", ErrorCode::EntryExpired, CallError::None, "op.entry_expired", "Time ran out",
         FailureSource::MessageKey, ""},
        // A key no client has a sentence for falls through to the code.
        {"unlisted key", ErrorCode::CommunicationError, CallError::None, "op.read_failed", "reader said 6F00",
         FailureSource::ErrorCode, "reader said 6F00"},
        // One code, many engine complaints: the agent's words ride as detail.
        {"signing engine", ErrorCode::SigningEngineError, CallError::None, "op.sign_failed", "PAdES: xref broken",
         FailureSource::ErrorCode, "PAdES: xref broken"},
        {"code without message", ErrorCode::CredentialWrong, CallError::None, "", "", FailureSource::ErrorCode, ""},
        {"blank message is none", ErrorCode::CardRemoved, CallError::None, "", "   ", FailureSource::ErrorCode, ""},
        {"answered refusal", ErrorCode::None, CallError::AccessDenied, "", "caller not permitted",
         FailureSource::AgentMessage, "caller not permitted"},
        {"answered refusal without words", ErrorCode::None, CallError::InvalidArguments, "", "",
         FailureSource::Transport, ""},
        {"transport", ErrorCode::None, CallError::Timeout, "", "org.freedesktop.DBus.Error.NoReply",
         FailureSource::Transport, ""},
        {"only a message", ErrorCode::None, CallError::None, "", "something specific", FailureSource::AgentMessage,
         "something specific"},
        {"nothing", ErrorCode::None, CallError::None, "", "", FailureSource::Generic, ""},
        {"unknown code", static_cast<ErrorCode>(200), CallError::None, "", "new failure", FailureSource::ErrorCode,
         "new failure"},
    };
    for (const Case& c : cases) {
        const FailureCopy copy =
            describeFailure(c.code, c.call, QString::fromLatin1(c.key), QString::fromLatin1(c.fallback));
        EXPECT_EQ(copy.source, c.source) << c.name;
        EXPECT_EQ(copy.detail, QString::fromLatin1(c.detail)) << c.name;
        if (c.source == FailureSource::MessageKey) {
            EXPECT_EQ(copy.messageKey, QString::fromLatin1(c.key)) << c.name;
        }
        if (c.source == FailureSource::ErrorCode) {
            EXPECT_EQ(copy.errorCode, c.code) << c.name;
        }
        if (c.source == FailureSource::Transport) {
            EXPECT_EQ(copy.callError, c.call) << c.name;
        }
    }
}

} // namespace
