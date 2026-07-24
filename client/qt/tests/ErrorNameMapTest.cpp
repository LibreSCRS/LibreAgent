// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The D-Bus error-name -> CallError/ErrorCode mapping table (brief: "CallError
// mapping table"). Compiles src/dbus/ErrorNameMap.cpp directly (internal,
// hidden-visibility TU — same pattern as TokenMapTest) so the table is pinned
// without a bus.

#include "ErrorNameMap.h"

#include <gtest/gtest.h>

using namespace LibreSCRS::AgentClient;

namespace {

SeamError mapFull(const char* name)
{
    return mapDBusErrorName(QString::fromLatin1(name), QStringLiteral("msg"));
}

} // namespace

// ---- transport-level (freedesktop) family -> CallError buckets ---------------

TEST(ErrorNameMap, ServiceUnknownIsAgentUnavailable)
{
    const SeamError e = mapFull("org.freedesktop.DBus.Error.ServiceUnknown");
    EXPECT_EQ(e.callError, CallError::AgentUnavailable);
    EXPECT_EQ(e.errorCode, ErrorCode::None);
    const SeamError e2 = mapFull("org.freedesktop.DBus.Error.NameHasNoOwner");
    EXPECT_EQ(e2.callError, CallError::AgentUnavailable);
}

TEST(ErrorNameMap, NoReplyAndTimeoutAreTimeout)
{
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.NoReply").callError, CallError::Timeout);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.Timeout").callError, CallError::Timeout);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.TimedOut").callError, CallError::Timeout);
}

TEST(ErrorNameMap, AccessFamilyIsAccessDenied)
{
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.AccessDenied").callError, CallError::AccessDenied);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.AuthFailed").callError, CallError::AccessDenied);
}

TEST(ErrorNameMap, ArgumentFamilyIsInvalidArguments)
{
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.InvalidArgs").callError, CallError::InvalidArguments);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.UnknownMethod").callError, CallError::InvalidArguments);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.UnknownObject").callError, CallError::InvalidArguments);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.InvalidSignature").callError, CallError::InvalidArguments);
}

TEST(ErrorNameMap, OtherBusDaemonErrorsAreTransportFailure)
{
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.Disconnected").callError, CallError::TransportFailure);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.NoMemory").callError, CallError::TransportFailure);
    EXPECT_EQ(mapFull("org.freedesktop.DBus.Error.LimitsExceeded").callError, CallError::TransportFailure);
}

TEST(ErrorNameMap, ForeignErrorDomainIsProtocolError)
{
    const SeamError e = mapFull("com.example.SomeService.Error.Whatever");
    EXPECT_EQ(e.callError, CallError::ProtocolError);
    EXPECT_EQ(e.errorCode, ErrorCode::None);
}

// ---- agent namespace: taxonomy refusals -> ErrorCode, callError stays None ----

TEST(ErrorNameMap, AgentTaxonomyRefusalsMapToErrorCode)
{
    struct Row
    {
        const char* name;
        ErrorCode expected;
    };
    const Row rows[] = {
        {"org.librescrs.Agent.Error.UnknownCard", ErrorCode::UnsupportedCard},
        {"org.librescrs.Agent.Error.KeyNotFound", ErrorCode::KeyNotFound},
        {"org.librescrs.Agent.Error.AuthFailed", ErrorCode::AuthFailed},
        {"org.librescrs.Agent.Error.RateLimited", ErrorCode::RateLimited},
        {"org.librescrs.Agent.Error.UnsupportedOnThisCard", ErrorCode::CapabilityMissing},
        {"org.librescrs.Agent.Error.NotSupported", ErrorCode::CapabilityMissing},
        {"org.librescrs.Agent.Error.InputTooLarge", ErrorCode::InvalidDocument},
        {"org.librescrs.Agent.Error.CommunicationError", ErrorCode::CommunicationError},
    };
    for (const Row& row : rows) {
        const SeamError e = mapFull(row.name);
        EXPECT_EQ(e.errorCode, row.expected) << row.name;
        EXPECT_EQ(e.callError, CallError::None) << row.name;
        EXPECT_EQ(e.message, QStringLiteral("msg"));
    }
}

TEST(ErrorNameMap, AgentEntryRejectionsMapToCallError)
{
    struct Row
    {
        const char* name;
        CallError expected;
    };
    const Row rows[] = {
        {"org.librescrs.Agent.Error.InvalidRequest", CallError::InvalidArguments},
        {"org.librescrs.Agent.Error.UnknownCredential", CallError::InvalidArguments},
        {"org.librescrs.Agent.Error.UnsupportedSignatureParameter", CallError::InvalidArguments},
        {"org.librescrs.Agent.Error.NotAuthorized", CallError::AccessDenied},
        {"org.librescrs.Agent.Error.UserNotLoggedIn", CallError::AccessDenied},
        {"org.librescrs.Agent.Error.UnsupportedProtocol", CallError::ProtocolError},
    };
    for (const Row& row : rows) {
        const SeamError e = mapFull(row.name);
        EXPECT_EQ(e.callError, row.expected) << row.name;
        EXPECT_EQ(e.errorCode, ErrorCode::None) << row.name;
    }
}

TEST(ErrorNameMap, UnknownAgentNameDegradesToCommunicationError)
{
    // "Internal" and any future appended agent error name: the agent answered,
    // so degrade to the taxonomy catch-all — never a fake transport failure.
    const SeamError internalErr = mapFull("org.librescrs.Agent.Error.Internal");
    EXPECT_EQ(internalErr.callError, CallError::None);
    EXPECT_EQ(internalErr.errorCode, ErrorCode::CommunicationError);
    const SeamError future = mapFull("org.librescrs.Agent.Error.SomethingFromTheFuture");
    EXPECT_EQ(future.callError, CallError::None);
    EXPECT_EQ(future.errorCode, ErrorCode::CommunicationError);
}

TEST(ErrorNameMap, ShortNameTableMatchesFullNameTable)
{
    // The socket wire carries the SHORT spellings; both entry points must
    // agree so a later transport reuses the same table.
    const SeamError viaShort = mapAgentErrorShortName(u"UnsupportedOnThisCard", QStringLiteral("m"));
    const SeamError viaFull =
        mapDBusErrorName(QStringLiteral("org.librescrs.Agent.Error.UnsupportedOnThisCard"), QStringLiteral("m"));
    EXPECT_EQ(viaShort.callError, viaFull.callError);
    EXPECT_EQ(viaShort.errorCode, viaFull.errorCode);
}

TEST(ErrorNameMap, WireNameAndMessageAreCarriedForDiagnostics)
{
    const SeamError e =
        mapDBusErrorName(QStringLiteral("org.librescrs.Agent.Error.RateLimited"), QStringLiteral("retry shortly"));
    EXPECT_EQ(e.wireName, QStringLiteral("RateLimited"));
    EXPECT_EQ(e.message, QStringLiteral("retry shortly"));
    EXPECT_TRUE(e.isError());

    const SeamError none;
    EXPECT_FALSE(none.isError());
}
