// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ErrorNameMap.h"

#include "AgentDBus.h"

#include <QLatin1StringView>

namespace LibreSCRS::AgentClient {

namespace {

SeamError make(CallError call, ErrorCode code, QStringView name, const QString& message)
{
    SeamError e;
    e.callError = call;
    e.errorCode = code;
    e.wireName = name.toString();
    e.message = message;
    return e;
}

} // namespace

SeamError mapAgentErrorShortName(QStringView shortName, const QString& message)
{
    // Wire-taxonomy refusals: the agent answered, and the answer fits the
    // frozen ErrorCode vocabulary the async operation path already uses —
    // give the caller ONE taxonomy for both.
    if (shortName == QLatin1StringView("UnknownCard")) {
        return make(CallError::None, ErrorCode::UnsupportedCard, shortName, message);
    }
    if (shortName == QLatin1StringView("KeyNotFound")) {
        return make(CallError::None, ErrorCode::KeyNotFound, shortName, message);
    }
    if (shortName == QLatin1StringView("AuthFailed")) {
        return make(CallError::None, ErrorCode::AuthFailed, shortName, message);
    }
    if (shortName == QLatin1StringView("RateLimited")) {
        return make(CallError::None, ErrorCode::RateLimited, shortName, message);
    }
    if (shortName == QLatin1StringView("UnsupportedOnThisCard") || shortName == QLatin1StringView("NotSupported")) {
        return make(CallError::None, ErrorCode::CapabilityMissing, shortName, message);
    }
    if (shortName == QLatin1StringView("InputTooLarge")) {
        return make(CallError::None, ErrorCode::InvalidDocument, shortName, message);
    }
    if (shortName == QLatin1StringView("CommunicationError")) {
        return make(CallError::None, ErrorCode::CommunicationError, shortName, message);
    }
    // GetSignResult's dedicated dead-end name: nothing retained for this op
    // (never completed as Sign, the recovery grace window elapsed, or -- an
    // IDOR-safe agent answers a not-mine op identically to an absent one, by
    // design -- the caller does not own it). This is the SAME generic bucket
    // the unknown-name catch-all below already produced for this exact name
    // before it was pinned (both FakeAgent's D-Bus double and the socket
    // wire's GetSignResult recovery pull have always been swallowed by that
    // catch-all in practice); giving it its own case makes that a deliberate,
    // documented classification instead of an accidental fallthrough. Every
    // caller of the GetResult recovery pull (DBusTransport::fetchOperationResult
    // / SocketTransport::fetchOperationResult) already discards the specific
    // SeamError on a non-reply and reports one fixed CommunicationError at the
    // AgentOperation layer regardless, so this decision does not change any
    // observable behaviour today -- it only stops relying on the catch-all.
    if (shortName == QLatin1StringView("NoResult")) {
        return make(CallError::None, ErrorCode::CommunicationError, shortName, message);
    }

    // Pre-operation rejections outside the taxonomy: the request itself was
    // unacceptable (fix the request / re-list and retry), or the caller was
    // not allowed to make it.
    if (shortName == QLatin1StringView("InvalidRequest") || shortName == QLatin1StringView("UnknownCredential") ||
        shortName == QLatin1StringView("UnsupportedSignatureParameter") ||
        shortName == QLatin1StringView("UnknownConfigKey") || shortName == QLatin1StringView("ReadOnlyConfig") ||
        shortName == QLatin1StringView("InvalidConfigValue")) {
        return make(CallError::InvalidArguments, ErrorCode::None, shortName, message);
    }
    if (shortName == QLatin1StringView("NotAuthorized") || shortName == QLatin1StringView("UserNotLoggedIn")) {
        return make(CallError::AccessDenied, ErrorCode::None, shortName, message);
    }
    if (shortName == QLatin1StringView("UnsupportedProtocol")) {
        return make(CallError::ProtocolError, ErrorCode::None, shortName, message);
    }

    // Unknown agent-namespace name (including "Internal" and any future
    // appended name): the agent answered but this client cannot classify it.
    // Degrade to the taxonomy catch-all rather than inventing a transport
    // failure that never happened.
    return make(CallError::None, ErrorCode::CommunicationError, shortName, message);
}

SeamError mapDBusErrorName(const QString& fullName, const QString& message)
{
    const QLatin1StringView agentPrefix{kAgentErrorPrefix};
    if (fullName.startsWith(agentPrefix)) {
        return mapAgentErrorShortName(QStringView{fullName}.mid(agentPrefix.size()), message);
    }

    const QLatin1StringView fdoPrefix{"org.freedesktop.DBus.Error."};
    if (fullName.startsWith(fdoPrefix)) {
        const QStringView tail = QStringView{fullName}.mid(fdoPrefix.size());
        if (tail == QLatin1StringView("ServiceUnknown") || tail == QLatin1StringView("NameHasNoOwner")) {
            return make(CallError::AgentUnavailable, ErrorCode::None, fullName, message);
        }
        if (tail == QLatin1StringView("NoReply") || tail == QLatin1StringView("Timeout") ||
            tail == QLatin1StringView("TimedOut")) {
            return make(CallError::Timeout, ErrorCode::None, fullName, message);
        }
        if (tail == QLatin1StringView("AccessDenied") || tail == QLatin1StringView("AuthFailed")) {
            return make(CallError::AccessDenied, ErrorCode::None, fullName, message);
        }
        if (tail == QLatin1StringView("InvalidArgs") || tail == QLatin1StringView("InvalidSignature") ||
            tail == QLatin1StringView("UnknownMethod") || tail == QLatin1StringView("UnknownInterface") ||
            tail == QLatin1StringView("UnknownObject") || tail == QLatin1StringView("UnknownProperty")) {
            return make(CallError::InvalidArguments, ErrorCode::None, fullName, message);
        }
        // Disconnected / NoMemory / IOError / LimitsExceeded / NoNetwork /
        // anything else in the bus-daemon namespace: the transport itself
        // failed underneath the call.
        return make(CallError::TransportFailure, ErrorCode::None, fullName, message);
    }

    // A reply from outside both contracts (a foreign error domain): the
    // exchange does not decode against the wire contract this client speaks.
    return make(CallError::ProtocolError, ErrorCode::None, fullName, message);
}

} // namespace LibreSCRS::AgentClient
