// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ErrorNameMap.h"

#include "AgentDBus.h"

#include <LibreSCRS/Agent/wire/SyncError.h>

#include <QByteArray>
#include <QLatin1StringView>

#include <string_view>

namespace LibreSCRS::AgentClient {

namespace Wire = LibreSCRS::Agent::Wire;

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

/// The short name as its `sync-error` enumerator. Called only from
/// mapAgentErrorShortName, i.e. only where the name is already known to be in
/// the AGENT namespace: the same spelling under org.freedesktop.DBus.Error.*
/// means something entirely different (that namespace's AuthFailed is a bus
/// authentication failure, not the card's), which is exactly why this is
/// derived here rather than from SeamError::wireName downstream.
///
/// The decoder is the wire library's own — the repo that owns the vocabulary —
/// rather than a client-side name table, which would be a second hand-kept
/// mirror of a closed enum this codebase already single-sources. It never
/// fails: an unrecognised name degrades to CommunicationError, matching what
/// the socket wire already did to the same token at decode time, so both
/// transports converge (see decodeSyncError's own warning).
[[nodiscard]] Wire::SyncError decodeAgentShortName(QStringView shortName)
{
    // The vocabulary is ASCII by construction (a D-Bus error-name element and a
    // CDDL text literal), so Latin-1 is a faithful narrowing here; a name
    // carrying anything else simply will not match a token and degrades.
    const QByteArray narrowed = shortName.toLatin1();
    return Wire::decodeSyncError(std::string_view{narrowed.constData(), static_cast<std::size_t>(narrowed.size())});
}

/// The CallError/ErrorCode half of the agent-namespace classification —
/// unchanged by the named-error axis, and kept a separate function precisely so
/// that stays true: mapAgentErrorShortName stamps the name onto whatever this
/// returns, in ONE place, so no arm of the table below can forget it and no
/// arm's existing decision can be quietly adjusted while adding it.
SeamError classifyAgentErrorShortName(QStringView shortName, const QString& message)
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
    // MasterListReplayed sits in this bucket rather than a taxonomy one for
    // the same reason InvalidRequest does: the INPUT was unacceptable and the
    // fix is a different input (a newer list), not a retry of this one. The
    // bucket cannot say which of the six it was -- which is precisely why the
    // sync-error axis carries the name alongside it.
    if (shortName == QLatin1StringView("InvalidRequest") || shortName == QLatin1StringView("UnknownCredential") ||
        shortName == QLatin1StringView("UnsupportedSignatureParameter") ||
        shortName == QLatin1StringView("UnknownConfigKey") || shortName == QLatin1StringView("ReadOnlyConfig") ||
        shortName == QLatin1StringView("InvalidConfigValue") || shortName == QLatin1StringView("MasterListReplayed")) {
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

} // namespace

SeamError mapAgentErrorShortName(QStringView shortName, const QString& message)
{
    SeamError e = classifyAgentErrorShortName(shortName, message);
    // The name itself, as an enumerator, alongside the classification rather
    // than instead of it. Engaged for EVERY name in this namespace — including
    // one this build does not recognise, which degrades exactly as the socket
    // wire's own decode does. What stays disengaged is everything that never
    // reaches this function: the bus-daemon namespace, a foreign error domain,
    // and a local refusal that borrowed no wire vocabulary.
    e.syncError = decodeAgentShortName(shortName);
    return e;
}

SeamError localExchangeFailure(const QString& message)
{
    // Deliberately NOT mapAgentErrorShortName("CommunicationError", ...), which
    // is what these sites used to call: that spelling produced the right two
    // axes but now also stamps the named-error axis, claiming the peer said
    // something it never said. Reproduce the same two axes — and the same
    // diagnostic wireName, so logs are byte-identical to before — while leaving
    // syncError disengaged.
    return make(CallError::None, ErrorCode::CommunicationError, QStringLiteral("CommunicationError"), message);
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
