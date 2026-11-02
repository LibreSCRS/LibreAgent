// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/FailureCopy.h>

#include <algorithm>

namespace LibreSCRS::AgentClient {

FailureCopy describeFailure(ErrorCode code, CallError call, const QString& messageKey, const QString& messageFallback)
{
    // A whitespace-only message is no message: non-empty to QString, blank to
    // a reader. Normalised once so no rule hands a user an empty line.
    const QString message = messageFallback.trimmed().isEmpty() ? QString() : messageFallback;
    FailureCopy copy;

    if (std::ranges::any_of(kLocalizedMessageKeys, [&](QLatin1StringView key) { return messageKey == key; })) {
        copy.source = FailureSource::MessageKey;
        copy.messageKey = messageKey;
        return copy;
    }
    if (code != ErrorCode::None) {
        copy.source = FailureSource::ErrorCode;
        copy.errorCode = code;
        copy.detail = message;
        return copy;
    }
    const bool answered =
        call == CallError::InvalidArguments || call == CallError::AccessDenied || call == CallError::ProtocolError;
    if (answered && !message.isEmpty()) {
        copy.source = FailureSource::AgentMessage;
        copy.detail = message;
        return copy;
    }
    if (call != CallError::None) {
        copy.source = FailureSource::Transport;
        copy.callError = call;
        return copy;
    }
    if (!message.isEmpty()) {
        copy.source = FailureSource::AgentMessage;
        copy.detail = message;
        return copy;
    }
    return copy;
}

} // namespace LibreSCRS::AgentClient
