// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>

namespace LibreSCRS::Agent {

ErrorCode errorCodeFor(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept
{
    using LibreSCRS::SecureChannel::ChannelActivationError;
    switch (err) {
    case ChannelActivationError::None:
        return ErrorCode::None;
    case ChannelActivationError::SelectAppletFailed:
        return ErrorCode::UnsupportedCard;
    case ChannelActivationError::PaceWrongSecret:
        return ErrorCode::CredentialWrong;
    case ChannelActivationError::PacePinBlocked:
        return ErrorCode::CredentialBlocked;
    case ChannelActivationError::PaceProtocolFailure:
        return ErrorCode::AuthFailed;
    case ChannelActivationError::PaceUnsupported:
        return ErrorCode::UnsupportedCard;
    case ChannelActivationError::UserCancelled:
        return ErrorCode::None;
    case ChannelActivationError::Cancelled:
        return ErrorCode::None;
    case ChannelActivationError::CardRemoved:
        return ErrorCode::CardRemoved;
    case ChannelActivationError::ReaderError:
        return ErrorCode::CommunicationError;
    case ChannelActivationError::CredentialsRequired:
        return ErrorCode::AuthFailed;
    case ChannelActivationError::Internal:
        return ErrorCode::CommunicationError;
    case ChannelActivationError::ReentrantAccess:
        return ErrorCode::CommunicationError;
    }
    return ErrorCode::CommunicationError;
}

ErrorCode errorCodeFor(LibreSCRS::Plugin::ReadResult::Status status) noexcept
{
    using Status = LibreSCRS::Plugin::ReadResult::Status;
    switch (status) {
    case Status::Ok:
        return ErrorCode::None;
    case Status::CommunicationError:
        return ErrorCode::CommunicationError;
    case Status::ParseError:
        return ErrorCode::ParseError;
    case Status::UnsupportedCard:
        return ErrorCode::UnsupportedCard;
    case Status::AuthenticationFailed:
        return ErrorCode::AuthFailed;
    case Status::Cancelled:
        return ErrorCode::None;
    }
    return ErrorCode::CommunicationError;
}

} // namespace LibreSCRS::Agent
