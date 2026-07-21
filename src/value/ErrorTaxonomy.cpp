// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>

#include <LibreSCRS/Agent/value/CredentialRecord.h> // full CredentialOutcome definition

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

CredentialFinish errorCodeFor(CredentialOutcome outcome) noexcept
{
    using Status = Operations::OperationStatus;
    // Exhaustive over CredentialOutcome with NO default case: a member appended
    // to the enum trips -Wswitch here, which is -Werror in the CI library build —
    // this TU is the mapping guard, so the wire contract cannot drift silently.
    switch (outcome) {
    case CredentialOutcome::Ok:
        return {Status::Ok, ErrorCode::None};
    case CredentialOutcome::UserCancelled:
        // Cancellation is a finish STATUS, never an ErrorCode (same as the
        // channel/read mappers, which return ErrorCode::None for a user cancel).
        return {Status::Cancelled, ErrorCode::None};
    case CredentialOutcome::Unspecified:
        return {Status::Error, ErrorCode::CommunicationError};
    case CredentialOutcome::MissingFields:
        // Provider returned Ok but required fields were absent; on the agent path
        // the credential provider is the prompter.
        return {Status::Error, ErrorCode::PrompterError};
    case CredentialOutcome::InvalidPin:
        // retriesLeft rides the Result payload, not this code.
        return {Status::Error, ErrorCode::CredentialWrong};
    case CredentialOutcome::Blocked:
        // blocked=true rides the Result payload, not this code.
        return {Status::Error, ErrorCode::CredentialBlocked};
    case CredentialOutcome::PluginError:
        return {Status::Error, ErrorCode::CommunicationError};
    case CredentialOutcome::Unsupported:
        // The card resolves to a plugin that advertises nothing for this request,
        // not "no plugin resolves this card at all" (that is UnsupportedCard).
        return {Status::Error, ErrorCode::CapabilityMissing};
    case CredentialOutcome::KeyActivationFailed:
        // Verify succeeded, the card-side ACTIVATE step failed: a card-side
        // operation failure, the coarse class this taxonomy maps to
        // CommunicationError. The verify-vs-activate distinction (and the
        // standalone key-activation recovery it enables) crosses in the Result
        // payload, NOT in this numeric code — mapping to a credential/auth code
        // would wrongly invite a client to re-prompt the already-correct PIN.
        return {Status::Error, ErrorCode::CommunicationError};
    case CredentialOutcome::CardRemoved:
        return {Status::Error, ErrorCode::CardRemoved};
    }
    return {Status::Error, ErrorCode::CommunicationError};
}

} // namespace LibreSCRS::Agent
