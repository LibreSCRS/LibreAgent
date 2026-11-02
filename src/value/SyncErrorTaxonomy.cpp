// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/SyncErrorTaxonomy.h>

namespace LibreSCRS::Agent {

using Wire::SyncError;

// Every switch below is exhaustive with no default, so an outcome appended to
// one of the enums is a -Wswitch diagnostic here instead of a silent fall to
// the generic error.

SyncError toSyncError(Pkcs11Broker::CryptoOutcome outcome) noexcept
{
    using CO = Pkcs11Broker::CryptoOutcome;
    switch (outcome) {
    case CO::Cancelled:
        // The one a person produces on purpose. As a device error, dismissing
        // the PIN prompt would look like a broken reader to the loader.
        return SyncError::Cancelled;
    case CO::KeyNotFound:
        return SyncError::KeyNotFound;
    case CO::AuthFailed:
        return SyncError::AuthFailed;
    case CO::NotSupported:
        return SyncError::NotSupported;
    case CO::UnknownCard:
        return SyncError::UnknownCard;
    case CO::UserNotLoggedIn:
        return SyncError::UserNotLoggedIn;
    case CO::RateLimited:
        return SyncError::RateLimited;
    case CO::InvalidInput:
        // Refused before any prompt: the request does not fit the key.
        return SyncError::InvalidRequest;
    case CO::Ok:
    case CO::CardError:
        break;
    }
    return SyncError::CommunicationError;
}

SyncError toSyncError(Pkcs11Broker::LoginOutcome outcome) noexcept
{
    using LO = Pkcs11Broker::LoginOutcome;
    switch (outcome) {
    case LO::Cancelled:
        return SyncError::Cancelled;
    case LO::NotAuthorizedByCard:
        return SyncError::AuthFailed;
    case LO::UnknownCard:
        return SyncError::UnknownCard;
    case LO::NotAuthorized:
        return SyncError::NotAuthorized;
    case LO::Ok:
    case LO::CardError:
        break;
    }
    return SyncError::CommunicationError;
}

SyncError toSyncError(EntryError error) noexcept
{
    switch (error) {
    case EntryError::UnknownCredential:
        return SyncError::UnknownCredential;
    case EntryError::UnknownVerb:
    case EntryError::UnknownOption:
    case EntryError::InvalidCombination:
    case EntryError::AmbiguousCredential: // a non-unique label: the plugin must never guess
        break;
    }
    return SyncError::InvalidRequest;
}

} // namespace LibreSCRS::Agent
