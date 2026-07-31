// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Both halves of the sync-error name conversion, in one translation unit so
// the enum -> name switch and the name -> enum walk over the SAME closed set
// are readable side by side. They used to sit in two unrelated TUs (the
// server-role message model and the client-role codec), which is how the
// inverse half came to be an internal detail of one of them while the forward
// half was public.
#include <LibreSCRS/Agent/wire/SyncError.h>

namespace LibreSCRS::Agent::Wire {

std::string_view syncErrorName(SyncError e) noexcept
{
    switch (e) {
    case SyncError::UnknownCard:
        return "UnknownCard";
    case SyncError::KeyNotFound:
        return "KeyNotFound";
    case SyncError::NotAuthorized:
        return "NotAuthorized";
    case SyncError::UserNotLoggedIn:
        return "UserNotLoggedIn";
    case SyncError::UnknownConfigKey:
        return "UnknownConfigKey";
    case SyncError::ReadOnlyConfig:
        return "ReadOnlyConfig";
    case SyncError::InvalidConfigValue:
        return "InvalidConfigValue";
    case SyncError::UnsupportedProtocol:
        return "UnsupportedProtocol";
    case SyncError::AuthFailed:
        return "AuthFailed";
    case SyncError::CommunicationError:
        return "CommunicationError";
    case SyncError::NotSupported:
        return "NotSupported";
    case SyncError::UnsupportedOnThisCard:
        return "UnsupportedOnThisCard";
    case SyncError::UnsupportedSignatureParameter:
        return "UnsupportedSignatureParameter";
    case SyncError::InputTooLarge:
        return "InputTooLarge";
    case SyncError::RateLimited:
        return "RateLimited";
    case SyncError::UnknownCredential:
        return "UnknownCredential";
    case SyncError::InvalidRequest:
        return "InvalidRequest";
    case SyncError::NoResult:
        return "NoResult";
    }
    return "UnknownCard"; // unreachable (all enumerators handled)
}

SyncError decodeSyncError(std::string_view name) noexcept
{
    // Every enumerator, in declaration order. This list is the ONE piece of
    // this vocabulary with no compile-time append protection of its own --
    // syncErrorName() above is an exhaustive switch, so an appended member is
    // a -Wswitch error there, but a member missing HERE only shows up as a
    // token that silently degrades. tests/wire/WireContractGuardTest.cpp walks
    // every enumerator and asserts the round trip through both halves, which
    // is what turns that into a test failure.
    static constexpr SyncError kAll[] = {
        SyncError::UnknownCard,
        SyncError::KeyNotFound,
        SyncError::NotAuthorized,
        SyncError::UserNotLoggedIn,
        SyncError::UnknownConfigKey,
        SyncError::ReadOnlyConfig,
        SyncError::InvalidConfigValue,
        SyncError::UnsupportedProtocol,
        SyncError::AuthFailed,
        SyncError::CommunicationError,
        SyncError::NotSupported,
        SyncError::UnsupportedOnThisCard,
        SyncError::UnsupportedSignatureParameter,
        SyncError::InputTooLarge,
        SyncError::RateLimited,
        SyncError::UnknownCredential,
        SyncError::InvalidRequest,
        SyncError::NoResult,
    };
    for (const auto e : kAll) {
        if (syncErrorName(e) == name) {
            return e;
        }
    }
    // Unrecognised token -> generic protocol error. See the header's @warning:
    // the original token is not retained, and this is indistinguishable from
    // the peer genuinely naming CommunicationError.
    return SyncError::CommunicationError;
}

} // namespace LibreSCRS::Agent::Wire
