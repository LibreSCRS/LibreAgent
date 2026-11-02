// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>    // CryptoOutcome, LoginOutcome
#include <LibreSCRS/Agent/value/CredentialRecord.h> // EntryError
#include <LibreSCRS/Agent/wire/SyncError.h>         // SyncError: std-only, no link needed for the enum

/// @file
/// @brief Which named synchronous error a refusal the core produced goes out
///        as, on either wire.
///
/// The core decides a request's outcome; each host only carries it. When the
/// mapping lived in the hosts, each kept its own table, the tables were equal
/// only because nobody had yet changed one, and no test compared them. One
/// table here means a host spells the result with `syncErrorName()` and cannot
/// disagree with the other host about what a refusal means.

namespace LibreSCRS::Agent {

/// A raw crypto operation's outcome as the wire error the caller receives.
/// `Ok` is not an error; it fails closed to `CommunicationError`.
[[nodiscard]] Wire::SyncError toSyncError(Pkcs11Broker::CryptoOutcome outcome) noexcept;

/// A token login's outcome as the wire error the caller receives.
/// `Ok` is not an error; it fails closed to `CommunicationError`.
[[nodiscard]] Wire::SyncError toSyncError(Pkcs11Broker::LoginOutcome outcome) noexcept;

/// A refused credential-management request as the wire error the caller
/// receives. `UnknownCredential` keeps its own name, because the remedy differs
/// -- list again and retry, rather than fix the request -- and every other
/// refusal is the caller's malformed request.
[[nodiscard]] Wire::SyncError toSyncError(EntryError error) noexcept;

} // namespace LibreSCRS::Agent
