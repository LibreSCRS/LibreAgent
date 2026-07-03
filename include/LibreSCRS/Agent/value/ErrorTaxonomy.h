// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <cstdint>

namespace LibreSCRS::Agent {

// Stable agent-side error taxonomy. Carried on Operation1.Finished as the
// `errorCode` field; clients branch on the numeric value. Append-only —
// never renumber existing entries.
enum class ErrorCode : std::uint32_t {
    None = 0,
    CardRemoved = 1,
    CredentialWrong = 2,
    CredentialBlocked = 3,
    CommunicationError = 4,
    ParseError = 5,
    UnsupportedCard = 6,
    AuthFailed = 7,
    // The prompter UI failed or was absent on the bus (no org.librescrs.Prompter1
    // owner / proxy throw / memfd I/O error) — distinct from a wrong secret
    // (CredentialWrong) or a generic transport failure (CommunicationError). The
    // flows remap their final code to this when the credential provider reports a
    // PromptStatus::Error (set via the prompterFailed flag); a cancellation or a
    // wrong-but-collected secret never maps here.
    PrompterError = 8,
    CapabilityMissing = 9,
    WatchdogTimeout = 10,
    // Signing. Append-only; never renumber.
    KeyNotFound = 11,        // chosen cert not resolvable / certId mismatch
    KeyAmbiguous = 12,       // >1 key matches the discriminator
    CertExpiredBlocked = 13, // expired signer blocked (per-level policy)
    ChainIncomplete = 14,    // chain cannot be completed/validated (LT family)
    TsaUnreachable = 15,     // timestamp authority unreachable/unconfigured
    SigningEngineError = 16, // engine failure not otherwise classified
    RateLimited = 17,        // too many sign requests from the caller
};

[[nodiscard]] ErrorCode errorCodeFor(LibreSCRS::SecureChannel::ChannelActivationError err) noexcept;

[[nodiscard]] ErrorCode errorCodeFor(LibreSCRS::Plugin::ReadResult::Status status) noexcept;

} // namespace LibreSCRS::Agent
