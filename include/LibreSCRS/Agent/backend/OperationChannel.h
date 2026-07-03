// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h> // CardReadSnapshot
#include <LibreSCRS/Agent/value/CertSnapshot.h>     // CertSnapshot
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>    // ErrorCode
#include <LibreSCRS/Agent/OperationPhase.h>         // OperationStatus
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Resolved Sign1.Result metadata. Carried on the Result signal and re-served by
// Sign1.GetResult (it never carries secret material — the signed document is the
// client's own output).
struct SignMeta
{
    std::string format;
    std::string level;
    bool tsaUsed{false};
    // RESERVED this release: always false. The signing backend exposes no chain
    // verdict yet, so nothing assigns this (it rides the default through every
    // sign). Emitted on the wire so the Sign1.meta shape is frozen; clients MUST
    // NOT read false as "chain incomplete". Will be set from a real verdict once
    // the backend surfaces one.
    bool chainComplete{false};
};

// One signed document plus its resolved metadata. Core yields the raw bytes; the
// Linux channel seals them into a sealed memfd for the Sign1.Result signal (and
// publishes the recovery store Sign1.GetResult re-dups from). macOS delivers
// inline.
struct SignedArtifact
{
    std::vector<std::uint8_t> bytes;
    SignMeta meta;
};

// One named photo (was the Photo1.Result map<"groupKey:fieldKey", UnixFd>). Core
// yields raw bytes; the Linux channel seals each into a memfd keyed by `key`.
// macOS delivers inline.
struct PhotoField
{
    std::string key;
    std::vector<std::uint8_t> bytes;
};
using PhotoResult = std::vector<PhotoField>;

// CLOSED variant. One arm per high-level Card1 result shape. A NEW high-level
// result shape is an API break at the frozen boundary — accepted, because crypto
// growth routes through Pkcs11Broker + Reply, never here.
using ResultPayload = std::variant<CardReadSnapshot,          // ReadIdentity     -> Identity1.Result
                                   std::vector<CertSnapshot>, // ReadCertificates -> Certificates1.Result
                                   PhotoResult,               // GetPhoto         -> Photo1.Result
                                   SignedArtifact>;           // Sign             -> Sign1.Result

// Per-operation emit-only channel the lifecycle core drives. Cancel rides
// OperationState, so this surface is emit-only. The concrete backend impl
// (Linux: the D-Bus operation adaptor with memfd sealing; macOS: XPC reply) is
// injected into OperationBase, which never references the sub-adaptor type.
class OperationChannel
{
public:
    virtual ~OperationChannel() = default;
    virtual void emitPropertiesChanged() noexcept = 0;
    virtual void emitFinished(OperationStatus status, ErrorCode code, std::string_view msgKey,
                              std::string_view msgFallback) noexcept = 0;
    // Returns true when the result was delivered (or there is nothing to deliver
    // for this channel's arm / the channel delivers inline with no seal step);
    // false ONLY when a REQUIRED large-result sealing step failed — the Linux
    // Photo1/Sign1 channels seal the raw bytes into a memfd, and a seal failure
    // MUST fail the op closed rather than emit a half-result. The lifecycle core
    // (Sign/GetPhoto ops) turns false into finish(Error, CommunicationError,
    // "op.memfd_failed"); Identity/Certificates deliver inline and always return
    // true. A future macOS inline impl returns true.
    [[nodiscard]] virtual bool emitResult(const ResultPayload& result) noexcept = 0;
};

} // namespace LibreSCRS::Agent::Operations
