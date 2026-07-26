// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h> // CardReadSnapshot
#include <LibreSCRS/Agent/value/CertSnapshot.h>     // CertSnapshot
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialOpResult, CredentialRecord
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

// One row of a Card1.SignBatch result, index-aligned with the request's
// documents. Mirrors SignedArtifact's shape (bytes + meta) plus this row's OWN
// `displayName` (the client-supplied, per-document chrome the consent prompt
// also showed) and `code` (None on a successfully signed row). `bytes` is
// empty on a failed row -- sealing it into the wire's pinned
// zero-length-sealed-memfd convention (D-Bus `h` is non-nullable) is a
// transport concern, done by the Linux channel exactly like SignedArtifact's
// bytes are sealed for the single-document Sign1.Result. Deliberately a
// DISTINCT type from operations/BatchSignFlow.h's own BatchSignRow (which
// carries the flow's per-field breakdown, not this channel-level bytes+meta
// shape) -- SignOperation::doWork() draws the same distinction for
// SignedArtifact vs SignFlow::Result, and this mirrors it for the batch.
struct BatchSignedRow
{
    std::string displayName;
    std::vector<std::uint8_t> bytes;
    SignMeta meta;
    ErrorCode code{ErrorCode::None};
};
using BatchSignResult = std::vector<BatchSignedRow>;

// One credential-management result. `op` carries the uniform outcome payload
// (outcome token + retriesLeft/blocked/pinActivated/keyActivated) surfaced for
// EVERY completed management attempt — including InvalidPin/Blocked, where
// retriesLeft is meaningful — so it rides the Credentials1.Result signal ahead of
// Finished(status, code). `records` carries the ListCredentials listing (empty for
// a ManagePin / ActivateSigningKey mutation). Core yields the neutral value types;
// the Linux Credentials1 channel marshals them to the (a{sv}, aa{sv}) wire shape.
struct CredentialResult
{
    CredentialOpResult op;
    std::vector<CredentialRecord> records;
};

// CLOSED variant. One arm per high-level Card1 / Credentials1 result shape. A NEW
// high-level result shape is an API break at the frozen boundary — accepted here
// for the credential-management surface (ManagePin / ActivateSigningKey /
// ListCredentials share the one CredentialResult arm); other crypto growth routes
// through Pkcs11Broker + Reply, never here.
using ResultPayload = std::variant<CardReadSnapshot,          // ReadIdentity     -> Identity1.Result
                                   std::vector<CertSnapshot>, // ReadCertificates -> Certificates1.Result
                                   PhotoResult,               // GetPhoto         -> Photo1.Result
                                   SignedArtifact,            // Sign             -> Sign1.Result
                                   BatchSignResult,           // SignBatch        -> SignBatch1.Result
                                   CredentialResult>;         // Credentials1     -> Credentials1.Result

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
    // Emit one progressively-available identity field group, ahead of the
    // eventual emitResult/emitFinished pair (Identity1.Group on Linux; the
    // socket "OpIdentityGroup" event on macOS). Unlike emitResult this is NOT
    // pure virtual: every OperationChannel implementation shares this one
    // interface regardless of kind, but only an Identity1-hosting channel
    // ever has a Group signal to marshal — every other kind's channel simply
    // never receives a call here (GroupSink is wired to a NullGroupSink at
    // the GetPhotoOperation call site instead of this channel's owning
    // OperationBase; Sign/Certificates/Credentials never wire a real
    // GroupSink at all), so the default no-op is dead code in production,
    // kept only as defense-in-depth.
    virtual void emitGroup(const GroupSnapshot& /*group*/) noexcept {}
};

} // namespace LibreSCRS::Agent::Operations
