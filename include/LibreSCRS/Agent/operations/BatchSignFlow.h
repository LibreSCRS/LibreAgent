// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/String.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {
class CredentialCache;
}

namespace LibreSCRS::Agent::Operations {

class PromptSerializer;
class CardSessionHolder;

// Batch size bounds. A caller (the SignBatch dispatch entry, wired in a later
// task) is expected to validate BEFORE ever constructing a BatchSignFlow,
// mirroring how SignatureParams::isValidLayoutRect gates
// Manager1.LayoutVisualSignature at method entry -- a malformed count never
// reaches an Operation. isValidBatchDocumentCount is exposed here (pure,
// noexcept, directly testable) so that gate and this flow's own defensive
// re-check (BatchSignFlow::run() refuses a batch outside these bounds before
// touching the card, session or prompter) share one definition.
//
// kMaxBatchDocuments is bounded by the BUS's per-message fd budget, not by
// SCM_RIGHTS or the kernel: the reference dbus-daemon's max_message_unix_fds
// defaults to 16 fds PER MESSAGE, and a SignBatch round trip relays fds on
// BOTH legs -- the request carries one fd per document, the Result signal
// carries one artifact fd per row -- so either leg alone must stay under
// that ceiling on a stock session bus. 12 leaves headroom under 16 for any
// future auxiliary fd sharing a message; raising this cap later is
// wire-compatible, lowering it would not be.
inline constexpr std::size_t kMinBatchDocuments = 1;
inline constexpr std::size_t kMaxBatchDocuments = 12;

[[nodiscard]] constexpr bool isValidBatchDocumentCount(std::size_t count) noexcept
{
    return count >= kMinBatchDocuments && count <= kMaxBatchDocuments;
}

// One document entered into a batch. displayName is client-supplied chrome
// (untrusted, exactly like SignParams::displayName) and rides both the
// consent prompt's `artifacts` list and the resulting row. `bytes` is the
// already-resolved document payload -- fd-index resolution is a transport
// concern (the caller reads the frame's SCM_RIGHTS vector before this flow
// ever runs), so the flow never sees an fd, exactly like SignParams::
// inputDocument.
struct BatchDocumentInput
{
    std::string displayName;
    std::vector<std::uint8_t> bytes;
};

// One row of the batch's outcome, index-aligned with the input documents.
// Mirrors SignFlow::Result's per-sign fields (minus `candidates`, which is
// batch-scoped, not per-row) plus this ROW's own `code`. `signedBytes` is
// empty on any failed row -- sealing a failed artifact into the wire's
// pinned zero-length-memfd convention is a transport concern, done above
// this flow (Messages.cpp / the daemon dispatch), exactly like SignFlow
// never touches an fd either.
struct BatchSignRow
{
    std::string displayName;
    std::vector<std::uint8_t> signedBytes;
    std::string resolvedFormat;
    std::string resolvedLevel;
    bool tsaUsed{false};
    bool chainComplete{false};
    ErrorCode code{ErrorCode::None};
};

// Caches the ONE PIN collected via consent for a batch's duration, so the
// SAME secret is served to every document's Signer.sign() call without
// re-prompting the human. `wiped()` is an observability flag for tests: this
// repo has no death-test infrastructure to observe memory being zeroed
// directly, so a boolean a test can assert on stands in for "the secret
// storage was actually zeroed" -- wipe() itself calls Secure::String::clear()
// (which does the real zeroing) before dropping the value.
class BatchPinHolder
{
public:
    // Store the collected PIN, replacing any previously-held value.
    void set(LibreSCRS::Secure::String pin);

    // Non-null iff a PIN is currently held (set() called since construction
    // or the last wipe()).
    [[nodiscard]] const LibreSCRS::Secure::String* get() const noexcept;

    // Cleanse the held PIN (if any) and mark wiped() true. Idempotent; safe
    // to call whether or not a PIN was ever collected.
    void wipe() noexcept;

    [[nodiscard]] bool wiped() const noexcept;

private:
    std::optional<LibreSCRS::Secure::String> m_pin;
    bool m_wiped{false};
};

// References-only dependency bundle, mirroring SignFlowDeps: one shared
// session, one Signer seam, one credential-collection path -- but N
// documents processed sequentially under the SAME consent+PIN rather than
// one per call. `params` carries the batch-wide signing parameters (certId,
// format/level/packaging, allowExpired, tsaUrl, visual, reason, location --
// the SAME SignParams shape a single Sign already uses, reused verbatim);
// `params.inputDocument` and `params.displayName` are ignored -- each entry
// in `documents` supplies its own.
//
// `pinHolder` is INJECTED (not a local variable inside run()) specifically
// so it stays inspectable after run() returns: the caller (a test, or the
// daemon dispatch that will construct this flow) owns the holder's storage
// and can observe wiped() once the flow-scoped instance has gone out of
// scope, which a purely internal local could never expose.
struct BatchSignFlowDeps
{
    CardSessionHolder& holder;
    Signer& signer;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    OperationPhaseSink& phaseSink;
    BatchPinHolder& pinHolder;
    std::string cardKey;
    std::string requester;
    SignParams params;
    std::vector<BatchDocumentInput> documents;
    LibreSCRS::CancelToken token;
};

// Sequential per-file Signer.sign() under ONE collected credential. The PIN
// is asked exactly once (via the prompter) and cached agent-side in a
// BatchPinHolder for the batch's duration only, wiped by a scope guard on
// EVERY exit path (success, halt, cancel, or an exception unwinding through
// run()) -- see BatchSignFlow.cpp. A wrong or blocked credential HALTS the
// remaining documents: they are never attempted and their row inherits the
// SAME halt code, rather than re-prompting per file.
//
// Per-caller rate limiting: this flow does not hold a RateLimiter of its
// own. Every other Card1 entry (Sign, ManagePin, ActivateSigningKey) is
// gated by a single RateLimiter::allow() call at the daemon's dispatch
// entry, BEFORE any Operation (hence any flow) is constructed -- see
// RateLimiter.h. A SignBatch request reaches this flow through the exact
// same one-call dispatch (the daemon mints ONE Operation per SignBatch
// call and this flow's own run() loops over `documents` entirely in-
// process, never re-entering that dispatch per file), so the existing
// one-call-one-charge discipline already yields exactly one charge per
// batch regardless of document count -- duplicating a limiter reference
// here would only risk a second, redundant charge point drifting from the
// first.
class BatchSignFlow
{
public:
    enum class Outcome {
        Ok,             // >= 1 row signed; per-row `code`s are authoritative for the rest
        Cancelled,      // the batch was cancelled before a usable result existed
        Error,          // zero rows signed; `code` carries the terminal cause
        InvalidRequest, // document count outside [kMinBatchDocuments, kMaxBatchDocuments]
    };
    struct Result
    {
        Outcome outcome{Outcome::Error};
        // Meaningful iff outcome == Error (the terminal cause when zero rows
        // signed). Cancelled/InvalidRequest carry no meaningful code, exactly
        // like SignFlow::Result's own Cancelled convention.
        ErrorCode code{ErrorCode::None};
        std::vector<BatchSignRow> rows;
        std::string msgKey;
        std::string msgFallback;
    };

    explicit BatchSignFlow(BatchSignFlowDeps deps);
    [[nodiscard]] Result run();

private:
    BatchSignFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
