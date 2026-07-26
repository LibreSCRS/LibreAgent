// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/BatchSignFlow.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // signingCandidates
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/OperationPhase.h> // OperationPhase enum
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Agent/operations/SignatureParams.h> // isQualifiedSignLevel
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

namespace LibreSCRS::Agent::Operations {

void BatchPinHolder::set(LibreSCRS::Secure::String pin)
{
    m_pin = std::move(pin);
}

const LibreSCRS::Secure::String* BatchPinHolder::get() const noexcept
{
    return m_pin.has_value() ? &*m_pin : nullptr;
}

void BatchPinHolder::wipe() noexcept
{
    if (m_pin.has_value()) {
        m_pin->clear();
        m_pin.reset();
    }
    m_wiped = true;
}

bool BatchPinHolder::wiped() const noexcept
{
    return m_wiped;
}

namespace {

BatchSignFlow::Result makeInvalidRequest()
{
    return BatchSignFlow::Result{
        .outcome = BatchSignFlow::Outcome::InvalidRequest,
        .code = ErrorCode::None,
        .rows = {},
        .msgKey = "op.invalid_request",
        .msgFallback = "Batch document count must be between 1 and 12",
    };
}

BatchSignFlow::Result makeCancelled()
{
    return BatchSignFlow::Result{
        .outcome = BatchSignFlow::Outcome::Cancelled,
        .code = ErrorCode::None,
        .rows = {},
        .msgKey = "op.cancelled",
        .msgFallback = "Operation cancelled",
    };
}

BatchSignFlow::Result makeOpenError(ErrorCode code, std::string msgFallback)
{
    return BatchSignFlow::Result{
        .outcome = BatchSignFlow::Outcome::Error,
        .code = code,
        .rows = {},
        .msgKey = "op.open_failed",
        .msgFallback = std::move(msgFallback),
    };
}

// Non-halting per-row status -> wire ErrorCode. Mirrors SignFlow's own
// mapSignStatus for every status EXCEPT AuthFailed/CardBlocked: this flow
// classifies those two separately (see isHaltingStatus below) because they
// halt the WHOLE batch rather than merely failing one row, and the halt
// code they surface (CredentialWrong/CredentialBlocked) is a deliberately
// more precise pair than SignFlow's own AuthFailed/CredentialBlocked
// mapping -- a new-for-batch decision, not a bug relative to SignFlow.
ErrorCode mapRowStatus(SignOutcome::Status s) noexcept
{
    switch (s) {
    case SignOutcome::Status::Ok:
        return ErrorCode::None;
    case SignOutcome::Status::KeyNotFound:
        return ErrorCode::KeyNotFound;
    case SignOutcome::Status::KeyAmbiguous:
        return ErrorCode::KeyAmbiguous;
    case SignOutcome::Status::CertExpiredBlocked:
        return ErrorCode::CertExpiredBlocked;
    case SignOutcome::Status::ChainIncomplete:
        return ErrorCode::ChainIncomplete;
    case SignOutcome::Status::TsaUnreachable:
        return ErrorCode::TsaUnreachable;
    case SignOutcome::Status::AuthFailed:
        return ErrorCode::CredentialWrong;
    case SignOutcome::Status::CardBlocked:
        return ErrorCode::CredentialBlocked;
    case SignOutcome::Status::CommunicationError:
        return ErrorCode::CommunicationError;
    case SignOutcome::Status::Cancelled:
        return ErrorCode::None;
    case SignOutcome::Status::SigningEngineError:
        return ErrorCode::SigningEngineError;
    case SignOutcome::Status::EngineUnavailable:
        return ErrorCode::EngineUnavailable;
    case SignOutcome::Status::InvalidDocument:
        return ErrorCode::InvalidDocument;
    }
    return ErrorCode::SigningEngineError;
}

// A wrong or blocked signing credential halts the remaining batch (the
// PIN the whole batch shares is exhausted/wrong, so retrying the next
// document could only reproduce the same failure); every other non-Ok
// status fails only the ONE row that produced it.
bool isHaltingStatus(SignOutcome::Status s) noexcept
{
    return s == SignOutcome::Status::AuthFailed || s == SignOutcome::Status::CardBlocked;
}

// Truncated, honest consent summary for the legacy `description` field: a
// prompter build that does not know the new `artifacts` option key still
// shows a meaningful ("N documents: a.pdf, b.pdf (+2 more)") consent rather
// than a blank one. Capped at 3 named entries; the full list rides
// PromptOptions::artifacts regardless of this cap.
std::string summarizeBatch(const std::vector<std::string>& names)
{
    constexpr std::size_t kMaxNamesInSummary = 3;
    std::string out = std::to_string(names.size());
    out += (names.size() == 1) ? " document" : " documents";
    const std::size_t shown = std::min(names.size(), kMaxNamesInSummary);
    if (shown == 0) {
        return out;
    }
    std::string joined;
    for (std::size_t i = 0; i < shown; ++i) {
        if (i > 0) {
            joined += ", ";
        }
        joined += names[i];
    }
    out += ": " + joined;
    if (names.size() > shown) {
        out += " (+" + std::to_string(names.size() - shown) + " more)";
    }
    return out;
}

} // namespace

BatchSignFlow::BatchSignFlow(BatchSignFlowDeps deps) : m_deps(std::move(deps)) {}

BatchSignFlow::Result BatchSignFlow::run()
{
    // The scope guard wipes the INJECTED pin holder (BatchSignFlowDeps::
    // pinHolder -- owned by the caller, not this function) on every exit
    // from run() (success, halt, cancel, invalid-request, or an exception
    // unwinding through run()) -- wipe() runs exactly once per run(),
    // unconditionally. Constructed before the count check below so even the
    // earliest refusal still counts as a run() exit.
    auto& pinHolder = m_deps.pinHolder;
    struct PinWipeGuard
    {
        BatchPinHolder& holder;
        ~PinWipeGuard()
        {
            holder.wipe();
        }
    } wipeGuard{pinHolder};

    if (!isValidBatchDocumentCount(m_deps.documents.size())) {
        return makeInvalidRequest();
    }

    // Open the held session (shared with the read flows via FlowPrelude).
    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return makeCancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return makeOpenError(opened.code, std::move(opened.msgFallback));
    }
    auto session = std::move(opened.session);
    auto candidates = std::move(opened.candidates);
    auto signCands = signingCandidates(candidates);

    auto& cache = m_deps.cache;
    auto& prompter = m_deps.prompter;
    auto& serializer = m_deps.serializer;
    auto& phaseSink = m_deps.phaseSink;
    const std::string cardKey = m_deps.cardKey;
    const std::string requester = m_deps.requester;
    const LibreSCRS::CancelToken token = m_deps.token;

    // The untrusted per-document display-name list for the consent prompt's
    // `artifacts` option, plus a truncated legacy-`description` summary (see
    // summarizeBatch above). `artifact` itself stays the TRUSTED, agent-
    // owned category token for the whole request ("signature-batch"),
    // exactly mirroring SignFlow's own "signature" -- neither is ever a
    // client-supplied string.
    std::vector<std::string> artifactNames;
    artifactNames.reserve(m_deps.documents.size());
    for (const auto& doc : m_deps.documents) {
        artifactNames.push_back(doc.displayName);
    }
    const std::string summary = summarizeBatch(artifactNames);

    // Set true iff a prompt failed because the prompter UI broke / was
    // absent on the bus (NOT cancellation, NOT a wrong-but-collected PIN).
    // Once true the PIN was never collected (the cached branch below never
    // reaches the real prompter), so the batch halts on it exactly like a
    // wrong/blocked credential -- retrying the next document against the
    // same broken prompter could only reproduce the same failure.
    auto prompterFailed = std::make_shared<std::atomic<bool>>(false);

    LibreSCRS::Auth::CredentialProvider provider =
        [&cache, &prompter, &serializer, &phaseSink, cardKey, requester, artifactNames, summary, token, prompterFailed,
         &pinHolder](const LibreSCRS::Auth::AuthRequirement& req) -> LibreSCRS::Auth::CredentialResult {
        try {
            SerializingPrompter gated{serializer, prompter, token};

            if (req.purpose() == LibreSCRS::Auth::Purpose::Signing) {
                if (const auto* cached = pinHolder.get()) {
                    // Already collected for this batch: serve the SAME PIN
                    // to every subsequent document. No re-prompt.
                    std::vector<LibreSCRS::Auth::CredentialEntry> entries;
                    entries.emplace_back(PrompterWire::kKindPin, *cached);
                    return LibreSCRS::Auth::CredentialResult::ok(std::move(entries));
                }
                phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
                PromptOptions opts;
                opts.requester = requester;
                opts.artifact = "signature-batch";
                opts.description = summary;
                opts.artifacts = artifactNames;
                if (const auto fields = req.fields(); !fields.empty()) {
                    if (const auto mn = fields.front().minLength) {
                        opts.minLength = static_cast<std::uint32_t>(*mn);
                    }
                    if (const auto mx = fields.front().maxLength) {
                        opts.maxLength = static_cast<std::uint32_t>(*mx);
                    }
                }
                const auto prompt = gated.requestPin(opts);
                if (prompt.status == PromptStatus::Cancelled) {
                    return LibreSCRS::Auth::CredentialResult::cancelled();
                }
                if (prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) {
                    if (prompt.status == PromptStatus::Error) {
                        prompterFailed->store(true, std::memory_order_relaxed);
                    }
                    return LibreSCRS::Auth::CredentialResult::error(LibreSCRS::LocalizedText{});
                }
                // PIN collected: cache it for the rest of the batch, then
                // arm the watchdog (Authenticating) and surface the on-card
                // signing phase -- both AFTER the human, exactly like
                // SignFlow, so the unbounded consent wait is never timed.
                pinHolder.set(*prompt.secret);
                phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
                phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Signing));
                std::vector<LibreSCRS::Auth::CredentialEntry> entries;
                entries.emplace_back(PrompterWire::kKindPin, *prompt.secret);
                return LibreSCRS::Auth::CredentialResult::ok(std::move(entries));
            }

            // Channel-establishment secret (CAN/MRZ): cacheable, no sign phases.
            phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
            PromptOptions chanOpts;
            chanOpts.requester = requester;
            chanOpts.artifact = "signature-batch";
            return cache.requestCredential(cardKey, req, gated, chanOpts, prompterFailed.get());
        } catch (...) {
            return LibreSCRS::Auth::CredentialResult::error(LibreSCRS::LocalizedText{});
        }
    };
    // Install with a UAF scope guard (see FlowPrelude::installScopedReadProvider):
    // the provider captures the per-op phaseSink and pinHolder by reference,
    // both owned by this stack frame, but `session` is owned by the
    // CardSessionHolder and outlives this flow. The SAME provider (copied)
    // is handed to every document's signer.sign() call below.
    const auto providerGuard = FlowPrelude::installScopedReadProvider(session, provider);

    if (m_deps.token.isCancelled()) {
        return makeCancelled();
    }

    std::vector<BatchSignRow> rows;
    rows.reserve(m_deps.documents.size());
    std::size_t successCount = 0;
    ErrorCode lastCode = ErrorCode::None;
    bool halted = false;
    ErrorCode haltCode = ErrorCode::None;

    for (const auto& doc : m_deps.documents) {
        if (halted) {
            // The batch already halted on an earlier document: the
            // remaining documents are never attempted (the Signer seam is
            // never called again, so the credential provider is never
            // re-invoked either) -- they simply inherit the halt code.
            rows.push_back(BatchSignRow{.displayName = doc.displayName,
                                        .signedBytes = {},
                                        .resolvedFormat = {},
                                        .resolvedLevel = {},
                                        .tsaUsed = false,
                                        .chainComplete = false,
                                        .code = haltCode});
            lastCode = haltCode;
            continue;
        }

        if (m_deps.token.isCancelled()) {
            return makeCancelled();
        }

        SignParams params = m_deps.params;
        params.inputDocument = doc.bytes;
        params.displayName = doc.displayName;

        SignOutcome outcome = m_deps.signer.sign(session, params, signCands, provider, m_deps.token);

        // A cancelled token wins over any per-row bookkeeping: on shutdown
        // the token is the agent-wide shutdown-cancel token, so bailing here
        // returns Cancelled before touching the credential cache below --
        // which an abandoned worker must not reach once the aggregate that
        // owns it is gone.
        if (outcome.status == SignOutcome::Status::Cancelled || m_deps.token.isCancelled()) {
            return makeCancelled();
        }

        if (outcome.status == SignOutcome::Status::Ok) {
            if (SignatureParams::isQualifiedSignLevel(outcome.resolvedLevel)) {
                m_deps.phaseSink.setPhase(static_cast<std::uint32_t>(OperationPhase::Timestamping));
            }
            ++successCount;
            lastCode = ErrorCode::None;
            rows.push_back(BatchSignRow{
                .displayName = doc.displayName,
                .signedBytes = std::move(outcome.signedDocumentBytes),
                .resolvedFormat = std::move(outcome.resolvedFormat),
                .resolvedLevel = std::move(outcome.resolvedLevel),
                .tsaUsed = outcome.tsaUsed,
                .chainComplete = outcome.chainComplete,
                .code = ErrorCode::None,
            });
            continue;
        }

        // Non-Ok, non-Cancelled: classify into a halting or a row-local code.
        ErrorCode code;
        bool haltsBatch = false;
        if (prompterFailed->load(std::memory_order_relaxed)) {
            // A broken/absent prompter prevented PIN collection -- no PIN
            // was ever cached, so every remaining document would hit the
            // same broken prompter. Halt rather than retry per file.
            code = ErrorCode::PrompterError;
            haltsBatch = true;
        } else if (isHaltingStatus(outcome.status)) {
            // A wrong signing PIN must not poison a later read's cached
            // CAN; the PIN itself is never cached, but evict the PACE
            // secret so a card swap or a retry re-establishes cleanly --
            // mirrors SignFlow's own eviction.
            m_deps.cache.invalidate(m_deps.cardKey);
            session->clearCachedPaceCredentials();
            code = mapRowStatus(outcome.status);
            haltsBatch = true;
        } else {
            code = mapRowStatus(outcome.status);
        }

        rows.push_back(BatchSignRow{.displayName = doc.displayName,
                                    .signedBytes = {},
                                    .resolvedFormat = {},
                                    .resolvedLevel = {},
                                    .tsaUsed = false,
                                    .chainComplete = false,
                                    .code = code});
        lastCode = code;
        if (haltsBatch) {
            halted = true;
            haltCode = code;
        }
    }

    if (successCount > 0) {
        return BatchSignFlow::Result{
            .outcome = BatchSignFlow::Outcome::Ok,
            .code = ErrorCode::None,
            .rows = std::move(rows),
            .msgKey = "op.ok",
            .msgFallback = "Batch signature produced",
        };
    }
    return BatchSignFlow::Result{
        .outcome = BatchSignFlow::Outcome::Error,
        .code = lastCode,
        .rows = std::move(rows),
        .msgKey = "op.sign_failed",
        .msgFallback = "No document in the batch was signed",
    };
}

} // namespace LibreSCRS::Agent::Operations
