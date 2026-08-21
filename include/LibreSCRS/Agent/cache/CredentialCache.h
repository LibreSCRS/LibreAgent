// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>     // PromptOptions, PromptResult, PromptStatus
#include <LibreSCRS/Agent/backend/PrompterWire.h>    // shared pin/can/mrz kind vocabulary
#include <LibreSCRS/Agent/cache/MrzPayload.h>        // parseMrzPayload, MrzParts (A1)
#include <LibreSCRS/Agent/operations/PromptPolicy.h> // kMaxPaceAttempts
#include <LibreSCRS/Auth/AuthRequirement.h>          // AuthRequirement
#include <LibreSCRS/Auth/CredentialResult.h>         // CredentialResult, CredentialEntry
#include <LibreSCRS/Auth/ErrorKeys.h>                // ErrorKeys::genericComm
#include <LibreSCRS/Auth/PaceSecretKind.h>           // PaceSecretKind
#include <LibreSCRS/Secure/String.h>
#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace LibreSCRS::Agent {

// One-shot hand-off channel for a secret the user chose INSTEAD of the one the
// card asked for.
//
// A prompter that honoured the alternative-kind offer answers a CAN request
// with an MRZ payload. That payload is useless to the activation attempt in
// flight (the card asked for a CAN), so requestCredential parks it here and
// unwinds the walk as a cancellation; the flow one level up consults the sink
// BEFORE honouring that cancellation and renegotiates the read instead.
//
// Consumption is ONE-SHOT consume-and-scrub: take() moves the payload out under
// the mutex and disarms the sink, so a second take() yields nothing -- that is
// the rule the flow's "re-run the read exactly once" contract rests on. reset()
// scrubs a payload nobody consumed; the flow calls it at run() exit so a sink
// filled on an error/cancelled path never outlives the run holding secret bytes
// (the stored Secure::String cleanses itself on destruction either way).
//
// The sink is flow-owned and never shared across runs. Thread-safe: the
// credential provider may be invoked from LM's activation path on the reader's
// worker thread while the flow inspects it.
class MrzChoiceSink
{
public:
    using Secret = LibreSCRS::Secure::String;

    // Park @p payload and arm the sink, scrubbing anything still held.
    void offer(Secret payload)
    {
        const std::lock_guard lock(m_mutex);
        m_payload = std::move(payload);
        m_taken.store(true, std::memory_order_release);
    }

    // True iff the user TOOK the in-dialog switch and a payload is waiting.
    [[nodiscard]] bool taken() const noexcept
    {
        return m_taken.load(std::memory_order_acquire);
    }

    // One-shot consume-and-scrub: move the payload out and disarm.
    [[nodiscard]] std::optional<Secret> take()
    {
        const std::lock_guard lock(m_mutex);
        auto payload = std::move(m_payload);
        m_payload.reset();
        m_taken.store(false, std::memory_order_release);
        return payload;
    }

    // Scrub any unconsumed payload and disarm.
    void reset() noexcept
    {
        try {
            const std::lock_guard lock(m_mutex);
            m_payload.reset();
        } catch (...) {
            // Lock acquisition failure (allocator pressure): the payload is
            // still cleansed by the Secure::String destructor when this sink
            // dies with the flow.
        }
        m_taken.store(false, std::memory_order_release);
    }

private:
    mutable std::mutex m_mutex;
    std::atomic<bool> m_taken{false};
    std::optional<Secret> m_payload;
};

// Per-card in-memory cache for low-secrecy pre-read credentials (CAN / MRZ).
//
// PIN IS NEVER CACHED. The contract is enforced by the API: there is no
// putPin / getPin / hasPin method. Any future change that tries to cache a
// PIN must add new API surface and justify itself in code review.
//
// Caching is keyed by an opaque card identifier — in production the
// per-insertion D-Bus object path, but the cache itself imposes no format.
//
// Thread-safe via an internal mutex — callers do NOT need to hold the
// agent's state mutex. Accessors run both from the monitor thread (under
// the agent state mutex) and from per-reader worker jthreads (which do
// not), so every public method that touches m_entries locks m_mutex.
class CredentialCache
{
public:
    using Secret = LibreSCRS::Secure::String;

    void putCan(const std::string& cardKey, Secret can);
    void putMrz(const std::string& cardKey, Secret mrz);

    [[nodiscard]] std::optional<Secret> getCan(const std::string& cardKey) const;
    [[nodiscard]] std::optional<Secret> getMrz(const std::string& cardKey) const;

    [[nodiscard]] bool hasCan(const std::string& cardKey) const;
    [[nodiscard]] bool hasMrz(const std::string& cardKey) const;

    // Drop everything stored for one card (e.g. on CardRemoved / ReaderRemoved).
    // ALSO resets any retry context markCredentialWrong recorded for this card
    // (a full entry erase) -- callers that evict as a SIDE EFFECT of an
    // unrelated failure (e.g. a wrong signing PIN evicting the pre-read CAN so
    // a retry re-establishes cleanly) use this, not markCredentialWrong, since
    // that failure carries no claim about the CAN/MRZ having been wrong.
    void invalidate(const std::string& cardKey);

    // Drop everything (shutdown / idle-exit).
    void clear();

    // Record that the CAN/MRZ collected for @p cardKey was rejected by the
    // card: evicts the now-known-wrong cached value (same effect as
    // invalidate(), so the rejected secret is never replayed) AND bumps a
    // per-card attempt counter + remembers @p errorMsgKey, so the NEXT
    // requestCredential() prompt for this card carries that context (see
    // PromptOptions::attempt / PromptOptions::lastError) instead of either
    // silently reusing the rejected value or prompting cold.
    //
    // Call this ONLY when the failure genuinely means "the pre-read CAN/MRZ
    // was wrong" (the eMRTD read flows' AuthFailed branch). A signing-PIN
    // failure that incidentally evicts the CAN/MRZ cache as a side effect
    // (SignFlow / RawCryptoFlow / BatchSignFlow) must keep calling plain
    // invalidate() -- it has no claim about the CAN/MRZ, and a fresh PACE
    // cycle after a PIN failure has no wrong-CAN history to report.
    void markCredentialWrong(const std::string& cardKey, std::string errorMsgKey);

    // Cache-or-prompt helper invoked by the agent's credential provider
    // callback. Returns a CredentialResult populated from cache on hit,
    // from the prompter on miss (and stored on prompter success). The
    // secret to collect is chosen from the AuthRequirement the plugin's
    // activation path hands the provider: req.paceKind() selects CAN or
    // MRZ. PIN is never cached -- only Can and Mrz secrets are routed
    // through here; any other kind (or an absent paceKind) yields an error.
    //
    // The PrompterT template parameter is a duck-typed interface: any
    // type with PromptResult requestCan(const PromptOptions&) and
    // PromptResult requestMrz(const PromptOptions&) satisfies the
    // contract. Production callers pass the real backend prompter client; tests
    // pass a Fake.
    //
    // @p prompterFailed, when non-null, is set to true iff the prompt
    // returned PromptStatus::Error (the prompter UI broke / was absent on
    // the bus) — NOT on cancellation and NOT on a wrong-but-collected
    // secret. The caller uses it to remap the final ErrorCode to
    // PrompterError so clients can tell "the prompter failed" from a
    // generic comms/auth failure. Left null by callers that do not care.
    //
    // @p userCancelled, when non-null, is set to true iff the prompt returned
    // PromptStatus::Cancelled (the user dismissed the dialog) — the cancel
    // twin of prompterFailed. The list flow consults it because the LM seam
    // swallows a candidate's channel-activation throw: without this signal a
    // cancelled CAN prompt would be indistinguishable from a live card that
    // advertises no PIN credentials. Left null by callers that do not care.
    //
    // @p entryExpired, when non-null, is set to true iff the prompt returned
    // PromptStatus::Timeout (the window closed because the holder's entry time
    // ran out) — the clock twin of prompterFailed. The caller remaps the final
    // ErrorCode to EntryExpired, so the holder is not told they cancelled what
    // the clock took from them, nor that the card rejected something it never
    // saw. Left null by callers that do not care.
    //
    // @p helperTooOld, when non-null, is set to true iff the prompt returned
    // PromptStatus::HelperTooOld — the agent refused to raise a prompt it could
    // not later dismiss. The caller remaps the final ErrorCode to
    // CapabilityMissing, whose client copy names the remedy (restart the
    // session), rather than to PrompterError, which describes a helper that
    // broke when this one is running fine.
    //
    // @p mrzChoice, when non-null, opts the caller into the in-dialog CAN⇄MRZ
    // switch: a prompt that answers with a kind OTHER than the one requested
    // (an MRZ payload on a CAN request) parks its payload in the sink and
    // returns UserCancelled WITHOUT raising @p userCancelled and WITHOUT
    // caching anything — the walk unwinds so the caller can renegotiate. A
    // caller that leaves this null never advertised the alternative kinds, so
    // a chosen-kind reply to it is a broken-prompter condition: Error, with
    // @p prompterFailed raised. A reply whose chosen kind merely ECHOES the
    // requested one is an ordinary reply, not a switch.
    template <typename PrompterT>
    [[nodiscard]] LibreSCRS::Auth::CredentialResult
    requestCredential(const std::string& cardKey, const LibreSCRS::Auth::AuthRequirement& req, PrompterT& prompter,
                      const PromptOptions& options, std::atomic<bool>* prompterFailed = nullptr,
                      std::atomic<bool>* userCancelled = nullptr, MrzChoiceSink* mrzChoice = nullptr,
                      std::atomic<bool>* entryExpired = nullptr, std::atomic<bool>* helperTooOld = nullptr);

private:
    struct Entry
    {
        std::optional<Secret> can;
        std::optional<Secret> mrz;
        // Retry context maintained by markCredentialWrong(): the number of
        // CAN/MRZ collections rejected by the card so far for this card (0 ==
        // no known failure), and the msgKey of the most recent such failure.
        // Reset only by a full-entry erase (invalidate() / clear()).
        std::uint32_t failedAttempts = 0;
        std::string lastErrorKey;
    };
    mutable std::mutex m_mutex;
    std::map<std::string, Entry> m_entries;

    // Failures recorded for @p cardKey by markCredentialWrong(); 0 for a card
    // with no history. Locks m_mutex like every other accessor.
    [[nodiscard]] std::uint32_t failedAttemptsFor(const std::string& cardKey) const;

    // Populate @p opts.attempt / @p opts.lastError from @p cardKey's retry
    // context, iff a prior failure was recorded (failedAttempts > 0). Leaves
    // @p opts untouched (defaults: no context) on a card with no recorded
    // failure -- the first-ever prompt for a card. `attempt` numbers the
    // prompt about to be shown (one past the failures already recorded).
    void applyRetryContext(const std::string& cardKey, PromptOptions& opts) const;
};

template <typename PrompterT>
LibreSCRS::Auth::CredentialResult
CredentialCache::requestCredential(const std::string& cardKey, const LibreSCRS::Auth::AuthRequirement& req,
                                   PrompterT& prompter, const PromptOptions& options, std::atomic<bool>* prompterFailed,
                                   std::atomic<bool>* userCancelled, MrzChoiceSink* mrzChoice,
                                   std::atomic<bool>* entryExpired, std::atomic<bool>* helperTooOld)
{
    using LibreSCRS::Auth::CredentialEntry;
    using LibreSCRS::Auth::CredentialResult;
    using LibreSCRS::Auth::PaceSecretKind;

    auto buildOk = [](std::string key, const Secret& value) {
        std::vector<CredentialEntry> entries;
        entries.emplace_back(std::move(key), value);
        return CredentialResult::ok(std::move(entries));
    };

    // Surface prompter-side failures through the LM-canonical error factory
    // (LibreSCRS::Auth::ErrorKeys) rather than a hand-rolled LocalizedText —
    // keeps the agent's user-visible diagnostics consistent with the rest of
    // the LM Auth surface.
    auto buildError = []() { return CredentialResult::error(LibreSCRS::Auth::ErrorKeys::genericComm()); };

    // Per-kind RESULT BUILDER: adapt a stored/collected RAW secret into the
    // credential entries LM's activation branches consume, or std::nullopt when
    // the payload is MALFORMED for that kind. A nullopt drives buildError plus
    // no-cache-write (prompt path) / cache eviction (hit path): a malformed value
    // must never reach LM and must never survive to poison the next attempt.
    //
    // Can keeps exactly one "can" entry, PLUS a shape guard: a CAN payload that
    // contains '\n' is a 3-line MRZ mis-delivered into the CAN slot and must
    // never reach LM as a "CAN".
    auto buildCanResult = [&](const Secret& secret) -> std::optional<CredentialResult> {
        if (secret.view().find('\n') != std::string_view::npos) {
            return std::nullopt;
        }
        return buildOk(PrompterWire::kKindCan, secret);
    };
    // Mrz yields the UNION both activation branches consume — {"mrz"} (the PACE
    // MRZ_information, CardSession.cpp:876-886) plus the BAC trio
    // {"documentNumber","dateOfBirth","dateOfExpiry"} (CardSession.cpp:779-781),
    // check digit stripped. parseMrzPayload (A1) verifies the widget grammar AND
    // all three ICAO 7-3-1 check digits; anything else is std::nullopt so the
    // single-source-of-truth invariant (mrzInfo == buildMrzInformation(trio))
    // holds for every entry LM ever sees.
    auto buildMrzResult = [](const Secret& secret) -> std::optional<CredentialResult> {
        auto parts = parseMrzPayload(secret);
        if (!parts.has_value()) {
            return std::nullopt;
        }
        std::vector<CredentialEntry> entries;
        entries.emplace_back(PrompterWire::kKindMrz, std::move(parts->mrzInfo));  // PACE slot
        entries.emplace_back("documentNumber", std::move(parts->documentNumber)); // BAC branch
        entries.emplace_back("dateOfBirth", std::move(parts->dateOfBirth));
        entries.emplace_back("dateOfExpiry", std::move(parts->dateOfExpiry));
        return CredentialResult::ok(std::move(entries));
    };

    // The plugin's activation path establishes a PACE/BAC channel, so the
    // requirement carries the secret kind it needs. CAN and MRZ are the only
    // cacheable pre-read secrets; PIN/PUK (or an absent kind) are routed to an
    // error because PIN is never cached and the agent's pre-read flow does not
    // collect PIN-as-PACE-password here.
    // One shared cache-hit / prompt / cancel / error / store sequence for both
    // cacheable kinds, parameterized on the cache accessors, the prompter member
    // and the per-kind result builder. The CAN and MRZ case labels below differ
    // only in what they bind here, so a future change to the sequence cannot
    // drift between the two branches. Adaptation happens at RESULT-BUILD time on
    // BOTH paths, so the cache stays a raw-payload cache (Task 12's renegotiation
    // deposit shares one stored shape).
    auto cacheOrPrompt = [&](PaceSecretKind requestedKind, auto getter, auto putter, auto promptFn,
                             auto resultBuilder) -> CredentialResult {
        if (auto cached = (this->*getter)(cardKey)) {
            if (auto result = resultBuilder(*cached)) {
                return std::move(*result);
            }
            // Malformed cached value: EVICT it so it cannot poison the next
            // attempt, then surface the error.
            invalidate(cardKey);
            return buildError();
        }
        // Retry bound for PACE secrets. A CAN is not counted by the document, and
        // the watchdog no longer bounds the retry cycle (it is disarmed while the
        // holder types), so without this the cycle is unlimited. After the cache
        // hit on purpose: the cap refuses to ASK, never to answer.
        //
        // Only Can and Mrz reach here. A PIN must not: the CARD owns that counter
        // and a software cap disagreeing with it is worse than none.
        if (failedAttemptsFor(cardKey) >= Operations::kMaxPaceAttempts) {
            return CredentialResult::error(LibreSCRS::Auth::ErrorKeys::preReadAuthFailed());
        }
        PromptOptions promptOpts = options;
        applyRetryContext(cardKey, promptOpts);
        const auto prompt = (prompter.*promptFn)(promptOpts);
        if (prompt.status == PromptStatus::Cancelled) {
            if (userCancelled != nullptr) {
                userCancelled->store(true, std::memory_order_relaxed);
            }
            return CredentialResult::cancelled();
        }
        if (prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) {
            if (prompterFailed != nullptr && prompt.status == PromptStatus::Error) {
                prompterFailed->store(true, std::memory_order_relaxed);
            }
            // The clock closed the window: nobody cancelled and the card
            // rejected nothing, so neither of those codes may be reported.
            if (entryExpired != nullptr && prompt.status == PromptStatus::Timeout) {
                entryExpired->store(true, std::memory_order_relaxed);
            }
            // Refused before the window was ever raised: a capability gap, and
            // the one outcome here whose remedy the holder can act on.
            if (helperTooOld != nullptr && prompt.status == PromptStatus::HelperTooOld) {
                helperTooOld->store(true, std::memory_order_relaxed);
            }
            return buildError();
        }
        // The prompter honoured an in-dialog switch: the secret it collected is
        // NOT of the kind this activation asked for, so it must never be adapted
        // into this kind's entries nor stored in this kind's cache slot. Park it
        // for the caller and unwind the walk (a cancellation the caller
        // disambiguates by the sink, NOT by userCancelled -- nobody cancelled).
        if (prompt.chosenKind.has_value() && *prompt.chosenKind != requestedKind) {
            if (mrzChoice != nullptr && requestedKind == PaceSecretKind::Can &&
                *prompt.chosenKind == PaceSecretKind::Mrz) {
                mrzChoice->offer(*prompt.secret);
                return CredentialResult::cancelled();
            }
            // Either the caller never opted in, or the prompter answered a kind
            // no switch was ever offered for: a broken prompter, fail closed.
            if (prompterFailed != nullptr) {
                prompterFailed->store(true, std::memory_order_relaxed);
            }
            return buildError();
        }
        auto result = resultBuilder(*prompt.secret);
        if (!result.has_value()) {
            // Malformed collected payload: error, and DO NOT cache it.
            return buildError();
        }
        (this->*putter)(cardKey, *prompt.secret);
        return std::move(*result);
    };

    const auto kind = req.paceKind();
    if (!kind.has_value()) {
        return buildError();
    }
    switch (*kind) {
    case PaceSecretKind::Can:
        return cacheOrPrompt(PaceSecretKind::Can, &CredentialCache::getCan, &CredentialCache::putCan,
                             &PrompterT::requestCan, buildCanResult);
    case PaceSecretKind::Mrz:
        return cacheOrPrompt(PaceSecretKind::Mrz, &CredentialCache::getMrz, &CredentialCache::putMrz,
                             &PrompterT::requestMrz, buildMrzResult);
    case PaceSecretKind::Pin:
    case PaceSecretKind::Puk:
        return buildError();
    }
    return buildError();
}

} // namespace LibreSCRS::Agent
