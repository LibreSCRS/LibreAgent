// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>     // PromptOptions, PromptResult, PromptStatus
#include <LibreSCRS/Agent/backend/PrompterWire.h>    // shared pin/can/mrz kind vocabulary
#include <LibreSCRS/Agent/cache/AttemptContext.h>    // per-operation retry context
#include <LibreSCRS/Agent/cache/MrzPayload.h>        // parseMrzPayload, MrzParts (A1)
#include <LibreSCRS/Agent/operations/PromptPolicy.h> // kMaxPaceAttempts
#include <LibreSCRS/Auth/AuthRequirement.h>          // AuthRequirement
#include <LibreSCRS/Auth/CredentialResult.h>         // CredentialResult, CredentialEntry
#include <LibreSCRS/Auth/ErrorKeys.h>                // ErrorKeys::genericComm
#include <LibreSCRS/Auth/PaceSecretKind.h>           // PaceSecretKind
#include <LibreSCRS/Secure/String.h>
#include <atomic>
#include <cstdint>
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

    // Drop everything stored for one card (e.g. on CardRemoved / ReaderRemoved):
    // a full entry erase, so it ALSO drops @ref refusalGenerationFor's counter
    // and the lastPromptYieldedNothing flag -- a re-presented card starts over
    // on every card-level fact this cache still keeps, not just the secrets.
    // markCredentialWrong(), by contrast, evicts ONLY the secrets and leaves
    // those two card-level facts alone, because they describe the CARD's own
    // history (a declined window, a generation the prompt gate reads), not the
    // rejected value markCredentialWrong is about. Callers that evict as a
    // SIDE EFFECT of an unrelated failure (e.g. a wrong signing PIN evicting
    // the pre-read CAN so a retry re-establishes cleanly) use this, not
    // markCredentialWrong, since that failure carries no claim about the
    // CAN/MRZ having been wrong.
    void invalidate(const std::string& cardKey);

    // Drop everything (shutdown / idle-exit).
    void clear();

    // Record that the CAN/MRZ collected for @p cardKey was rejected by the
    // card: evicts the now-known-wrong cached value, so the rejected secret is
    // never replayed from cache (same effect as invalidate()).
    //
    // Does NOT count the rejection or remember why: the attempt count and its
    // msgKey belong to the operation that collected the rejected value, not to
    // the card -- see @ref AttemptContext. A caller that wants the next
    // requestCredential() prompt to carry retry context (PromptOptions::attempt
    // / PromptOptions::lastError) records the rejection on its OWN
    // AttemptContext (AttemptContext::recordRejection) and passes that context
    // to requestCredential().
    //
    // Call this ONLY when the failure genuinely means "the pre-read CAN/MRZ
    // was wrong" (the eMRTD read flows' AuthFailed branch). A signing-PIN
    // failure that incidentally evicts the CAN/MRZ cache as a side effect
    // (SignFlow / RawCryptoFlow / BatchSignFlow) must keep calling plain
    // invalidate() -- it has no claim about the CAN/MRZ, and a fresh PACE
    // cycle after a PIN failure has no wrong-CAN history to report.
    void markCredentialWrong(const std::string& cardKey);

    // True iff the last prompt raised for @p cardKey closed without collecting
    // anything. The rejection signal that follows such a prompt describes a
    // secret that was never presented, so the caller must not treat it as a
    // rejection: doing so evicts a value nobody supplied, burns a PACE attempt,
    // and tells the holder their entry was not accepted when they made none.
    [[nodiscard]] bool lastPromptYieldedNothingFor(const std::string& cardKey) const;

    // Record whether the last prompt for @p cardKey collected anything.
    void noteLastPromptYieldedNothing(const std::string& cardKey, bool yieldedNothing);

    // Which outcome closed the window behind a refusal: the clock ran out, or
    // the holder dismissed the dialog outright. The gate reads this back (via
    // @ref lastRefusalKindFor) so an operation it silences reports EXACTLY
    // what the operation that actually raised the window was told -- not a
    // generic failure. Timeout is the default so a card with no refusal
    // history yet reads as something, though that value is never consulted
    // there: @ref refusalGenerationFor is 0 for such a card, so the gate that
    // reads this can never fire for it.
    enum class RefusalKind : std::uint8_t { Timeout, Cancelled };

    // Record that a prompt for @p cardKey closed without collecting anything,
    // and which outcome closed it. Bumps the card's refusal generation, which
    // @ref stillWantedFor compares against an operation's own captured
    // generation (see @ref AttemptContext) to bound that SAME operation's
    // re-prompt loop after its own window closes empty. It does not silence a
    // genuinely different operation that was already queued when this
    // happened: such an operation only constructs its AttemptContext -- and
    // captures the generation -- once it is dequeued and starts running, by
    // which point this bump is already reflected in what it captures, so it
    // reads as unrefused. Remembers @p kind so @ref lastRefusalKindFor can
    // tell an operation that IS caught by the check which outcome to report.
    // Does NOT touch the attempt count: nothing was presented, so nothing was
    // rejected.
    void noteRefusal(const std::string& cardKey, RefusalKind kind = RefusalKind::Timeout);

    // The card's refusal generation; 0 for a card with no history.
    [[nodiscard]] std::uint64_t refusalGenerationFor(const std::string& cardKey) const;

    // The kind of the card's most recent refusal (Timeout for a card with no
    // history -- see @ref RefusalKind).
    [[nodiscard]] RefusalKind lastRefusalKindFor(const std::string& cardKey) const;

    // True iff an operation carrying @p attempts (its own retry context, or
    // null for "no per-operation context, gate off") is still allowed to
    // prompt for @p cardKey: no OTHER refusal has landed for this card since
    // @p attempts was constructed. THE single definition of that comparison
    // -- requestCredential's own dispatch-time gate and post-prompt recheck
    // both call this, and it is what a production caller wires into
    // SerializingPrompter's post-acquire still-wanted check (see that
    // class's constructor doc) so the two gates can never drift apart. A
    // drift would mean the serializer lets a prompt through the cache would
    // have refused, or the reverse -- either way a fabricated outcome.
    [[nodiscard]] bool stillWantedFor(const std::string& cardKey, const AttemptContext* attempts) const;

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
    //
    // @p attempts, when non-null, is the retry context OF THE CALLING
    // OPERATION (see @ref AttemptContext): a CAN/MRZ prompt is refused once
    // `attempts->attempts() >= Operations::kMaxPaceAttempts`, and a prompt that
    // is still allowed has @ref applyRetryContext populate @p opts.attempt /
    // @p opts.lastError from it. It also carries @ref
    // AttemptContext::generationAtDispatch, which the gate (see @ref
    // noteRefusal and @ref stillWantedFor) compares against the card's
    // current refusal generation: an operation whose captured generation has
    // fallen behind is refused a further window of its own. Within a single
    // operation that bounds the middleware's own re-invocation loop after one
    // window already closed empty; it does not yet reach a genuinely
    // different operation that was already queued when the refusal happened,
    // because such an operation only captures the generation once it is
    // dequeued and starts running, by which point the earlier refusal is
    // already reflected in what it captures. Null means "no operation
    // context": the prompt is unconditionally cold and both the cap and that
    // gate are OFF. Every production caller
    // reaches this call with a real AttemptContext constructed at the top of
    // its own run() (the read flows via FlowPrelude::makeReadCredentialProvider;
    // SignFlow / BatchSignFlow build theirs directly, since their hand-rolled
    // provider also serves the uncached signing PIN). PIN itself never reaches
    // THIS call on any path -- it is collected and verified by a separate
    // branch before the CAN/MRZ branch below is ever entered, and the CARD
    // owns that counter, not this cache. A caller must never construct an
    // AttemptContext just to satisfy this parameter.
    template <typename PrompterT>
    [[nodiscard]] LibreSCRS::Auth::CredentialResult
    requestCredential(const std::string& cardKey, const LibreSCRS::Auth::AuthRequirement& req, PrompterT& prompter,
                      const PromptOptions& options, std::atomic<bool>* prompterFailed = nullptr,
                      std::atomic<bool>* userCancelled = nullptr, MrzChoiceSink* mrzChoice = nullptr,
                      std::atomic<bool>* entryExpired = nullptr, std::atomic<bool>* helperTooOld = nullptr,
                      AttemptContext* attempts = nullptr);

private:
    struct Entry
    {
        std::optional<Secret> can;
        std::optional<Secret> mrz;
        // True while the most recent prompt for this card produced NO secret --
        // its window closed on the clock. Per CARD, not per flow run: the run
        // that raised the window ends with it, and the middleware's re-request
        // arrives inside the NEXT one, carrying the same rejection reason a
        // genuinely wrong secret carries. A per-run flag cannot see across that
        // boundary; this can. Cleared the moment a prompt does yield a secret.
        bool lastPromptYieldedNothing = false;
        // Monotonic count of prompts for this card that closed WITHOUT a
        // secret -- expired or cancelled. A caller captures it into its
        // AttemptContext (see that type: WHERE it captures decides how far
        // back the gate can reach) and a prompt is refused once the card's
        // count has moved past what was captured. Reset by a full-entry erase
        // (invalidate() / clear()), so re-presenting the card starts over.
        std::uint64_t refusalGeneration = 0;
        // Which outcome produced the MOST RECENT refusal above -- see
        // @ref RefusalKind. Read back by the gate so a silenced operation
        // reports the same outcome the operation that actually prompted did.
        RefusalKind refusalKind = RefusalKind::Timeout;
    };
    mutable std::mutex m_mutex;
    std::map<std::string, Entry> m_entries;

    // Populate @p opts.attempt / @p opts.lastError from THIS OPERATION's retry
    // context, iff it has recorded a rejection. Leaves @p opts untouched on a
    // context with no history -- the first prompt of a fresh operation is
    // always cold. `attempt` numbers the prompt about to be shown (one past
    // the rejections already recorded).
    static void applyRetryContext(const AttemptContext& attempts, PromptOptions& opts);
};

template <typename PrompterT>
LibreSCRS::Auth::CredentialResult
CredentialCache::requestCredential(const std::string& cardKey, const LibreSCRS::Auth::AuthRequirement& req,
                                   PrompterT& prompter, const PromptOptions& options, std::atomic<bool>* prompterFailed,
                                   std::atomic<bool>* userCancelled, MrzChoiceSink* mrzChoice,
                                   std::atomic<bool>* entryExpired, std::atomic<bool>* helperTooOld,
                                   AttemptContext* attempts)
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
    // BOTH paths, so the cache stays a raw-payload cache (the renegotiation
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
        // THIS operation's own captured generation (@p attempts, if any) has
        // fallen behind the card's current refusal generation: an earlier
        // window for this card already closed empty -- expired or cancelled
        // -- since @p attempts was constructed, and this call would
        // otherwise raise a second one. Refused instead, reporting the SAME
        // outcome (EntryExpired / UserCancelled) that earlier window closed
        // with, not a generic failure -- see @ref RefusalKind.
        //
        // In practice this fires WITHIN one operation: the middleware
        // re-invokes the credential provider with the SAME @p attempts after
        // its own window closes empty, and that object's generation is fixed
        // at construction (see @ref AttemptContext), so the re-invocation
        // reads behind and is silenced here -- bounding what would otherwise
        // be an unbounded re-prompt loop for a single read. It does NOT yet
        // reach a genuinely different operation that was already queued when
        // the refusal happened: one card's operations are dequeued and run
        // strictly one at a time, so such an operation only constructs its
        // own AttemptContext -- capturing the generation -- once it is
        // dequeued, by which point the earlier refusal is already reflected
        // in what it captures, and it reads as current, not behind.
        //
        // AFTER the cache hit, deliberately, exactly like the cap below: this
        // refuses to ASK, never to ANSWER. Moved above the hit it would break
        // the SUCCESS path -- the queued verbs a freshly entered CAN should
        // serve silently would fail instead.
        //
        // Sets no "the last prompt yielded nothing" flag of its own, and must
        // not: this operation raised no window, so it has nothing to report
        // about one. The refusal that bumped the generation already recorded
        // that flag -- both branches below that call noteRefusal set it first
        // -- so the eviction guard one layer up (see
        // FlowPrelude::isCardRejectionSignal) already reads true here.
        auto silenced = [&]() -> CredentialResult {
            if (lastRefusalKindFor(cardKey) == RefusalKind::Cancelled) {
                if (userCancelled != nullptr) {
                    userCancelled->store(true, std::memory_order_relaxed);
                }
                return CredentialResult::cancelled();
            }
            if (entryExpired != nullptr) {
                entryExpired->store(true, std::memory_order_relaxed);
            }
            return buildError();
        };
        auto stillWanted = [&]() { return stillWantedFor(cardKey, attempts); };
        if (!stillWanted()) {
            return silenced();
        }
        // Retry bound for PACE secrets. A CAN is not counted by the document, and
        // the watchdog no longer bounds the retry cycle (it is disarmed while the
        // holder types), so without this the cycle is unlimited. After the cache
        // hit on purpose: the cap refuses to ASK, never to answer.
        //
        // Only Can and Mrz reach here. A PIN must not: the CARD owns that counter
        // and a software cap disagreeing with it is worse than none.
        //
        // The count lives on @p attempts, THIS OPERATION's own retry context --
        // not on the card. Every production caller reaches here with a real
        // one; a null context means no cap at all (cold prompt, gate off) and
        // exists for callers with no per-operation context to charge, not for
        // PIN specifically -- PIN never reaches this branch on any path.
        if (attempts != nullptr && attempts->attempts() >= Operations::kMaxPaceAttempts) {
            return CredentialResult::error(LibreSCRS::Auth::ErrorKeys::preReadAuthFailed());
        }
        PromptOptions promptOpts = options;
        if (attempts != nullptr) {
            applyRetryContext(*attempts, promptOpts);
        }
        const auto prompt = (prompter.*promptFn)(promptOpts);
        // The prompter call above can itself be a long wait: production wraps
        // it in a per-card serializer that queues same-card operations behind
        // one live dialog (a SEPARATE gate this cache knows nothing about).
        // This operation could have sat queued there while a SIBLING's window
        // closed -- the serializer's own re-check (built from the same
        // stillWanted the caller wires into it) stops the second window from
        // EVER being raised in that case, but whatever placeholder result
        // comes back from that short-circuit must still be mapped to the
        // right outcome, not processed as if a real round trip happened. So
        // re-run the SAME check the pre-dispatch gate above ran -- but ONLY
        // when the prompt yielded NOTHING. A prompt that answered Ok WITH a
        // secret is exactly what the pre-dispatch gate's placement exists to
        // protect: refuse to ASK, never to ANSWER (the same invariant
        // ACacheHitSurvivesTheGate pins for the cache-hit path). A sibling
        // that never touches the prompter at all -- cancelled while queued,
        // or before it ever reached the queue (CancelCurrent, watchdog,
        // reader removal, shutdown drain) -- can bump the generation at ANY
        // moment during THIS operation's own live dialog; discarding a
        // correctly collected secret because of that would be the exact
        // dishonesty this whole gate exists to remove, just relocated to the
        // answer side. If the generation has ALREADY moved past what this
        // operation captured AND this prompt yielded nothing of its own,
        // this is not a NEW refusal (no window of THIS operation's own was
        // ever answered), so no further noteRefusal -- just report what the
        // operation that actually prompted reported.
        if ((prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) && !stillWanted()) {
            return silenced();
        }
        if (prompt.status == PromptStatus::Cancelled) {
            if (userCancelled != nullptr) {
                userCancelled->store(true, std::memory_order_relaxed);
            }
            // A dismissed window collected NOTHING, exactly like one the clock
            // closed, and the flag says precisely that. The card is handed no
            // secret either way, its activation fails either way, and it
            // re-invokes carrying the same rejection reason a genuinely wrong
            // value earns. Recording only the clock half left one dismissal
            // reading as a rejection everywhere above this cache: a value the
            // holder never entered evicted, one of the three PACE attempts
            // spent on it, and the next dialog telling them their entry was
            // not accepted.
            noteLastPromptYieldedNothing(cardKey, true);
            noteRefusal(cardKey, RefusalKind::Cancelled);
            return CredentialResult::cancelled();
        }
        if (prompt.status != PromptStatus::Ok || !prompt.secret.has_value()) {
            if (prompterFailed != nullptr && prompt.status == PromptStatus::Error) {
                prompterFailed->store(true, std::memory_order_relaxed);
            }
            // The clock closed the window: nobody cancelled and the card
            // rejected nothing, so neither of those codes may be reported.
            if (prompt.status == PromptStatus::Timeout) {
                if (entryExpired != nullptr) {
                    entryExpired->store(true, std::memory_order_relaxed);
                }
                noteLastPromptYieldedNothing(cardKey, true);
                noteRefusal(cardKey, RefusalKind::Timeout);
            }
            // Refused before the window was ever raised: a capability gap, and
            // the one outcome here whose remedy the holder can act on.
            if (helperTooOld != nullptr && prompt.status == PromptStatus::HelperTooOld) {
                helperTooOld->store(true, std::memory_order_relaxed);
            }
            return buildError();
        }
        // A prompt that ANSWERED clears the signal, per card and per run: it
        // means "the last prompt for this card yielded nothing", and this one
        // did not. Without the clear, a wrong value entered after an earlier
        // expiry would never be marked wrong.
        if (entryExpired != nullptr) {
            entryExpired->store(false, std::memory_order_relaxed);
        }
        noteLastPromptYieldedNothing(cardKey, false);
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
