// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>  // PromptOptions, PromptResult, PromptStatus
#include <LibreSCRS/Agent/backend/PrompterWire.h> // shared pin/can/mrz kind vocabulary
#include <LibreSCRS/Auth/AuthRequirement.h>       // AuthRequirement
#include <LibreSCRS/Auth/CredentialResult.h>      // CredentialResult, CredentialEntry
#include <LibreSCRS/Auth/ErrorKeys.h>             // ErrorKeys::genericComm
#include <LibreSCRS/Auth/PaceSecretKind.h>        // PaceSecretKind
#include <LibreSCRS/Secure/String.h>
#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace LibreSCRS::Agent {
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
    template <typename PrompterT>
    [[nodiscard]] LibreSCRS::Auth::CredentialResult
    requestCredential(const std::string& cardKey, const LibreSCRS::Auth::AuthRequirement& req, PrompterT& prompter,
                      const PromptOptions& options, std::atomic<bool>* prompterFailed = nullptr,
                      std::atomic<bool>* userCancelled = nullptr);

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
                                   std::atomic<bool>* userCancelled)
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

    // The plugin's activation path establishes a PACE/BAC channel, so the
    // requirement carries the secret kind it needs. CAN and MRZ are the only
    // cacheable pre-read secrets; PIN/PUK (or an absent kind) are routed to an
    // error because PIN is never cached and the agent's pre-read flow does not
    // collect PIN-as-PACE-password here.
    const auto kind = req.paceKind();
    if (!kind.has_value()) {
        return buildError();
    }
    switch (*kind) {
    case PaceSecretKind::Can: {
        if (auto cached = getCan(cardKey)) {
            return buildOk(PrompterWire::kKindCan, *cached);
        }
        PromptOptions promptOpts = options;
        applyRetryContext(cardKey, promptOpts);
        const auto prompt = prompter.requestCan(promptOpts);
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
            return buildError();
        }
        putCan(cardKey, *prompt.secret);
        return buildOk(PrompterWire::kKindCan, *prompt.secret);
    }
    case PaceSecretKind::Mrz: {
        if (auto cached = getMrz(cardKey)) {
            return buildOk(PrompterWire::kKindMrz, *cached);
        }
        PromptOptions promptOpts = options;
        applyRetryContext(cardKey, promptOpts);
        const auto prompt = prompter.requestMrz(promptOpts);
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
            return buildError();
        }
        putMrz(cardKey, *prompt.secret);
        return buildOk(PrompterWire::kKindMrz, *prompt.secret);
    }
    case PaceSecretKind::Pin:
    case PaceSecretKind::Puk:
        return buildError();
    }
    return buildError();
}

} // namespace LibreSCRS::Agent
