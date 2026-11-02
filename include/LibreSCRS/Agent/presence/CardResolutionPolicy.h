// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // ObjectId
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/value/ReaderLabels.h> // PresenceRoster
#include <LibreSCRS/Auth/AuthRequirement.h>     // PreReadAuthMethod
#include <LibreSCRS/SmartCard/CardSession.h>    // OpenError

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace LibreSCRS::Agent {

/// What one insertion probe learned about a card, taken on the reader's worker
/// from the session the probe opened.
///
/// @since 5.0
struct CardProbe
{
    /// Set when the probe could not open the card. Nothing is then known about
    /// it, and the other fields are empty.
    std::optional<LibreSCRS::SmartCard::OpenError> openFailure;
    /// Union of what the plugins that serve the card declare; 0 when none
    /// does, which is an answer, not a failure.
    std::uint32_t capabilities{0};
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth{LibreSCRS::Auth::PreReadAuthMethod::None};
    /// arbitrateCardType() over the probe's candidates; empty when not known.
    std::string cardType;

    [[nodiscard]] bool opened() const noexcept
    {
        return !openFailure.has_value();
    }
};

/// How often, and for how long, a card the probe could not open is asked
/// about again. The n-th wait (from 0) is @c firstDelay × @c growth^n, never
/// more than @c maxDelay; asking stops after @c maxRetries waits, or once the
/// waits add up to @c totalBudget, whichever comes first. The defaults are
/// three quick repeats, which is what shared PC/SC access needs: an open lost
/// to another process's transaction succeeds a moment later. A host whose
/// sessions are exclusive (another prober may hold the card for seconds) sets
/// a growing schedule bounded by a total instead.
///
/// @since 5.0
struct ResolveRetryBudget
{
    int maxRetries{3};
    std::chrono::milliseconds firstDelay{50};
    int growth{1};
    std::chrono::milliseconds maxDelay{50};
    std::chrono::milliseconds totalBudget{std::chrono::milliseconds::max()};
};

/// A pending card's progress through its budget. The host keeps one beside
/// each card it has not published yet; the policy advances it.
///
/// @since 5.0
struct ResolveAttempts
{
    int retries{0};
    std::chrono::milliseconds waited{0};
};

/// The one rule for a freshly inserted card: probe it on its reader's worker,
/// ask again only when the probe could not open it, and once it is answered
/// decide whether publishing it takes the reader's power hold.
///
/// A host owns its pending set, its event loop and the object it publishes;
/// everything it decides about the card comes from here, so the hold and the
/// retry behave the same on every platform. The policy holds no per-card
/// state and is safe to share between threads.
///
/// @since 5.0
class CardResolutionPolicy
{
public:
    /// Whether a failed open is worth another try. Consulted only for a probe
    /// that could not open the card.
    using RetryPredicate = std::function<bool(const LibreSCRS::SmartCard::OpenError&)>;

    /// The default predicate: every failed open is asked about again, since
    /// it says nothing about the card.
    [[nodiscard]] static bool retryEveryFailedOpen(const LibreSCRS::SmartCard::OpenError& /*failure*/) noexcept
    {
        return true;
    }

    explicit CardResolutionPolicy(ResolveRetryBudget budget = {}, RetryPredicate retryOn = retryEveryFailedOpen);

    [[nodiscard]] const ResolveRetryBudget& budget() const noexcept
    {
        return m_budget;
    }

    /// Probe the card on @p holder's reader. Worker thread only (the holder
    /// is the worker's). A card no plugin serves is answered here and its
    /// session closed by the holder, so it is never opened again for this
    /// insertion.
    [[nodiscard]] static CardProbe probe(Operations::CardSessionHolder& holder);

    /// Queue probe() on @p reader's worker and hand the result to @p onProbed
    /// ON THAT WORKER THREAD: the host marshals it onto its own loop. False
    /// when the reader's queue is at its cap and nothing was queued; the host
    /// asks again after budget().firstDelay. Throws what
    /// OperationManager::enqueueOnReaderWorker throws.
    [[nodiscard]] static bool probeOnWorker(Operations::OperationManager& operations, ObjectId reader,
                                            const std::string& readerName, std::function<void(CardProbe)> onProbed);

    /// The wait before the next open of a card that has used @p attempts of
    /// the budget, or nullopt when the budget is spent.
    [[nodiscard]] std::optional<std::chrono::milliseconds> nextRetry(const ResolveAttempts& attempts) const noexcept;

    /// Loop side: what to do with @p probe. A wait means "probe again after
    /// it", and @p attempts has been charged for it; nullopt means the card is
    /// answered and is published now with what @p probe says -- an opened
    /// probe, a failure the predicate does not retry, or a spent budget.
    [[nodiscard]] std::optional<std::chrono::milliseconds> retryAfter(const CardProbe& probe,
                                                                      ResolveAttempts& attempts) const;

    /// Whether publishing the card keyed @p cardKey in @p roster takes its
    /// reader's power hold: only a card a plugin serves, and only on the
    /// contact slot of a dual-interface unit. A card no plugin serves has just
    /// been let go by the probe; holding it would take the reader back for a
    /// card the agent cannot use.
    [[nodiscard]] static bool holdsReader(const CardProbe& probe, const PresenceRoster& roster,
                                          const std::string& cardKey);

private:
    ResolveRetryBudget m_budget;
    RetryPredicate m_retryOn;
};

// The reader half of card removal: release the power hold (a no-op for a
// reader that was never held), then invalidate the session. With the card gone
// there is nothing left to keep powered, and the next operation must re-open
// against whatever comes next. The worker drops the hold handle on the
// invalidate as well; clearing the FLAG here keeps a later idle sweep from
// re-acquiring a hold on an empty reader. The worker handles both flags in one
// pass, so the order is a convention, not an observable. A reader that is
// already gone hands this an invalid id, on which both calls are no-ops.
inline void releaseReaderOnCardRemoved(Operations::OperationManager& operations, ObjectId reader)
{
    operations.setReaderHold(reader, false);
    operations.invalidateReaderSession(reader);
}

} // namespace LibreSCRS::Agent
