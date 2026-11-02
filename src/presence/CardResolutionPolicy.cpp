// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/CardResolutionPolicy.h>

#include <LibreSCRS/Agent/operations/CardTypeArbitration.h>

#include <algorithm>
#include <utility>

namespace LibreSCRS::Agent {

CardResolutionPolicy::CardResolutionPolicy(ResolveRetryBudget budget, RetryPredicate retryOn)
    : m_budget(budget), m_retryOn(retryOn ? std::move(retryOn) : RetryPredicate{retryEveryFailedOpen})
{}

CardProbe CardResolutionPolicy::probe(Operations::CardSessionHolder& holder)
{
    auto resolved = holder.fullResolution();
    if (!resolved) {
        CardProbe failed;
        failed.openFailure = std::move(resolved.error());
        return failed;
    }
    return CardProbe{
        .openFailure = std::nullopt,
        .capabilities = resolved->capabilities,
        .preReadAuth = resolved->preReadAuth,
        .cardType = arbitrateCardType(resolved->candidates),
    };
}

bool CardResolutionPolicy::probeOnWorker(Operations::OperationManager& operations, ObjectId reader,
                                         const std::string& readerName, std::function<void(CardProbe)> onProbed)
{
    return operations.enqueueOnReaderWorker(
        reader, readerName,
        [onProbed = std::move(onProbed)](Operations::CardSessionHolder& holder) { onProbed(probe(holder)); });
}

std::optional<std::chrono::milliseconds> CardResolutionPolicy::nextRetry(const ResolveAttempts& attempts) const noexcept
{
    if (attempts.retries >= m_budget.maxRetries || attempts.waited >= m_budget.totalBudget) {
        return std::nullopt;
    }
    auto delay = std::min(m_budget.firstDelay, m_budget.maxDelay);
    for (int i = 0; i < attempts.retries && m_budget.growth > 1 && delay < m_budget.maxDelay; ++i) {
        // Compared before multiplying, so a large growth cannot overflow.
        delay = delay > m_budget.maxDelay / m_budget.growth ? m_budget.maxDelay : delay * m_budget.growth;
    }
    return std::min(delay, m_budget.maxDelay);
}

std::optional<std::chrono::milliseconds> CardResolutionPolicy::retryAfter(const CardProbe& probe,
                                                                          ResolveAttempts& attempts) const
{
    if (probe.opened() || !m_retryOn(*probe.openFailure)) {
        return std::nullopt;
    }
    const auto delay = nextRetry(attempts);
    if (delay) {
        ++attempts.retries;
        attempts.waited += *delay;
    }
    return delay;
}

bool CardResolutionPolicy::holdsReader(const CardProbe& probe, const PresenceRoster& roster, const std::string& cardKey)
{
    return probe.capabilities != 0 && isContactSlotOfDualInterfaceUnit(roster, cardKey);
}

} // namespace LibreSCRS::Agent
