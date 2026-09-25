// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>

#include <LibreSCRS/Plugin/CardPlugin.h> // clearCredentials on teardown

#include <utility>

namespace LibreSCRS::Agent::Operations {

// Both constructors are defined out of line on purpose: an inline body would
// emit no symbol of its own, and the archive's symbol table is what the ABI
// baseline records.
CardSessionHolder::CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                                     std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock)
    : CardSessionHolder(std::move(readerName), std::move(factory), std::move(resolver), std::move(sharedMap),
                        std::move(clock), SmProbe{})
{}

CardSessionHolder::CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                                     std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock,
                                     SmProbe smProbe)
    : m_readerName(std::move(readerName)), m_factory(std::move(factory)), m_resolver(std::move(resolver)),
      m_sharedMap(std::move(sharedMap)),
      m_clock(clock ? std::move(clock) : Clock{[] { return std::chrono::steady_clock::now(); }}),
      m_smProbe(smProbe ? std::move(smProbe) : SmProbe{[](const LibreSCRS::SmartCard::CardSession& s) noexcept {
          return s.hasLiveSecureChannel();
      }})
{}

std::expected<AcquiredCard, LibreSCRS::SmartCard::OpenError> CardSessionHolder::acquire()
{
    if (!m_session) {
        auto opened = m_factory(m_readerName);
        if (!opened) {
            return std::unexpected{opened.error()};
        }
        m_session = std::move(*opened);
        m_candidates = m_resolver(m_session->atr(), *m_session);
    }
    // Stamp on every successful acquire (new or reused session) so a busy
    // reader never trips closeIfIdle().
    m_lastUsed = m_clock();
    return AcquiredCard{m_session, m_candidates, m_sharedMap};
}

void CardSessionHolder::invalidate() noexcept
{
    // Wipe ALL per-session credentials the candidate plugins cached for this
    // session BEFORE we drop it: a deposited eSign PIN (the hash-on-card raw-sign
    // path stores it via setCredentials("pin")), an emrtd CAN/MRZ stash, and the
    // pkcs15 requiresPace flag. clearCredentials is the only eraser of that
    // per-session plugin state, and invalidate() is the teardown that runs on
    // card removal (OperationManager worker) and idle close — never between ops
    // within a lease, so within-lease multi-sign consent caching is preserved.
    // const_cast: clearCredentials is non-const but plugins hold the state in
    // mutable, session-keyed maps; the candidate list is shared_ptr<const> for
    // the read-only crypto NVIs.
    if (m_session) {
        for (const auto& plugin : m_candidates) {
            if (plugin) {
                const_cast<LibreSCRS::Plugin::CardPlugin&>(*plugin).clearCredentials(*m_session);
            }
        }
    }
    m_candidates.clear();
    m_preReadAuth.reset();
    m_session.reset();
}

void CardSessionHolder::closeIfIdle() noexcept
{
    // The injected clock is an std::function and could in principle throw;
    // honour the noexcept contract by degrading any escape to a no-op (a missed
    // idle-close is harmless — the next sweep retries).
    try {
        closeIfIdleAt(m_clock()); // noexcept
    } catch (...) {
        // leave the session held; the next closeIfIdle() will retry
    }
}

void CardSessionHolder::closeIfIdleAt(std::chrono::steady_clock::time_point now) noexcept
{
    if (!m_session) {
        return;
    }
    if (now - m_lastUsed >= kIdleClose) {
        invalidate(); // noexcept
    }
}

std::uint32_t CardSessionHolder::capabilities() noexcept
{
    // acquire() invokes the injected factory/resolver std::functions (which may
    // throw) and copies a vector (bad_alloc); honour the noexcept contract by
    // degrading any escape to the documented "0 on failure" result.
    try {
        auto a = acquire();
        if (!a) {
            return 0;
        }
        return unionCapabilities(a->candidates);
    } catch (...) {
        return 0;
    }
}

LibreSCRS::Auth::PreReadAuthMethod CardSessionHolder::preReadAuth() noexcept
{
    using LibreSCRS::Auth::PreReadAuthMethod;
    // acquire() and CardPlugin::preReadAuth() invoke injected std::functions and
    // plugin code that may throw; honour the noexcept contract by degrading any
    // escape to the documented "None on failure" result.
    try {
        if (m_preReadAuth) {
            return *m_preReadAuth;
        }
        auto acquired = acquire();
        if (!acquired) {
            return PreReadAuthMethod::None;
        }
        // Strongest pre-read auth: the first candidate that reports a non-None
        // method wins (candidates are priority-ordered); if all report None,
        // the result is None. Memoize for the lifetime of the held session.
        auto method = PreReadAuthMethod::None;
        for (const auto& plugin : acquired->candidates) {
            if (!plugin) {
                continue;
            }
            if (auto m = plugin->preReadAuth(*acquired->session); m != PreReadAuthMethod::None) {
                method = m;
                break;
            }
        }
        m_preReadAuth = method;
        return method;
    } catch (...) {
        return PreReadAuthMethod::None;
    }
}

CapabilityResolver::CardResolution CardSessionHolder::fullResolution() noexcept
{
    // Copies the candidate vector and constructs the resolution struct (both may
    // throw bad_alloc); honour the noexcept contract by degrading to an empty
    // resolution (caps 0, None) on failure.
    try {
        auto acquired = acquire();
        if (!acquired) {
            return {};
        }
        return CapabilityResolver::CardResolution{acquired->candidates, unionCapabilities(acquired->candidates),
                                                  preReadAuth()};
    } catch (...) {
        return {};
    }
}

void CardSessionHolder::acquireHold() noexcept
{
    if (m_hold) {
        return;
    }
    // The injected clock is an std::function and may throw; honour the noexcept
    // contract by degrading to "no hold" — the worker retries at its next sweep.
    try {
        acquireHoldAt(m_clock()); // noexcept
    } catch (...) {
        m_hold.reset();
    }
}

void CardSessionHolder::acquireHoldAt(std::chrono::steady_clock::time_point now) noexcept
{
    if (m_hold) {
        return;
    }
    // The injected factory and probe are std::functions and may throw; honour
    // the noexcept contract by degrading to "no hold" — the worker retries at
    // its next sweep.
    try {
        // A second handle buys nothing on a reader whose logical session is
        // already powered AND mid-secure-channel, so skip it — but only while
        // that session is still in use. Once it has gone idle the sweep is
        // about to close it, and the hold is what keeps the card powered
        // across that close: taking it here, BEFORE closeIfIdle runs in the
        // same sweep, is what keeps the handle-free window unchanged.
        if (m_session && m_smProbe(*m_session) && now - m_lastUsed < kIdleClose) {
            return;
        }
        auto opened = m_factory(m_readerName);
        if (opened) {
            m_hold = std::move(*opened);
        }
    } catch (...) {
        m_hold.reset();
    }
}

void CardSessionHolder::releaseHold() noexcept
{
    m_hold.reset();
}

void CardSessionHolder::renewHoldAndCloseIfIdle(bool holdWanted) noexcept
{
    // ONE reading, handed to both decisions: they test complementary halves of
    // the same idle boundary, so two readings could let the boundary fall
    // between them and answer "no hold" and "close the session" in the same
    // sweep.
    std::chrono::steady_clock::time_point now{};
    try {
        now = m_clock();
    } catch (...) {
        return; // a missed sweep; the next one retries
    }
    releaseHold(); // noexcept
    if (holdWanted) {
        acquireHoldAt(now); // noexcept
    }
    closeIfIdleAt(now); // noexcept
}

} // namespace LibreSCRS::Agent::Operations
