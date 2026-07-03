// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>

#include <LibreSCRS/Plugin/CardPlugin.h> // clearCredentials on teardown

#include <utility>

namespace LibreSCRS::Agent::Operations {

CardSessionHolder::CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                                     std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock)
    : m_readerName(std::move(readerName)), m_factory(std::move(factory)), m_resolver(std::move(resolver)),
      m_sharedMap(std::move(sharedMap)),
      m_clock(clock ? std::move(clock) : Clock{[] { return std::chrono::steady_clock::now(); }})
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
        if (!m_session) {
            return;
        }
        if (m_clock() - m_lastUsed >= kIdleClose) {
            invalidate(); // noexcept
        }
    } catch (...) {
        // leave the session held; the next closeIfIdle() will retry
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

} // namespace LibreSCRS::Agent::Operations
