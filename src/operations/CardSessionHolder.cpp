// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>

#include <LibreSCRS/Auth/ErrorKeys.h>    // genericComm (a resolution that threw)
#include <LibreSCRS/Plugin/CardPlugin.h> // clearCredentials on teardown

#include <utility>

namespace LibreSCRS::Agent::Operations {

CardSessionHolder::CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                                     Clock clock)
    : m_readerName(std::move(readerName)), m_factory(std::move(factory)), m_resolver(std::move(resolver)),
      m_clock(clock ? std::move(clock) : Clock{[] { return std::chrono::steady_clock::now(); }})
{}

std::expected<AcquiredCard, LibreSCRS::SmartCard::OpenError> CardSessionHolder::acquire()
{
    if (!m_session) {
        std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
        if (m_hold) {
            // Promote: the parked connection serves the operation again. It
            // carries no secrets (demote erased them), so the candidates are
            // resolved afresh by the same resolver -- the same union of plugins.
            session = std::move(m_hold);
        } else {
            auto opened = m_factory(m_readerName);
            if (!opened) {
                return std::unexpected{opened.error()};
            }
            session = std::move(*opened);
        }
        // Resolve before committing: a resolver that throws must leave no
        // session behind, or every later acquire would reuse it with an empty
        // candidate list and never resolve again. The local closes the
        // connection on the way out; the next acquire starts over.
        CandidateList candidates = m_resolver(session->atr(), *session);
        m_session = std::move(session);
        m_candidates = std::move(candidates);
    }
    // Stamp on every successful acquire (new or reused session) so a busy
    // reader is never swept.
    m_lastUsed = m_clock();
    return AcquiredCard{m_session, m_candidates};
}

void CardSessionHolder::eraseCredentials() noexcept
{
    // clearCredentials is the only eraser of the per-session state the
    // candidate plugins cache: a deposited eSign PIN (the hash-on-card
    // raw-sign path stores it via setCredentials("pin")), an emrtd CAN/MRZ
    // stash, and the pkcs15 requiresPace flag. It runs only at the end of a
    // session's use -- card removal, idle close, demote -- never between ops
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
}

void CardSessionHolder::invalidate() noexcept
{
    eraseCredentials(); // before the session goes
    m_session.reset();
    m_hold.reset();
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

std::expected<CapabilityResolver::CardResolution, LibreSCRS::SmartCard::OpenError>
CardSessionHolder::fullResolution() noexcept
{
    try {
        auto acquired = acquire();
        if (!acquired) {
            return std::unexpected{std::move(acquired.error())};
        }
        if (acquired->candidates.empty()) {
            // No plugin serves this card: holding its session would only keep
            // the reader taken for kIdleClose. The next operation re-opens.
            invalidate(); // noexcept
            return CapabilityResolver::CardResolution{};
        }
        return CapabilityResolver::CardResolution{acquired->candidates, unionCapabilities(acquired->candidates),
                                                  preReadAuth()};
    } catch (...) {
        // A seam that throws (the factory, the resolver) or an allocation that
        // fails has not told us what the card is: report it the way a failed
        // open is reported, so the caller asks again.
        return std::unexpected{LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ProtocolError,
                                                               LibreSCRS::Auth::ErrorKeys::genericComm(),
                                                               std::string{"card resolution threw"}}};
    }
}

void CardSessionHolder::acquireHold() noexcept
{
    // Never a second connection: with a session in use the hold is applied by
    // the sweep that finds it idle (demote).
    if (m_hold || m_session) {
        return;
    }
    // The injected factory is an std::function and may throw; honour the
    // noexcept contract by degrading to "no hold" — the worker retries at its
    // next sweep.
    try {
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

void CardSessionHolder::demote() noexcept
{
    // A session that ran secure messaging is not parked. Clearing the host's
    // side of the channel leaves the CHIP mid-session -- it still expects
    // protected APDUs under keys nobody holds any more -- and a held connection
    // keeps it powered in that state. Close it instead; the next operation
    // opens a fresh connection and the card starts from its reset state.
    if (m_session->hasLiveSecureChannel()) {
        invalidate();
        return;
    }
    // Every secret the session carried goes before the connection is parked:
    // what the candidate plugins deposited for it (a signing PIN, an eMRTD
    // CAN/MRZ), the PACE secrets the session cached, and the secure channel.
    eraseCredentials();
    m_session->clearCachedPaceCredentials();
    m_session->clearActiveChannel();
    m_hold = std::move(m_session);
}

void CardSessionHolder::sweep(bool holdWanted) noexcept
{
    // ONE reading: the idle test and what follows from it are decided against
    // the same instant.
    std::chrono::steady_clock::time_point now{};
    try {
        now = m_clock();
    } catch (...) {
        return; // a missed sweep; the next one retries
    }
    if (m_session) {
        if (now - m_lastUsed < kIdleClose) {
            return; // in use: left alone
        }
        if (holdWanted) {
            demote(); // noexcept
        } else {
            invalidate(); // noexcept
        }
        return;
    }
    if (holdWanted) {
        acquireHold(); // noexcept; opens only when the reader has no connection
    }
}

} // namespace LibreSCRS::Agent::Operations
