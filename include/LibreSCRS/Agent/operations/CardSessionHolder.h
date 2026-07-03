// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>

// Per-reader session holder: lazily opens one LM CardSession, reuses it across
// acquire() calls (open-once semantics), resolves the candidate plugin list
// once per held session, and can be invalidated (closed) to release the PC/SC
// handle. A reader that sits idle is proactively closed after kIdleClose via
// closeIfIdle() so a stale PACE channel / PC/SC handle is not held forever; the
// next acquire() transparently re-opens. Three injected seams keep this
// card-free testable without any PC/SC daemon or wall clock: SessionFactory,
// CandidateResolver, and a steady Clock are supplied at construction.
namespace LibreSCRS::Agent::Operations {

/// @brief Factory seam: opens or manufactures a CardSession for the named reader.
///        Production wiring: wraps CardSession::open + shared_ptr construction.
///        Test wiring: returns a detached session and counts calls.
using SessionFactory =
    std::function<std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError>(
        const std::string& reader)>;

/// @brief Candidate resolver seam: given a card ATR and an open session,
///        returns the prioritised plugin candidates.
///        Production wiring: wraps CardPluginService::findAllCandidates.
///        Test wiring: returns a canned CandidateList.
using CandidateResolver =
    std::function<CandidateList(std::span<const std::uint8_t> atr, LibreSCRS::SmartCard::CardSession& session)>;

/// @brief Result of a successful acquire(): session handle, plugin candidates,
///        and the shared card-state map passed at construction.
struct AcquiredCard
{
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
    CandidateList candidates;
    std::shared_ptr<LibreSCRS::SmartCard::CardMap> cardMap;
};

/// @brief Per-reader holder for an LM CardSession.
///
/// Owns at most one open CardSession at a time. acquire() returns the held
/// session on repeated calls (open-once); invalidate() closes it so the next
/// acquire() re-opens. The candidate plugin list is resolved exactly once per
/// held session (on the first acquire() after open or re-open).
///
/// Every successful acquire() stamps a last-used time read from the injected
/// Clock. closeIfIdle() invalidates the held session once kIdleClose has
/// elapsed since that stamp, so a reader the agent has stopped touching does
/// not pin a stale PACE channel / PC/SC handle indefinitely. The clock seam is
/// ctor-DI'd (default: steady_clock::now) so tests drive idle timing
/// deterministically without any wall-clock dependency.
class CardSessionHolder
{
public:
    /// @brief Clock seam: returns the current steady time. Default wiring is
    ///        steady_clock::now; tests inject a fake, advanceable clock.
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    /// @brief Idle window: a held session untouched for at least this long is
    ///        closed by closeIfIdle(). Also serves as the worker's bounded
    ///        cv wait cap so an idle reader is swept within one window.
    static constexpr auto kIdleClose = std::chrono::seconds{45};

    /// @param clock Optional clock seam; when empty, defaults to
    ///        steady_clock::now. The trailing default keeps existing four-arg
    ///        construction compiling unchanged.
    CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                      std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock = {});

    /// @brief Open the session if not already open (or after invalidate()), then
    ///        return the held session together with the resolved candidates and
    ///        the shared CardMap. Candidates are resolved once per open session.
    ///        Stamps the last-used time on every successful acquire so a busy
    ///        reader never idle-closes.
    [[nodiscard]] std::expected<AcquiredCard, LibreSCRS::SmartCard::OpenError> acquire();

    /// @brief Close the session and drop the candidate list. The next acquire()
    ///        will re-open via the factory.
    /// @note Outstanding AcquiredCard copies keep the CardSession alive (shared
    ///       ownership) until dropped; a caller must not retain an AcquiredCard
    ///       across invalidate() and expect the handle closed.
    void invalidate() noexcept;

    /// @brief Invalidate the held session if it has been idle for at least
    ///        kIdleClose (measured from the last successful acquire). No-op when
    ///        no session is held or the idle window has not yet elapsed. Must be
    ///        called on the owning worker thread, like the other holder methods.
    void closeIfIdle() noexcept;

    /// @brief Full resolution from the held session: candidate plugin list,
    ///        the union of their declared capabilities, and the pre-read auth
    ///        method. Reuses CapabilityResolver::CardResolution. Opens the
    ///        session if not already open; returns a default-constructed
    ///        resolution (empty candidates, caps 0, None) on open failure.
    ///        Worker-thread only.
    [[nodiscard]] CapabilityResolver::CardResolution fullResolution() noexcept;

private:
    /// @brief Union of all capabilities declared by the held session's candidates.
    ///        Opens the session if not already open. Returns 0 on open failure.
    [[nodiscard]] std::uint32_t capabilities() noexcept;

    /// @brief Strongest pre-read auth requirement among the held session's
    ///        candidates. Opens the session if not already open, queries each
    ///        candidate's CardPlugin::preReadAuth on the held session and
    ///        returns the first non-None method (else None). The result is
    ///        memoized for the lifetime of the held session and cleared by
    ///        invalidate(); a re-opened session re-resolves it. Returns None on
    ///        open failure. Worker-thread only (like the other holder methods).
    [[nodiscard]] LibreSCRS::Auth::PreReadAuthMethod preReadAuth() noexcept;

    std::string m_readerName;
    SessionFactory m_factory;
    CandidateResolver m_resolver;
    std::shared_ptr<LibreSCRS::SmartCard::CardMap> m_sharedMap;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> m_session; // held open
    CandidateList m_candidates;
    std::optional<LibreSCRS::Auth::PreReadAuthMethod> m_preReadAuth; // memoized per held session
    Clock m_clock;
    std::chrono::steady_clock::time_point m_lastUsed{}; // stamped on every acquire
};

} // namespace LibreSCRS::Agent::Operations
