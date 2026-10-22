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
// handle. A reader that sits idle is swept after kIdleClose by sweep() --
// closed, or emptied of its secrets and parked as the power hold -- so a stale
// PACE channel is not held forever; the next acquire() transparently re-opens
// or promotes. Three injected seams keep this
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
/// Clock. sweep() closes or demotes the held session once kIdleClose has
/// elapsed since that stamp, so a reader the agent has stopped touching does
/// not pin a stale PACE channel indefinitely. The clock seam is
/// ctor-DI'd (default: steady_clock::now) so tests drive idle timing
/// deterministically without any wall-clock dependency.
class CardSessionHolder
{
public:
    /// @brief Clock seam: returns the current steady time. Default wiring is
    ///        steady_clock::now; tests inject a fake, advanceable clock.
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    /// @brief Idle window: a session untouched for at least this long is
    ///        closed by sweep(), or demoted into the power hold when a hold is
    ///        wanted. Also serves as the worker's bounded cv wait
    ///        cap so an idle reader is swept within one window.
    static constexpr auto kIdleClose = std::chrono::seconds{45};

    /// @param clock Optional clock seam; when empty, defaults to
    ///        steady_clock::now. The trailing default keeps existing four-arg
    ///        construction compiling unchanged.
    CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                      std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock = {});

    /// @brief Return the reader's session together with the resolved candidates
    ///        and the shared CardMap: the held one; else the power hold,
    ///        promoted back without a new connection; else a session opened
    ///        through the factory. Candidates are resolved once per session
    ///        handed out (again after a promote, with the same resolver, so a
    ///        composite card keeps every plugin it had). Stamps the last-used
    ///        time on every successful acquire so a busy reader never idles.
    [[nodiscard]] std::expected<AcquiredCard, LibreSCRS::SmartCard::OpenError> acquire();

    /// @brief Close the session and drop the candidate list and the power hold:
    ///        the card was removed, so nothing is left to keep powered. The next
    ///        acquire() re-opens via the factory.
    /// @note Outstanding AcquiredCard copies keep the CardSession alive (shared
    ///       ownership) until dropped; a caller must not retain an AcquiredCard
    ///       across invalidate() and expect the handle closed.
    void invalidate() noexcept;

    /// @brief Full resolution from the held session: candidate plugin list,
    ///        the union of their declared capabilities, and the pre-read auth
    ///        method. Reuses CapabilityResolver::CardResolution. Opens the
    ///        session if not already open.
    /// @return The resolution when the card could be probed -- a definitive
    ///         answer. Empty candidates (caps 0, None) mean no plugin serves the
    ///         card, whose session is then closed at once rather than held for
    ///         kIdleClose; asking again would only open it again. The OpenError
    ///         when the session could not be opened (or a seam threw): nothing
    ///         is known about the card, and the caller may ask again.
    ///         Worker-thread only.
    [[nodiscard]] std::expected<CapabilityResolver::CardResolution, LibreSCRS::SmartCard::OpenError>
    fullResolution() noexcept;

    /// @brief Power hold: keep a connection to the card open while no
    ///        operation is using it, so the card stays powered and the
    ///        contactless twin of a dual-interface unit stops reporting a phantom
    ///        insert/remove. The hold is the reader's one session, never a second
    ///        one beside it: this opens a bare session through the factory ONLY
    ///        when the reader has none at all; with a session in use the hold is
    ///        applied by sweep(), which demotes that session once it is idle. A
    ///        failed open leaves no hold; the caller retries at its next sweep.
    ///        Worker-thread only, like every other method here.
    void acquireHold() noexcept;

    /// @brief Drop the power hold if present (the CardSession destructor
    ///        disconnects with SCARD_LEAVE_CARD). The session in use, if any, is
    ///        untouched. Worker-thread only.
    void releaseHold() noexcept;

    /// @brief The idle sweep, judged against ONE reading of the clock. A session
    ///        in use is left alone. An idle session is demoted into the power
    ///        hold when @p holdWanted -- every credential the candidates held for
    ///        it, its cached PACE secrets and its secure channel are erased, and
    ///        the connection is kept only to keep the card powered -- and closed
    ///        otherwise. A reader with no session at all is given its hold when
    ///        one is wanted. So a reader never carries two connections, and while
    ///        a hold is wanted never none. A throwing clock is degraded to a
    ///        missed sweep; the next one retries. Worker-thread only.
    void sweep(bool holdWanted) noexcept;

    /// @brief Test seam: whether a power hold is currently held.
    [[nodiscard]] bool hasHoldForTest() const noexcept
    {
        return m_hold != nullptr;
    }

private:
    /// @brief Erase what the candidates hold for the session -- a deposited
    ///        PIN, an eMRTD CAN/MRZ -- and forget the candidates and the
    ///        memoized pre-read auth. The one eraser for both ends of a
    ///        session's use: invalidate() and demote(). No-op without a session.
    void eraseCredentials() noexcept;

    /// @brief The idle session becomes the power hold, emptied of every secret:
    ///        the candidates' credentials, the cached PACE secrets and the
    ///        secure channel. The connection itself is kept.
    void demote() noexcept;

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
    // Power hold (see acquireHold): the same connection as m_session, parked
    // with no secrets while no operation uses it. Never both set; never
    // resolved or handed out while parked here.
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> m_hold;
};

} // namespace LibreSCRS::Agent::Operations
