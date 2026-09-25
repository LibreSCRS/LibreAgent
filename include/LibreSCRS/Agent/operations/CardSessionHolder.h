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

    /// @brief Secure-channel probe seam: answers whether the given session
    ///        currently carries a live secure channel. Default wiring is
    ///        CardSession::hasLiveSecureChannel; tests inject a fixed answer.
    ///        Read only by acquireHold(), which must not power-cycle a reader
    ///        whose logical session is mid-channel.
    /// @note  The default answer is the agent's own record of the channel it
    ///        established, never a question put to the card: after a
    ///        suspend/resume or a reset by another PC/SC client it can read
    ///        live while the card is unpowered. acquireHold() then skips the
    ///        reconnect that would have re-powered it, which is why the skip
    ///        is also bounded by the idle window — one window later the hold
    ///        is taken regardless of what the probe says.
    using SmProbe = std::function<bool(const LibreSCRS::SmartCard::CardSession&)>;

    /// @brief Idle window: a held session untouched for at least this long is
    ///        closed by closeIfIdle(). Also serves as the worker's bounded
    ///        cv wait cap so an idle reader is swept within one window.
    static constexpr auto kIdleClose = std::chrono::seconds{45};

    /// @param clock Optional clock seam; when empty, defaults to
    ///        steady_clock::now. The trailing default keeps existing four-arg
    ///        construction compiling unchanged.
    CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                      std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock = {});

    /// @param smProbe Secure-channel probe seam; when empty, defaults to
    ///        CardSession::hasLiveSecureChannel. Overload rather than a sixth
    ///        defaulted parameter so the five-argument form above keeps its own
    ///        symbol and every existing caller links unchanged.
    CardSessionHolder(std::string readerName, SessionFactory factory, CandidateResolver resolver,
                      std::shared_ptr<LibreSCRS::SmartCard::CardMap> sharedMap, Clock clock, SmProbe smProbe);

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
    /// @note Not to be composed with acquireHold() inside one sweep: the two
    ///       read the clock separately and test complementary halves of the
    ///       same idle boundary, so a crossing between the two readings answers
    ///       both and leaves the reader with no handle.
    ///       renewHoldAndCloseIfIdle() is that composition, done once.
    void closeIfIdle() noexcept;

    /// @brief Full resolution from the held session: candidate plugin list,
    ///        the union of their declared capabilities, and the pre-read auth
    ///        method. Reuses CapabilityResolver::CardResolution. Opens the
    ///        session if not already open; returns a default-constructed
    ///        resolution (empty candidates, caps 0, None) on open failure.
    ///        Worker-thread only.
    [[nodiscard]] CapabilityResolver::CardResolution fullResolution() noexcept;

    /// @brief Power hold: open a second, bare CardSession on this reader and keep
    ///        it until releaseHold(). It is never returned from acquire(), never
    ///        handed to a plugin, and never transmits; its only effect is to keep
    ///        the PC/SC handle — and so the card's power — alive, which starves
    ///        the contactless twin of a dual-interface card so its slot stops
    ///        reporting a phantom insert/remove. Opened through the same
    ///        SessionFactory as the logical session (CardSession::open is a bare
    ///        SCardConnect). A failed open leaves no hold; the caller retries at
    ///        its next sweep. Worker-thread only, like every other method here.
    /// @note The hold-changed path calls this on its own, which is correct: no
    ///       idle close follows it. Do not pair it with closeIfIdle() in one
    ///       sweep — see that method's note and renewHoldAndCloseIfIdle().
    void acquireHold() noexcept;

    /// @brief Drop the power hold if present (the CardSession destructor
    ///        disconnects with SCARD_LEAVE_CARD). No-op without a hold.
    ///        Worker-thread only.
    void releaseHold() noexcept;

    /// @brief The idle sweep, as one step: drop the power hold, take it again
    ///        when @p holdWanted, then close the logical session if it has
    ///        gone idle — in that order, and judged against ONE reading of the
    ///        clock.
    ///
    /// The order is the point, and the claim it earns is narrow. Renewing the
    /// hold before the close means the logical session is still standing while
    /// the new hold opens, so closing the session never adds a moment with no
    /// handle on the reader. It does NOT mean the reader always has one:
    /// releaseHold() runs first and unconditionally, so a reader carrying only
    /// a hold — the ordinary state once its session has idle-closed — is at
    /// zero handles until the factory returns. That gap is the renewal's own,
    /// two pcscd calls wide, and is the one the power hold was measured
    /// against; it is not widened by the close.
    ///
    /// The single reading is the other half of the same property. acquireHold()
    /// declines while the session is younger than kIdleClose and closeIfIdle()
    /// acts once it is at least that old: complementary against one instant, so
    /// exactly one of them fires. Read the clock twice and the boundary can
    /// fall in between — the hold declined AND the session closed, leaving the
    /// reader with nothing until the next sweep.
    ///
    /// Worker-thread only, like every other method here. A throwing clock is
    /// degraded to a missed sweep; the next one retries.
    void renewHoldAndCloseIfIdle(bool holdWanted) noexcept;

    /// @brief Test seam: whether a power hold is currently held.
    [[nodiscard]] bool hasHoldForTest() const noexcept
    {
        return m_hold != nullptr;
    }

private:
    /// @brief acquireHold() / closeIfIdle() against a caller-supplied instant,
    ///        so one sweep can give both the same one. The public no-argument
    ///        forms read the clock themselves and delegate here.
    void acquireHoldAt(std::chrono::steady_clock::time_point now) noexcept;
    void closeIfIdleAt(std::chrono::steady_clock::time_point now) noexcept;

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
    SmProbe m_smProbe;
    std::chrono::steady_clock::time_point m_lastUsed{}; // stamped on every acquire
    // Power hold (see acquireHold). Deliberately a separate slot from
    // m_session: invalidate()/closeIfIdle() must never drop it, and it must
    // never be resolved or handed out.
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> m_hold;
};

} // namespace LibreSCRS::Agent::Operations
