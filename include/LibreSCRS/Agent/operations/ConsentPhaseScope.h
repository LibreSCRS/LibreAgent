// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/OperationPhase.h>   // OperationPhase
#include <LibreSCRS/Agent/operations/Seams.h> // OperationPhaseSink
#include <cstdint>

namespace LibreSCRS::Agent::Operations {

/// Borrows the operation's phase for a human interaction and gives it back.
///
/// Entering AwaitingConsent disarms the per-op watchdog, which is what stops the
/// holder from being timed. Leaving it must re-arm, or the card I/O that follows
/// the prompt runs with no bound at all -- and an unbounded SCardTransmit is the
/// exact hazard the watchdog exists for.
///
/// A scope rather than a pair of calls: the obligation to return the phase then
/// cannot be forgotten at any of the sites that raise a prompt. It also survives
/// the paths a trailing call cannot see -- the read credential provider's prompt
/// body is wrapped in a catch-all that turns any throw into an error result, so
/// a phase handed back only on the normal return would stay in AwaitingConsent
/// for every throwing path, with the watchdog still disarmed while the driver
/// walks on to its next candidate.
///
/// Restores Authenticating, not the phase that was current on entry: consent is
/// always followed by the card checking the secret that was just collected, and
/// re-entering an arming phase is the point -- it starts a FRESH full budget
/// rather than resuming a remainder that would depend on how long the holder
/// took to type.
///
/// Construct on the stack, on the worker thread, for the duration of one prompt.
///
/// @since 4.3
class ConsentPhaseScope
{
public:
    explicit ConsentPhaseScope(OperationPhaseSink& sink) noexcept : m_sink(sink)
    {
        m_sink.setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
    }
    ~ConsentPhaseScope()
    {
        m_sink.setPhase(static_cast<std::uint32_t>(OperationPhase::Authenticating));
    }
    ConsentPhaseScope(const ConsentPhaseScope&) = delete;
    ConsentPhaseScope& operator=(const ConsentPhaseScope&) = delete;
    ConsentPhaseScope(ConsentPhaseScope&&) = delete;
    ConsentPhaseScope& operator=(ConsentPhaseScope&&) = delete;

private:
    OperationPhaseSink& m_sink;
};

} // namespace LibreSCRS::Agent::Operations
