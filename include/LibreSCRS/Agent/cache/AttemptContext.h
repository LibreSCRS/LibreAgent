// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

/// @brief Retry context for ONE read attempt: how many collected secrets the
///        card rejected during it, and why the last rejection happened.
///
/// Attempts are a property of one attempt at reading, not of the card. Holding
/// them per card made three verbs dispatched together spend each other's
/// allowance, and made a rejection outlive the operation that earned it -- so a
/// card could run out of attempts across unrelated reads and stop prompting
/// entirely. The design this restores says "3 attempts per operation".
///
/// The card's own state (the cached CAN/MRZ, and the refusal generation the
/// prompt gate reads) stays in @ref CredentialCache, where it belongs.
///
/// Thread-safe: @ref recordRejection, @ref attempts and @ref lastErrorKey are
/// guarded by an internal mutex, so the flow that owns this object and the
/// credential provider it installs may call them from different threads on
/// the shutdown keep-alive path. @ref generationAtDispatch needs no lock: the
/// constructor fixes it for the object's entire lifetime.
///
/// @since 4.3
class AttemptContext
{
public:
    /// @p generationAtDispatch is the card's refusal generation as it stood
    /// when this context was constructed. Captured HERE, in the constructor,
    /// and nowhere else -- there is no setter, so nothing can refresh it to a
    /// value read at prompt time.
    ///
    /// WHERE this object is constructed is therefore the whole mechanism, and
    /// it decides what the prompt gate can see. Constructed at the top of a
    /// flow's run(), as every caller does today, it bounds the re-prompt loop
    /// WITHIN one operation: after a window closes empty, the middleware's
    /// activation fails and it invokes the credential provider again, and that
    /// invocation finds the card's generation already past what this object
    /// holds, so no fresh window is raised. It does NOT yet reach a SIBLING
    /// operation: one card's operations are dequeued and run strictly one at a
    /// time, so an operation that was already queued when another's window
    /// closed builds its context AFTER that refusal and reads an equal
    /// generation. Closing that needs the capture to move to where the
    /// operation is created and published, which is above this library.
    ///
    /// Defaults to 0 so a test that does not care about the generation can
    /// still write a bare `AttemptContext ctx;`.
    explicit AttemptContext(std::uint64_t generationAtDispatch = 0) noexcept
        : m_generationAtDispatch(generationAtDispatch)
    {}

    /// The card rejected a secret that WAS collected. Never call this for an
    /// expired or cancelled prompt: nothing was presented, so nothing was
    /// rejected.
    void recordRejection(std::string msgKey)
    {
        const std::lock_guard lock(m_mutex);
        ++m_attempts;
        m_lastErrorKey = std::move(msgKey);
    }

    [[nodiscard]] std::uint32_t attempts() const
    {
        const std::lock_guard lock(m_mutex);
        return m_attempts;
    }

    [[nodiscard]] std::string lastErrorKey() const
    {
        const std::lock_guard lock(m_mutex);
        return m_lastErrorKey;
    }

    [[nodiscard]] std::uint64_t generationAtDispatch() const noexcept
    {
        return m_generationAtDispatch;
    }

private:
    mutable std::mutex m_mutex;
    std::uint32_t m_attempts = 0;
    std::string m_lastErrorKey;
    // Set once, in the constructor's init-list, and never again: the
    // compiler enforces "written once" instead of a comment asserting it, so
    // this field genuinely needs no lock.
    const std::uint64_t m_generationAtDispatch;
};

} // namespace LibreSCRS::Agent
