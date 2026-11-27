// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

/// @brief A card's refusal generation as read when an operation was published.
///
/// A distinct type, with no default, so an operation cannot be handed a bare
/// number or forget to carry one: the only way to build an @ref AttemptContext
/// is from this, and the only way to build this is to name the value.
///
/// @since 5.0
class PublishedRefusalGeneration
{
public:
    explicit PublishedRefusalGeneration(std::uint64_t generation) noexcept : m_value(generation) {}

    [[nodiscard]] std::uint64_t value() const noexcept
    {
        return m_value;
    }

private:
    std::uint64_t m_value;
};

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
/// @since 5.0
class AttemptContext
{
public:
    /// generationAtDispatch() is the card's refusal generation as it stood
    /// when the operation was PUBLISHED, handed in by the caller and fixed
    /// for the object's lifetime -- there is no setter, so nothing can refresh
    /// it to a value read at prompt time.
    ///
    /// Reading it at publish is the whole mechanism. After a window closes
    /// empty, the middleware's activation fails and it invokes the credential
    /// provider again; that invocation finds the card's generation already
    /// past what this object holds, so no fresh window is raised. The same
    /// holds for a SIBLING operation: one card's operations run strictly one
    /// at a time, but each was published before the earlier one's window
    /// closed, so it carries the older generation and is silenced too.
    ///
    /// There is no default and no bare-number overload: a caller must name the
    /// generation it carries.
    explicit AttemptContext(PublishedRefusalGeneration published) noexcept : m_generationAtDispatch(published.value())
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
