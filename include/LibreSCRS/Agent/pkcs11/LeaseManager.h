// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // CallerToken, ObjectId
#include <chrono>
#include <map>
#include <mutex>

namespace LibreSCRS::Agent::Pkcs11 {

// Lease scope: the connecting peer's opaque identity (caller) + the card's
// opaque identity (card). Both are neutral newtypes minted by the backend; the
// manager only compares them.
// caller = the CallerToken the wiring layer mints for the connecting peer.
// card   = the ObjectId the backend minted for the inserted card.
struct LeaseKey
{
    CallerToken caller;
    ObjectId card;
    [[nodiscard]] bool operator<(const LeaseKey& o) const noexcept
    {
        return caller < o.caller || (caller == o.caller && card < o.card);
    }
};

struct LeaseConfig
{
    std::chrono::seconds idleTimeout{std::chrono::minutes(10)}; // primary bound
    std::chrono::seconds maxLifetime{std::chrono::hours(8)};    // hard cap; 0 = none
};

// Pure lease state with an injected clock (steady_clock::time_point passed in).
// Thread-safe: a single internal mutex (the agent calls this from the bus
// thread, but card-remove signals may arrive on a monitor thread).
class LeaseManager
{
public:
    explicit LeaseManager(LeaseConfig config) : m_config(config) {}

    // Create/refresh a lease (called on a successful Pkcs11_1.Login). Resets
    // both the idle clock and (on first grant) the lifetime origin.
    void grant(const LeaseKey& key, std::chrono::steady_clock::time_point now);

    // True iff a non-expired lease exists for @p key at @p now.
    [[nodiscard]] bool isActive(const LeaseKey& key, std::chrono::steady_clock::time_point now);

    // If active, bump the idle clock and return true; else false (caller maps to
    // CKR_USER_NOT_LOGGED_IN). Called by SignRaw/Decrypt before the card op.
    [[nodiscard]] bool touch(const LeaseKey& key, std::chrono::steady_clock::time_point now);

    // PIN-as-consent verified state, scoped to the lease (NOT the PIN itself —
    // only a boolean). The raw-crypto flow prompts + verifies the PIN on the
    // first op of a lease, then calls markPinVerified; subsequent ops query
    // isPinVerified and skip the re-prompt (the held channel persists the on-card
    // verified state). Reset to false on grant/revoke so a fresh login always
    // re-verifies. Returns false for an absent lease.
    [[nodiscard]] bool isPinVerified(const LeaseKey& key);
    void markPinVerified(const LeaseKey& key);
    // Reset the lease's verified flag WITHOUT dropping the lease — used by the
    // raw-crypto flow when a verify-skipped op finds the held channel was
    // silently dropped (the lease idle-timeout outlives the holder's idle-close),
    // so the next op re-prompts + re-verifies. No-op for an absent lease.
    void clearPinVerified(const LeaseKey& key);

    void revoke(const LeaseKey& key);             // C_Logout for one (caller,card)
    void revokeCard(ObjectId card);               // card removed
    void revokeCaller(const CallerToken& caller); // last session closed / client disconnect

    [[nodiscard]] std::chrono::seconds idleTimeout() const noexcept
    {
        return m_config.idleTimeout;
    }

private:
    struct Entry
    {
        std::chrono::steady_clock::time_point lastUse;
        std::chrono::steady_clock::time_point origin; // grant time (for maxLifetime)
        bool pinVerified{false};                      // PIN-as-consent verified for this lease
    };
    [[nodiscard]] bool isActiveLocked(const Entry& e, std::chrono::steady_clock::time_point now) const noexcept;

    LeaseConfig m_config;
    std::mutex m_mutex;
    std::map<LeaseKey, Entry> m_leases;
};

} // namespace LibreSCRS::Agent::Pkcs11
