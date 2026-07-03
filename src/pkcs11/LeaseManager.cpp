// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>

namespace LibreSCRS::Agent::Pkcs11 {

bool LeaseManager::isActiveLocked(const Entry& e, std::chrono::steady_clock::time_point now) const noexcept
{
    if (now - e.lastUse >= m_config.idleTimeout) {
        return false;
    }
    if (m_config.maxLifetime.count() > 0 && now - e.origin >= m_config.maxLifetime) {
        return false;
    }
    return true;
}

void LeaseManager::grant(const LeaseKey& key, std::chrono::steady_clock::time_point now)
{
    std::lock_guard lock(m_mutex);
    auto it = m_leases.find(key);
    if (it == m_leases.end()) {
        m_leases.emplace(key, Entry{.lastUse = now, .origin = now});
    } else {
        it->second.lastUse = now;       // re-login refreshes idle; origin (lifetime) unchanged
        it->second.pinVerified = false; // a fresh Login is fresh consent: re-verify the PIN next op
    }
}

bool LeaseManager::isActive(const LeaseKey& key, std::chrono::steady_clock::time_point now)
{
    std::lock_guard lock(m_mutex);
    auto it = m_leases.find(key);
    if (it == m_leases.end()) {
        return false;
    }
    if (!isActiveLocked(it->second, now)) {
        m_leases.erase(it); // lazy reap
        return false;
    }
    return true;
}

bool LeaseManager::touch(const LeaseKey& key, std::chrono::steady_clock::time_point now)
{
    std::lock_guard lock(m_mutex);
    auto it = m_leases.find(key);
    if (it == m_leases.end() || !isActiveLocked(it->second, now)) {
        if (it != m_leases.end()) {
            m_leases.erase(it);
        }
        return false;
    }
    it->second.lastUse = now;
    return true;
}

bool LeaseManager::isPinVerified(const LeaseKey& key)
{
    std::lock_guard lock(m_mutex);
    auto it = m_leases.find(key);
    return it != m_leases.end() && it->second.pinVerified;
}

void LeaseManager::markPinVerified(const LeaseKey& key)
{
    std::lock_guard lock(m_mutex);
    auto it = m_leases.find(key);
    if (it != m_leases.end()) {
        it->second.pinVerified = true;
    }
}

void LeaseManager::clearPinVerified(const LeaseKey& key)
{
    std::lock_guard lock(m_mutex);
    auto it = m_leases.find(key);
    if (it != m_leases.end()) {
        it->second.pinVerified = false;
    }
}

void LeaseManager::revoke(const LeaseKey& key)
{
    std::lock_guard lock(m_mutex);
    m_leases.erase(key);
}

void LeaseManager::revokeCard(ObjectId card)
{
    std::lock_guard lock(m_mutex);
    for (auto it = m_leases.begin(); it != m_leases.end();) {
        it = (it->first.card == card) ? m_leases.erase(it) : std::next(it);
    }
}

void LeaseManager::revokeCaller(const CallerToken& caller)
{
    std::lock_guard lock(m_mutex);
    for (auto it = m_leases.begin(); it != m_leases.end();) {
        it = (it->first.caller == caller) ? m_leases.erase(it) : std::next(it);
    }
}

} // namespace LibreSCRS::Agent::Pkcs11
