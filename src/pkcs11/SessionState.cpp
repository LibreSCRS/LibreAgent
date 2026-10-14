// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/pkcs11/SessionState.h>

#include <LibreSCRS/Agent/KeyType.h>

#include <cstring>
#include <string>
#include <utility>

namespace LibreSCRS::Pkcs11Agent {

namespace {

// Object handle layout: high 32 bits = slot id, low 32 bits = object index + 1
// (0 is reserved for CK_INVALID_HANDLE). Lets a handle resolve without a global
// object table while staying stable for a given snapshot.
constexpr CK_OBJECT_HANDLE kIndexMask = 0xFFFFFFFFULL;
constexpr unsigned kSlotShift = 32;

} // namespace

void SessionState::setModel(ObjectModel model)
{
    // The token each slot showed before this refresh: a derived key belongs to
    // the card it was derived with, and goes when that card does.
    std::map<CK_SLOT_ID, std::string> before;
    for (const auto& [id, idx] : m_slotIndex) {
        const Slot& s = m_model.slots[idx];
        before.emplace(id, s.tokenPresent ? s.tokenSerial : std::string{});
    }

    m_model = std::move(model);
    m_slotIndex.clear();
    for (std::size_t i = 0; i < m_model.slots.size(); ++i) {
        const std::string& reader = m_model.slots[i].readerPath;
        auto it = m_readerToSlot.find(reader);
        CK_SLOT_ID id;
        if (it == m_readerToSlot.end()) {
            id = m_nextSlotId++;
            m_readerToSlot.emplace(reader, id);
        } else {
            id = it->second;
        }
        m_slotIndex[id] = i;
    }

    // A token that named no serial cannot be told from the next one, so its
    // keys do not survive a refresh at all.
    for (const auto& [id, serial] : before) {
        const Slot* now = slotById(id);
        if (serial.empty() || now == nullptr || !now->tokenPresent || now->tokenSerial != serial) {
            destroyDerivedKeysOfSlot(id);
        }
    }
}

std::vector<CK_SLOT_ID> SessionState::slotIds(bool tokenPresentOnly) const
{
    std::vector<CK_SLOT_ID> ids;
    for (const auto& [id, idx] : m_slotIndex) {
        if (tokenPresentOnly && !m_model.slots[idx].tokenPresent)
            continue;
        ids.push_back(id);
    }
    return ids;
}

const Slot* SessionState::slotById(CK_SLOT_ID id) const
{
    auto it = m_slotIndex.find(id);
    if (it == m_slotIndex.end())
        return nullptr;
    return &m_model.slots[it->second];
}

CK_SESSION_HANDLE SessionState::openSession(CK_SLOT_ID slot, CK_FLAGS flags)
{
    const CK_SESSION_HANDLE h = m_nextSession++;
    Session s;
    s.slot = slot;
    s.flags = flags;
    m_sessions.emplace(h, std::move(s));
    return h;
}

Session* SessionState::session(CK_SESSION_HANDLE h)
{
    auto it = m_sessions.find(h);
    return it == m_sessions.end() ? nullptr : &it->second;
}

bool SessionState::closeSession(CK_SESSION_HANDLE h)
{
    destroyDerivedKeysOfSession(h);
    return m_sessions.erase(h) > 0;
}

void SessionState::closeAllSessions(CK_SLOT_ID slot)
{
    destroyDerivedKeysOfSlot(slot);
    for (auto it = m_sessions.begin(); it != m_sessions.end();) {
        if (it->second.slot == slot)
            it = m_sessions.erase(it);
        else
            ++it;
    }
}

bool SessionState::slotHasSessions(CK_SLOT_ID slot) const
{
    for (const auto& [h, s] : m_sessions)
        if (s.slot == slot)
            return true;
    return false;
}

CK_OBJECT_HANDLE SessionState::encodeHandle(CK_SLOT_ID slot, std::size_t objIndex)
{
    return (static_cast<CK_OBJECT_HANDLE>(slot) << kSlotShift) |
           ((static_cast<CK_OBJECT_HANDLE>(objIndex) + 1) & kIndexMask);
}

const Object* SessionState::resolveObject(CK_SLOT_ID slot, CK_OBJECT_HANDLE h) const
{
    const CK_SLOT_ID hSlot = static_cast<CK_SLOT_ID>(h >> kSlotShift);
    const CK_OBJECT_HANDLE rawIndex = h & kIndexMask;
    if (hSlot != slot || rawIndex == 0)
        return nullptr;
    const std::size_t objIndex = static_cast<std::size_t>(rawIndex - 1);
    const Slot* s = slotById(slot);
    if (!s || objIndex >= s->objects.size())
        return nullptr;
    return &s->objects[objIndex];
}

std::vector<CK_OBJECT_HANDLE> SessionState::findMatches(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                                                        CK_ATTRIBUTE_PTR tmpl, CK_ULONG count) const
{
    std::vector<CK_OBJECT_HANDLE> out;
    const Slot* s = slotById(slot);
    if (!s)
        return out;

    for (std::size_t i = 0; i < s->objects.size(); ++i) {
        const Object& obj = s->objects[i];
        bool match = true;
        for (CK_ULONG a = 0; a < count && tmpl; ++a) {
            const CK_ATTRIBUTE& attr = tmpl[a];
            switch (attr.type) {
            case CKA_CLASS: {
                if (attr.pValue && attr.ulValueLen == sizeof(CK_OBJECT_CLASS)) {
                    CK_OBJECT_CLASS cls = 0;
                    std::memcpy(&cls, attr.pValue, sizeof(cls));
                    if (cls != obj.cls)
                        match = false;
                }
                break;
            }
            case CKA_ID: {
                if (attr.pValue) {
                    const auto* p = static_cast<const std::uint8_t*>(attr.pValue);
                    std::vector<std::uint8_t> want(p, p + attr.ulValueLen);
                    if (want != obj.ckaId)
                        match = false;
                }
                break;
            }
            case CKA_TOKEN: {
                // All our objects are token objects (CK_TRUE). A request for
                // session objects (CK_FALSE) matches nothing.
                if (attr.pValue && attr.ulValueLen == sizeof(CK_BBOOL)) {
                    CK_BBOOL want = *static_cast<CK_BBOOL*>(attr.pValue);
                    if (want != CK_TRUE)
                        match = false;
                }
                break;
            }
            case CKA_KEY_TYPE: {
                // Only key objects have a key type; a certificate never matches.
                if (attr.pValue && attr.ulValueLen == sizeof(CK_KEY_TYPE)) {
                    CK_KEY_TYPE want = 0;
                    std::memcpy(&want, attr.pValue, sizeof(want));
                    const bool isKey = obj.cls == CKO_PUBLIC_KEY || obj.cls == CKO_PRIVATE_KEY;
                    const CK_KEY_TYPE have = (obj.keyType == LibreSCRS::Agent::KeyType::Ec) ? CKK_EC : CKK_RSA;
                    if (!isKey || want != have)
                        match = false;
                }
                break;
            }
            case CKA_PRIVATE: {
                if (attr.pValue && attr.ulValueLen == sizeof(CK_BBOOL)) {
                    const CK_BBOOL want = *static_cast<CK_BBOOL*>(attr.pValue);
                    const CK_BBOOL have = (obj.cls == CKO_PRIVATE_KEY) ? CK_TRUE : CK_FALSE;
                    if (want != have)
                        match = false;
                }
                break;
            }
            default:
                // Unhandled selector attributes are ignored (permissive match,
                // matching common token behaviour for NSS/pkcs11-tool probes).
                break;
            }
            if (!match)
                break;
        }
        if (match)
            out.push_back(encodeHandle(slot, i));
    }

    // The application's derived keys on this slot, private: only a logged-in
    // session sees them.
    for (const auto& [h, key] : m_derived) {
        if (derivedKey(session, h) != nullptr && derivedKeyMatches(key, tmpl, count))
            out.push_back(h);
    }
    return out;
}

CK_OBJECT_HANDLE SessionState::addDerivedKey(DerivedKey key)
{
    const CK_OBJECT_HANDLE h = kDerivedHandleBit | m_nextDerived++;
    m_derived.emplace(h, std::move(key));
    return h;
}

const DerivedKey* SessionState::derivedKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) const
{
    const auto s = m_sessions.find(session);
    const auto k = m_derived.find(h);
    if (s == m_sessions.end() || k == m_derived.end())
        return nullptr;
    if (k->second.slot != s->second.slot || !s->second.loggedIn)
        return nullptr;
    return &k->second;
}

bool SessionState::destroyDerivedKey(CK_OBJECT_HANDLE h)
{
    return m_derived.erase(h) > 0; // ~DerivedKey wipes the value
}

void SessionState::destroyDerivedKeysOfSlot(CK_SLOT_ID slot)
{
    std::erase_if(m_derived, [slot](const auto& entry) { return entry.second.slot == slot; });
}

void SessionState::destroyDerivedKeysOfSession(CK_SESSION_HANDLE creator)
{
    std::erase_if(m_derived, [creator](const auto& entry) { return entry.second.creator == creator; });
}

} // namespace LibreSCRS::Pkcs11Agent
