// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SessionState — the module's per-process session/object/cursor bookkeeping
// behind the C_* ABI. Holds the live slot model (built from an AgentClient
// snapshot), the slotID<->reader mapping, opaque object handles, and per-session
// find / sign / decrypt cursors. It performs NO D-Bus and NO crypto: Module.cpp
// owns the AgentClient and feeds snapshots in; SessionState answers the pure
// handle/cursor questions. Object handles encode (slot, object-index) so a
// handle resolves without a global object table.

#pragma once

#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/Agent/pkcs11/DerivedKeys.h>
#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>
#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief A live sign operation initialised by C_SignInit.
struct SignCursor
{
    bool active = false;
    std::string reader;
    std::string certId;
    std::uint32_t keyBits = 0;
    CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS; ///< As C_SignInit admitted it.
    LibreSCRS::Agent::KeyType keyType = LibreSCRS::Agent::KeyType::Other;
    std::vector<std::uint8_t> accumulated; ///< For the C_SignUpdate multi-part path.
};

/// @brief A live decrypt operation initialised by C_DecryptInit.
struct DecryptCursor
{
    bool active = false;
    std::string reader;
    std::string certId;
    std::uint32_t keyBits = 0;
    std::vector<std::uint8_t> accumulated; ///< For the C_DecryptUpdate multi-part path.
};

/// @brief A live C_FindObjects enumeration.
struct FindCursor
{
    bool active = false;
    std::vector<CK_OBJECT_HANDLE> matches;
    std::size_t next = 0;
};

/// @brief One open PKCS#11 session.
struct Session
{
    CK_SLOT_ID slot = 0;
    CK_FLAGS flags = 0;
    FindCursor find;
    SignCursor sign;
    DecryptCursor decrypt;
    /// @brief A blocking agent RPC (login / sign / decrypt) is in flight on this
    ///        session, with the global lock RELEASED. Re-entrant blocking calls
    ///        on the same session are refused (CKR_OPERATION_ACTIVE) so the op
    ///        cursors cannot be mutated under the running RPC.
    bool rpcInFlight = false;
};

/// @brief Per-process session/object state behind the C_* ABI.
class SessionState
{
public:
    /// @brief Replace the slot model from a fresh agent snapshot. Slot IDs are
    ///        assigned by reader-path order and kept STABLE across refreshes so
    ///        a slot id a caller holds keeps meaning the same reader.
    void setModel(ObjectModel model);

    [[nodiscard]] const ObjectModel& model() const noexcept
    {
        return m_model;
    }

    /// @brief All slot IDs (optionally only token-present ones).
    [[nodiscard]] std::vector<CK_SLOT_ID> slotIds(bool tokenPresentOnly) const;

    /// @brief Resolve a slot id to its model slot (nullptr if unknown).
    [[nodiscard]] const Slot* slotById(CK_SLOT_ID id) const;

    // --- sessions ----------------------------------------------------------
    [[nodiscard]] CK_SESSION_HANDLE openSession(CK_SLOT_ID slot, CK_FLAGS flags);
    [[nodiscard]] Session* session(CK_SESSION_HANDLE h);
    bool closeSession(CK_SESSION_HANDLE h);
    void closeAllSessions(CK_SLOT_ID slot);
    /// @brief Slot ids that still have at least one open session.
    [[nodiscard]] bool slotHasSessions(CK_SLOT_ID slot) const;

    // --- login ---------------------------------------------------------------
    // PKCS#11 v2.40 section 5.6: a login belongs to the application on the
    // token, so every session of a slot shares it, the ones opened later too.

    /// @brief How often the module asks the agent whether a login still holds:
    ///        NSS asks the module no more often than this (LOGIN_DELAY_TIME).
    static constexpr std::chrono::seconds kLoginCheckInterval{1};

    [[nodiscard]] bool isLoggedIn(CK_SLOT_ID slot) const;
    /// @brief Every session of @p slot is a user session from now on. The agent
    ///        has just granted the login, so it counts as checked at @p now.
    void setLoggedIn(CK_SLOT_ID slot, std::chrono::steady_clock::time_point now);
    /// @brief Every session of @p slot is public again, and the token's private
    ///        session objects go with the login. Idempotent.
    void endLogin(CK_SLOT_ID slot);
    /// @brief Counts the logins of @p slot, so an answer about an earlier one
    ///        is not taken for the current one.
    [[nodiscard]] std::uint64_t loginGeneration(CK_SLOT_ID slot) const;
    /// @brief @p slot is logged in and was last checked with the agent at least
    ///        kLoginCheckInterval before @p now.
    [[nodiscard]] bool loginCheckDue(CK_SLOT_ID slot, std::chrono::steady_clock::time_point now) const;
    void markLoginChecked(CK_SLOT_ID slot, std::chrono::steady_clock::time_point now);

    // --- objects -----------------------------------------------------------
    /// @brief Encode an object handle from (slot, object index).
    [[nodiscard]] static CK_OBJECT_HANDLE encodeHandle(CK_SLOT_ID slot, std::size_t objIndex);
    /// @brief Decode -> the Object* on the given session's slot (nullptr if stale).
    [[nodiscard]] const Object* resolveObject(CK_SLOT_ID slot, CK_OBJECT_HANDLE h) const;

    /// @brief Object handles on @p slot matching @p tmpl (CKA_CLASS, CKA_ID, CKA_TOKEN, CKA_KEY_TYPE, CKA_PRIVATE):
    ///        the card's objects, then the derived keys @p session may see.
    [[nodiscard]] std::vector<CK_OBJECT_HANDLE> findMatches(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                                                            CK_ATTRIBUTE_PTR tmpl, CK_ULONG count) const;

    // --- derived keys (C_DeriveKey) -----------------------------------------
    /// @brief The high bit marks a derived key's handle; the card objects'
    ///        (slot << 32 | index + 1) handles never reach it.
    static constexpr CK_OBJECT_HANDLE kDerivedHandleBit = CK_OBJECT_HANDLE{1} << 63;
    [[nodiscard]] static bool isDerivedHandle(CK_OBJECT_HANDLE h) noexcept
    {
        return (h & kDerivedHandleBit) != 0;
    }
    /// @brief Keep @p key; its handle is never reused while the module is loaded.
    [[nodiscard]] CK_OBJECT_HANDLE addDerivedKey(DerivedKey key);
    /// @brief The derived key @p h as @p session sees it: the same slot, and
    ///        only while that slot is logged in (it is a private object).
    [[nodiscard]] const DerivedKey* derivedKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h) const;
    bool destroyDerivedKey(CK_OBJECT_HANDLE h);
    void destroyDerivedKeysOfSlot(CK_SLOT_ID slot);

private:
    ObjectModel m_model;
    std::map<std::string, CK_SLOT_ID> m_readerToSlot; ///< stable reader-path -> slot id
    CK_SLOT_ID m_nextSlotId = 0;
    std::map<CK_SLOT_ID, std::size_t> m_slotIndex; ///< slot id -> index into m_model.slots
    std::map<CK_SESSION_HANDLE, Session> m_sessions;
    CK_SESSION_HANDLE m_nextSession = 1;
    struct SlotLogin
    {
        bool loggedIn = false;
        std::uint64_t generation = 0;
        std::chrono::steady_clock::time_point checkedAt{};
    };
    std::map<CK_SLOT_ID, SlotLogin> m_logins;
    std::map<CK_OBJECT_HANDLE, DerivedKey> m_derived;
    CK_OBJECT_HANDLE m_nextDerived = 1;

    void destroyDerivedKeysOfSession(CK_SESSION_HANDLE creator);
};

static_assert(sizeof(CK_OBJECT_HANDLE) == 8, "the derived-key handle bit needs a 64-bit handle");

} // namespace LibreSCRS::Pkcs11Agent
