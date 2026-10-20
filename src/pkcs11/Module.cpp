// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-pkcs11-agent — a standalone, Qt-free, libcrypto-free PKCS#11
// v2.40 module that implements the C_* ABI by brokering to the per-user
// librescrs-agent through an AgentClient (D-Bus on Linux, a Unix socket on
// macOS). It holds NO card connection and NO card key: every real crypto
// operation is performed on-card by the agent.
//
// PIN/CAN are collected by the agent's prompter, so every token advertises
// CKF_PROTECTED_AUTHENTICATION_PATH and the application PIN passed to C_Login is
// IGNORED — it is NEVER placed on the wire. The secret bytes the module touches
// are sign/decrypt I/O, which pass straight through to/from the agent, and the
// ECDH secrets C_DeriveKey keeps as session keys of the application; none is
// ever logged, and each is wiped when it goes.
//
// Layout: this file owns the C ABI surface + the static function-list table;
// SessionState owns the session/object/cursor bookkeeping; AgentClient is the
// transport to the agent; ObjectModel is the pure slot/token/object/mechanism mapping.

#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/pkcs11/AgentClient.h>
#include <LibreSCRS/Agent/pkcs11/AgentClientFactory.h>
#include <LibreSCRS/Agent/pkcs11/DerivedKeys.h>
#include <LibreSCRS/Agent/pkcs11/EcEncoding.h>
#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>
#include <LibreSCRS/Agent/pkcs11/SessionState.h>
#include <LibreSCRS/Agent/pkcs11/pkcs11.h>
#include <LibreSCRS/Agent/util/DisplayText.h> // utf8PrefixLength

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>

namespace {

using namespace LibreSCRS::Pkcs11Agent;
using LibreSCRS::Agent::KeyType;

// PKCS#11 is a C API — C++ exceptions must never cross the boundary.
#define PKCS11_TRY try {
#define PKCS11_CATCH                                                                                                   \
    }                                                                                                                  \
    catch (...)                                                                                                        \
    {                                                                                                                  \
        return CKR_DEVICE_ERROR;                                                                                       \
    }

// --- File-scoped library state --------------------------------------------
struct Library
{
    // Held by pointer, not by value: which transport this is comes from the
    // host's factory at link time, and the core has no business naming it.
    std::unique_ptr<AgentClient> client = makeAgentClient();
    SessionState state;
    // Certificate DER by certId. The id is the DER's SHA-256, so an entry can
    // never stand for another certificate, and each one is read from the card once.
    std::map<std::string, std::vector<std::uint8_t>> certDers;
};

std::mutex g_mutex;
std::unique_ptr<Library> g_lib;

// In-flight blocking-RPC accounting. The interactive C_* paths
// (Login/Sign/Decrypt) release g_mutex across the blocking agent RPC so an
// unrelated C_* is not stalled behind a human-paced PIN prompt. That narrowing
// means a concurrent C_Finalize could run g_lib.reset() — destroying the
// AgentClient the RPC thread is still inside — a use-after-free. We therefore
// count threads currently parked in an RPC (incremented under g_mutex BEFORE the
// release, decremented under g_mutex AFTER the re-take, via the RAII guard
// below) and have C_Finalize WAIT for the count to drain to zero before the
// reset. g_rpcDrained is notified on each decrement; C_Finalize bounds its wait
// and refuses (via the standard path) if the count cannot drain.
int g_rpcInFlight = 0;                // guarded by g_mutex
std::condition_variable g_rpcDrained; // notified when g_rpcInFlight hits 0

// RAII for the per-session rpcInFlight flag AND the global in-flight RPC count.
// Constructed UNDER g_mutex with the flag set + the count incremented; cleared on
// destruction by RE-TAKING g_mutex (the blocking RPC runs with the lock
// released in between). This guarantees both the session flag and the global
// count are cleared on EVERY exit path — including a std::bad_alloc thrown by the
// input-buffer build between the set and the RPC. A null session pointer is
// tolerated (the session may have been closed during the RPC); only the global
// count is then adjusted.
class RpcInFlightGuard
{
public:
    // PRECONDITION: g_mutex is held by the caller, @p s is validated, and the
    // session's rpcInFlight was NOT already set (the caller checked + refused
    // CKR_OPERATION_ACTIVE). Sets the flag + bumps the global count.
    explicit RpcInFlightGuard(Session* s) : m_session(s)
    {
        if (m_session) {
            m_session->rpcInFlight = true;
        }
        ++g_rpcInFlight;
    }

    RpcInFlightGuard(const RpcInFlightGuard&) = delete;
    RpcInFlightGuard& operator=(const RpcInFlightGuard&) = delete;

    ~RpcInFlightGuard()
    {
        std::lock_guard lk(g_mutex);
        // Re-resolve the session by handle: it may have been closed during the
        // RPC, in which case only the global count is adjusted. The owner clears
        // rpcInFlight here on the live session (mirrors the prior manual reset).
        if (m_session && g_lib) {
            if (Session* s = g_lib->state.session(m_handle)) {
                s->rpcInFlight = false;
            }
        }
        if (--g_rpcInFlight == 0) {
            g_rpcDrained.notify_all();
        }
    }

    // Record the handle so the dtor can re-resolve the (possibly recreated)
    // Session* rather than trusting a pointer that may have dangled.
    void setHandle(CK_SESSION_HANDLE h) noexcept
    {
        m_handle = h;
    }

private:
    Session* m_session = nullptr;
    CK_SESSION_HANDLE m_handle = 0;
};

// Pull a fresh snapshot from the agent into the session state. Called on every
// slot/token query so live reader/card changes are reflected.
void refreshModel()
{
    g_lib->state.setModel(ObjectModel::build(g_lib->client->snapshot()));
}

// Map an AgentClient::Status to a CKR_* for a sign/decrypt/login outcome.
// @p invalidInputRv is what the calling function answers for an input the
// agent refused: each operation has its own length or parameter error.
CK_RV ckrFromStatus(Status s, CK_RV invalidInputRv = CKR_GENERAL_ERROR)
{
    switch (s) {
    case Status::Ok:
        return CKR_OK;
    case Status::UserNotLoggedIn:
        // Surfaced so NSS transparently re-C_Login when the agent lease expired.
        return CKR_USER_NOT_LOGGED_IN;
    case Status::NotAuthorized:
        return CKR_PIN_INCORRECT;
    case Status::AuthFailed:
        return CKR_PIN_INCORRECT;
    case Status::Cancelled:
        return CKR_FUNCTION_CANCELED;
    case Status::KeyNotFound:
        return CKR_KEY_HANDLE_INVALID;
    case Status::UnknownCard:
        return CKR_TOKEN_NOT_PRESENT;
    case Status::NotSupported:
        return CKR_FUNCTION_NOT_SUPPORTED;
    case Status::RateLimited:
        return CKR_FUNCTION_REJECTED;
    case Status::Communication:
        return CKR_DEVICE_ERROR;
    case Status::DeviceRemoved:
        return CKR_DEVICE_REMOVED;
    case Status::InvalidInput:
        // The agent refused the input before any prompt: the calling
        // function's own length or parameter error.
        return invalidInputRv;
    case Status::GeneralError:
    default:
        return CKR_GENERAL_ERROR;
    }
}

// The agent answers UserNotLoggedIn when the lease is gone (idle, lifetime,
// card removed). The session is PUBLIC again from that answer on, so a loader
// that reads the state logs in afresh instead of being told it still is.
void dropLoginOnLapsedLease(Status s, CK_SESSION_HANDLE hSession)
{
    if (s != Status::UserNotLoggedIn)
        return;
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return;
    if (Session* sess = g_lib->state.session(hSession)) {
        sess->loggedIn = false;
        // ...and the private session objects of that token go with the login.
        g_lib->state.destroyDerivedKeysOfSlot(sess->slot);
    }
}

// The signature length a key produces, from the model alone: an RSA
// signature is the modulus length, an ECDSA one r||s at the curve's width. 0
// when the model does not say. Answering a length from the card would cost a
// PIN prompt for a key the card marks for consent per operation.
CK_ULONG signatureLength(KeyType type, std::uint32_t bits)
{
    const CK_ULONG bytes = (static_cast<CK_ULONG>(bits) + 7) / 8;
    switch (type) {
    case KeyType::Rsa:
        return bytes;
    case KeyType::Ec:
        return 2 * bytes;
    case KeyType::Other:
        break;
    }
    return 0;
}

// The agent mechanism for a module sign mechanism (C_SignInit admitted only these three).
LibreSCRS::Agent::Mechanism agentSignMechanism(CK_MECHANISM_TYPE m)
{
    switch (m) {
    case CKM_ECDSA:
        return LibreSCRS::Agent::Mechanism::EcdsaSign;
    case CKM_SHA256_RSA_PKCS:
        return LibreSCRS::Agent::Mechanism::Sha256RsaPkcs1Sign;
    default:
        return LibreSCRS::Agent::Mechanism::RsaPkcs1Sign;
    }
}

// Copy a padded C-string field (CK_TOKEN_INFO / CK_SLOT_INFO are space-padded,
// NOT null-terminated). Truncates to the field length on a UTF-8 character
// boundary: these fields are CK_UTF8CHAR, and a holder name or reader name cut
// mid-character would hand the loader an invalid string to display.
void padField(CK_UTF8CHAR* dst, std::size_t len, const std::string& src)
{
    std::memset(dst, ' ', len);
    std::memcpy(dst, src.data(), LibreSCRS::Agent::utf8PrefixLength(src, len));
}

// Copy the caller's ready-to-sign block into the wire buffer VERBATIM. The
// module is libcrypto-free and performs NO hashing and prepends NO DigestInfo
// prefix for EITHER advertised mechanism — the caller's data already has the
// right form per the slot's single advertised mechanism: a complete pre-built
// DigestInfo for CKM_RSA_PKCS (DigestInfo cards), or the RAW message for
// CKM_SHA256_RSA_PKCS (hash-on-card cards, where the CARD computes SHA-256).
// The copy is kept as a distinct helper so the std::bad_alloc it can throw
// lands on the RpcInFlightGuard's every-exit-path cleanup in doSign, not inside
// the guarded region.
std::vector<std::uint8_t> buildSignInput(const std::uint8_t* data, std::size_t len)
{
    return std::vector<std::uint8_t>(data, data + len);
}

// True if @p mech is in the slot's advertised mechanism table.
bool slotHasMechanism(const Slot& slot, CK_MECHANISM_TYPE mech)
{
    for (const auto m : slot.mechanisms)
        if (m == mech)
            return true;
    return false;
}

} // namespace

// ===========================================================================
// General-purpose
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (g_lib)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    if (pInitArgs != NULL_PTR) {
        auto* args = static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
        if (args->pReserved != NULL_PTR)
            return CKR_ARGUMENTS_BAD;
        const bool hasCustomMutex = (args->CreateMutex != NULL_PTR || args->DestroyMutex != NULL_PTR ||
                                     args->LockMutex != NULL_PTR || args->UnlockMutex != NULL_PTR);
        if (hasCustomMutex && !(args->flags & CKF_OS_LOCKING_OK))
            return CKR_CANT_LOCK;
    }
    g_lib = std::make_unique<Library>();
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    PKCS11_TRY
    std::unique_lock lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pReserved != NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    // a well-behaved app quiesces before C_Finalize (PKCS#11 §5.6), but the
    // narrowed locking means a misbehaving (or simply racing) app could leave a
    // blocking RPC in flight on another thread. Destroying the library now would
    // be a use-after-free on that thread. Wait (bounded) for the in-flight RPC
    // count to drain to zero before the reset; the wait releases g_mutex so the
    // RPC threads can re-take it to decrement. If it cannot drain within the
    // bound (a genuinely wedged op), refuse via the standard path rather than
    // free memory out from under a live RPC.
    constexpr auto kDrainBudget = std::chrono::seconds{30};
    if (!g_rpcDrained.wait_for(lk, kDrainBudget, [] { return g_rpcInFlight == 0; }))
        return CKR_FUNCTION_FAILED; // could not quiesce; leave the library intact
    g_lib.reset();
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    PKCS11_TRY
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    *pInfo = CK_INFO{};
    pInfo->cryptokiVersion = {2, 40};
    padField(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    padField(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "LibreSCRS agent-proxy PKCS#11");
    pInfo->flags = 0;
    pInfo->libraryVersion = {0, 1};
    return CKR_OK;
    PKCS11_CATCH
}

// C_GetFunctionList is defined at the end of this file (needs the table).

// ===========================================================================
// Slot and token management
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    refreshModel();
    const auto ids = g_lib->state.slotIds(tokenPresent == CK_TRUE);

    if (pSlotList == NULL_PTR) {
        *pulCount = static_cast<CK_ULONG>(ids.size());
        return CKR_OK;
    }
    if (*pulCount < ids.size()) {
        *pulCount = static_cast<CK_ULONG>(ids.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    for (std::size_t i = 0; i < ids.size(); ++i)
        pSlotList[i] = ids[i];
    *pulCount = static_cast<CK_ULONG>(ids.size());
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    *pInfo = CK_SLOT_INFO{};
    // The reader's own name is what a user recognises; the agent's handle for
    // it is only a key, and shown only when the agent reported no name.
    padField(pInfo->slotDescription, sizeof(pInfo->slotDescription),
             slot->readerName.empty() ? slot->readerPath : slot->readerName);
    padField(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (slot->tokenPresent)
        pInfo->flags |= CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion = {0, 1};
    pInfo->firmwareVersion = {0, 1};
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;

    *pInfo = CK_TOKEN_INFO{};
    padField(pInfo->label, sizeof(pInfo->label), slot->tokenLabel.empty() ? "LibreSCRS Token" : slot->tokenLabel);
    padField(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    padField(pInfo->model, sizeof(pInfo->model), "agent-proxy");
    padField(pInfo->serialNumber, sizeof(pInfo->serialNumber), slot->tokenSerial);
    // The agent prompter is the protected authentication path; login is required
    // before any private-key op. Token present is implicit (checked above).
    // The issuer initialized the card's PIN; without CKF_USER_PIN_INITIALIZED NSS
    // treats the token as needing a user PIN set and disables login.
    pInfo->flags =
        CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_PROTECTED_AUTHENTICATION_PATH;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen = 0; // PIN is collected by the agent prompter, not here.
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion = {0, 1};
    pInfo->firmwareVersion = {0, 1};
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    const auto& mechs = slot->mechanisms;
    if (pMechanismList == NULL_PTR) {
        *pulCount = static_cast<CK_ULONG>(mechs.size());
        return CKR_OK;
    }
    if (*pulCount < mechs.size()) {
        *pulCount = static_cast<CK_ULONG>(mechs.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    for (std::size_t i = 0; i < mechs.size(); ++i)
        pMechanismList[i] = mechs[i];
    *pulCount = static_cast<CK_ULONG>(mechs.size());
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slotHasMechanism(*slot, type))
        return CKR_MECHANISM_INVALID;

    *pInfo = CK_MECHANISM_INFO{};
    // Per-mechanism bounds (bits) and flags; slotHasMechanism gated the type above.
    switch (type) {
    case CKM_ECDSA:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 521;
        pInfo->flags = CKF_HW | CKF_SIGN | CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS;
        break;
    case CKM_ECDH1_DERIVE:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 521;
        pInfo->flags = CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS;
        break;
    case CKM_SHA256_RSA_PKCS:
        // Hash-on-card family: sign only (the pkcs15 plugin has no decipher primitive).
        pInfo->ulMinKeySize = 2048;
        pInfo->ulMaxKeySize = 4096;
        pInfo->flags = CKF_HW | CKF_SIGN;
        break;
    default:
        // CKM_RSA_PKCS: DigestInfo family, sign and decrypt.
        pInfo->ulMinKeySize = 2048;
        pInfo->ulMaxKeySize = 4096;
        pInfo->flags = CKF_HW | CKF_SIGN | CKF_DECRYPT;
        break;
    }
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)
(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    (void)slotID;
    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)hSession;
    (void)pPin;
    (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    (void)hSession;
    (void)pOldPin;
    (void)ulOldLen;
    (void)pNewPin;
    (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Session management
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)
(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    PKCS11_TRY(void) pApplication;
    (void)Notify;
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (phSession == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;
    *phSession = g_lib->state.openSession(slotID, flags);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    const CK_SLOT_ID slot = s->slot;
    g_lib->state.closeSession(hSession);
    // On the last session for a slot, drop the agent lease (idempotent).
    if (!g_lib->state.slotHasSessions(slot)) {
        if (const Slot* sl = g_lib->state.slotById(slot); sl)
            (void)g_lib->client->logout(sl->readerPath);
    }
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    g_lib->state.closeAllSessions(slotID);
    if (const Slot* sl = g_lib->state.slotById(slotID); sl)
        (void)g_lib->client->logout(sl->readerPath);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    *pInfo = CK_SESSION_INFO{};
    pInfo->slotID = s->slot;
    if (s->loggedIn)
        pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    else
        pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession;
    (void)pOperationState;
    (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
 CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession;
    (void)pOperationState;
    (void)ulOperationStateLen;
    (void)hEncryptionKey;
    (void)hAuthenticationKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Login)
(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    PKCS11_TRY
        // pPin / ulPinLen are DELIBERATELY IGNORED: the agent prompter is the
        // protected authentication path (CKF_PROTECTED_AUTHENTICATION_PATH). The
        // application PIN, if any, is NEVER read and NEVER placed on the wire.
        (void) pPin;
    (void)ulPinLen;

    // --- under lock: validate + capture the reader; mark in-flight ---
    std::string reader;
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        // CKU_USER: the per-card login. CKU_CONTEXT_SPECIFIC (PKCS#11 v2.40
        // §4.9, §5.6): what a loader sends between C_SignInit and C_Sign for a
        // key whose CKA_ALWAYS_AUTHENTICATE is TRUE. Both refresh the agent
        // lease; the PIN itself is asked for by the agent, which enforces the
        // card's rule on every operation with such a key. The standard answers
        // CKR_OPERATION_NOT_INITIALIZED to CKU_CONTEXT_SPECIFIC when no
        // operation on such a key is active; this module accepts it anyway,
        // because the agent, not the module, decides when the PIN is due and a
        // refusal here would gain nothing. CKU_SO is unsupported.
        if (userType != CKU_USER && userType != CKU_CONTEXT_SPECIFIC)
            return CKR_USER_TYPE_INVALID;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        // A repeat CKU_USER login is an error; a CKU_CONTEXT_SPECIFIC re-auth is
        // EXPECTED while USER-logged-in (it re-confirms consent for the pending
        // operation), so it must fall through and refresh the lease.
        if (userType == CKU_USER && s->loggedIn)
            return CKR_USER_ALREADY_LOGGED_IN; // spec conformance (benign for NSS)
        const Slot* slot = g_lib->state.slotById(s->slot);
        if (!slot || !slot->tokenPresent)
            return CKR_TOKEN_NOT_PRESENT;
        if (slot->objects.empty())
            return CKR_KEY_HANDLE_INVALID;
        // Login is per-card (the lease is (caller, card)-scoped, not per-cert).
        reader = slot->readerPath;
        // Arm the in-flight guard (sets s->rpcInFlight + bumps the global count)
        // so C_Finalize cannot reset the library mid-RPC, and the flag is cleared
        // on every exit path (including a throw before the RPC).
        guard.emplace(s);
        guard->setHandle(hSession);
    }

    // --- lock RELEASED: the agent prompts for the PIN (human-paced) here, so no
    //     other C_* (even unrelated slots) is blocked app-wide. ---
    const auto res = g_lib->client->login(reader);

    // --- re-take the lock: record the outcome. The session may have been closed
    //     meanwhile; re-resolve by handle. The guard clears rpcInFlight + the
    //     global count on scope exit. ---
    {
        std::lock_guard lk(g_mutex);
        if (g_lib && res.status == Status::Ok) {
            if (Session* s = g_lib->state.session(hSession))
                s->loggedIn = true;
        }
    }
    if (res.status != Status::Ok)
        return ckrFromStatus(res.status);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (slot)
        (void)g_lib->client->logout(slot->readerPath);
    s->loggedIn = false;
    // The token's private session objects end with the login.
    g_lib->state.destroyDerivedKeysOfSlot(s->slot);
    return CKR_OK;
    PKCS11_CATCH
}

// ===========================================================================
// Object management
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    (void)hSession;
    (void)pTemplate;
    (void)ulCount;
    (void)phObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phNewObject)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (SessionState::isDerivedHandle(hObject)) {
        if (g_lib->state.derivedKey(hSession, hObject) == nullptr)
            return CKR_OBJECT_HANDLE_INVALID;
        (void)g_lib->state.destroyDerivedKey(hObject); // the value is wiped
        return CKR_OK;
    }
    // The card's objects are the card's: this module neither creates nor destroys them.
    if (g_lib->state.resolveObject(s->slot, hObject) != nullptr)
        return CKR_ACTION_PROHIBITED;
    return CKR_OBJECT_HANDLE_INVALID;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    (void)hSession;
    (void)hObject;
    (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

namespace {

// The element at the front of @p in -- its whole encoding and its content --
// and @p in moved past it. DER: low tag numbers, definite lengths only.
struct DerElement
{
    std::span<const std::uint8_t> whole;
    std::span<const std::uint8_t> content;
};

std::optional<DerElement> takeDerElement(std::span<const std::uint8_t>& in)
{
    if (in.size() < 2 || (in[0] & 0x1F) == 0x1F)
        return std::nullopt;
    std::size_t header = 2;
    std::size_t length = in[1];
    if ((length & 0x80) != 0) {
        const std::size_t octets = length & 0x7F;
        if (octets == 0 || octets > sizeof(std::size_t) || in.size() < header + octets)
            return std::nullopt;
        length = 0;
        for (std::size_t i = 0; i < octets; ++i)
            length = (length << 8) | in[header + i];
        header += octets;
    }
    if (in.size() - header < length)
        return std::nullopt;
    const DerElement out{in.first(header + length), in.subspan(header, length)};
    in = in.subspan(header + length);
    return out;
}

// CKA_SERIAL_NUMBER / CKA_ISSUER / CKA_SUBJECT: that TBSCertificate field
// exactly as the certificate encodes it -- a loader compares these bytes with
// the ones it decodes from CKA_VALUE, so they are cut, never rebuilt.
// RFC 5280 4.1 fixes the order, and DER keeps it:
//   Certificate    ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
//   TBSCertificate ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, serialNumber INTEGER,
//                                 signature SEQUENCE, issuer Name, validity SEQUENCE,
//                                 subject Name, ... }
// so the fields are taken off the front one after another; only version may be absent.
std::optional<std::span<const std::uint8_t>> certificateField(std::span<const std::uint8_t> der, CK_ATTRIBUTE_TYPE type)
{
    const auto take = [](std::span<const std::uint8_t>& in, std::uint8_t tag) {
        auto e = takeDerElement(in);
        return e && e->whole[0] == tag ? e : std::nullopt;
    };
    const auto cert = take(der, 0x30);
    if (!cert)
        return std::nullopt;
    auto certContent = cert->content;
    const auto tbs = take(certContent, 0x30);
    if (!tbs)
        return std::nullopt;
    auto fields = tbs->content;
    if (!fields.empty() && fields[0] == 0xA0 && !takeDerElement(fields))
        return std::nullopt;
    const auto serial = take(fields, 0x02);
    const auto signature = take(fields, 0x30);
    const auto issuer = take(fields, 0x30);
    const auto validity = take(fields, 0x30);
    const auto subject = take(fields, 0x30);
    if (!serial || !signature || !issuer || !validity || !subject)
        return std::nullopt;
    switch (type) {
    case CKA_SERIAL_NUMBER:
        return serial->whole;
    case CKA_ISSUER:
        return issuer->whole;
    case CKA_SUBJECT:
        return subject->whole;
    default:
        return std::nullopt;
    }
}

// The certificate's DER: from the agent the first time, then as kept.
BytesResult certDerOf(const Slot& slot, const Object& obj)
{
    if (const auto it = g_lib->certDers.find(obj.certId); it != g_lib->certDers.end())
        return {Status::Ok, it->second};
    auto der = g_lib->client->certDer(slot.readerPath, obj.certId);
    if (der.status == Status::Ok)
        g_lib->certDers.emplace(obj.certId, der.bytes);
    return der;
}

// Serve one attribute for an object. Returns CKR_OK (filled / sized) or
// CKR_ATTRIBUTE_TYPE_INVALID. Implements the buffer-size protocol:
// pValue==NULL -> set ulValueLen; small buffer -> ulValueLen = -1 +
// CKR_BUFFER_TOO_SMALL.
CK_RV serveAttribute(const Slot& slot, const Object& obj, CK_ATTRIBUTE& attr)
{
    auto give = [&](const void* src, std::size_t len) -> CK_RV {
        if (attr.pValue == NULL_PTR) {
            attr.ulValueLen = static_cast<CK_ULONG>(len);
            return CKR_OK;
        }
        if (attr.ulValueLen < len) {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::memcpy(attr.pValue, src, len);
        attr.ulValueLen = static_cast<CK_ULONG>(len);
        return CKR_OK;
    };

    const CK_BBOOL ckTrue = CK_TRUE;
    const CK_BBOOL ckFalse = CK_FALSE;

    // Fetch the cert's public key (lazy, agent-served — the module holds no
    // crypto) and map the fetch status onto the PKCS#11 attribute protocol:
    // KeyNotFound -> CKR_KEY_HANDLE_INVALID, anything else non-Ok (NotSupported /
    // non-RSA / bus error) -> the attribute is absent (CKR_ATTRIBUTE_TYPE_INVALID).
    // On success @p out holds the key and the helper returns CKR_OK so the caller
    // serves its own field. Shared by the CKA_MODULUS / CKA_PUBLIC_EXPONENT /
    // CKA_EC_POINT arms (each independently served, no extra round-trip — the
    // AgentClient caches the key per certId).
    auto fetchPubKeyOr = [&](PublicKeyResult& out) -> CK_RV {
        out = g_lib->client->publicKey(slot.readerPath, obj.certId, obj.keyType);
        if (out.status == Status::KeyNotFound)
            return CKR_KEY_HANDLE_INVALID;
        if (out.status != Status::Ok)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return CKR_OK;
    };

    switch (attr.type) {
    case CKA_CLASS:
        return give(&obj.cls, sizeof(obj.cls));
    case CKA_ID:
        return give(obj.ckaId.data(), obj.ckaId.size());
    case CKA_LABEL:
        return give(obj.label.data(), obj.label.size());
    case CKA_TOKEN:
        return give(&ckTrue, sizeof(ckTrue));
    case CKA_PRIVATE:
        return give(obj.cls == CKO_PRIVATE_KEY ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_KEY_TYPE: {
        if (obj.cls == CKO_PUBLIC_KEY || obj.cls == CKO_PRIVATE_KEY) {
            const CK_KEY_TYPE kt = (obj.keyType == KeyType::Ec) ? CKK_EC : CKK_RSA;
            return give(&kt, sizeof(kt));
        }
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    case CKA_CERTIFICATE_TYPE: {
        if (obj.cls == CKO_CERTIFICATE) {
            const CK_CERTIFICATE_TYPE ct = CKC_X_509;
            return give(&ct, sizeof(ct));
        }
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    case CKA_SIGN:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(obj.sign ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_DECRYPT:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(obj.decrypt ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_DERIVE:
        // A common key attribute: a public key has it too, and does not derive.
        if (obj.cls == CKO_PUBLIC_KEY)
            return give(&ckFalse, sizeof(ckFalse));
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(obj.derive ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_UNWRAP:
        // No key is ever unwrapped with a card key through this module.
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(&ckFalse, sizeof(ckFalse));
    case CKA_EC_PARAMS: {
        // The named curve's OID, from the model (P-256/P-384/P-521 by size).
        if ((obj.cls != CKO_PUBLIC_KEY && obj.cls != CKO_PRIVATE_KEY) || obj.keyType != KeyType::Ec)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        const auto params = ecParamsDerFor(obj.keyBits);
        if (params.empty())
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(params.data(), params.size());
    }
    case CKA_EC_POINT: {
        // The point, on the public key only, as the agent read it off the
        // certificate -- and only on the curve CKA_EC_PARAMS names for the
        // key's size, whatever the transport let through.
        if (obj.cls != CKO_PUBLIC_KEY || obj.keyType != KeyType::Ec)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        PublicKeyResult pk;
        if (const CK_RV rv = fetchPubKeyOr(pk); rv != CKR_OK)
            return rv;
        if (!isPointOfKey(obj.keyBits, pk.crv, pk.x, pk.y))
            return CKR_ATTRIBUTE_TYPE_INVALID;
        const auto point = ecPointOctetString(pk.x, pk.y);
        if (point.empty())
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(point.data(), point.size());
    }
    case CKA_EXTRACTABLE:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(&ckFalse, sizeof(ckFalse)); // always false
    case CKA_SENSITIVE:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(&ckTrue, sizeof(ckTrue));
    case CKA_ALWAYS_AUTHENTICATE:
        // The card's per-operation PIN rule for this key (PKCS#15 userConsent,
        // PIV PIN-always), as the agent reads it. The agent enforces it
        // whatever a loader does -- it asks for the PIN again for every
        // operation with such a key -- so this tells a loader what to expect;
        // it gates nothing here.
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(obj.alwaysAuthenticate ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_MODULUS: {
        // RSA modulus (big-endian, unpadded) for key objects. Fetched lazily
        // from the agent — the module holds no crypto.
        if ((obj.cls != CKO_PUBLIC_KEY && obj.cls != CKO_PRIVATE_KEY) || obj.keyType != KeyType::Rsa)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        PublicKeyResult pk;
        if (const CK_RV rv = fetchPubKeyOr(pk); rv != CKR_OK)
            return rv;
        return give(pk.modulus.data(), pk.modulus.size());
    }
    case CKA_PUBLIC_EXPONENT: {
        if ((obj.cls != CKO_PUBLIC_KEY && obj.cls != CKO_PRIVATE_KEY) || obj.keyType != KeyType::Rsa)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        PublicKeyResult pk;
        if (const CK_RV rv = fetchPubKeyOr(pk); rv != CKR_OK)
            return rv;
        return give(pk.exponent.data(), pk.exponent.size());
    }
    case CKA_MODULUS_BITS: {
        // The public key's modulus size, from the model.
        if (obj.cls != CKO_PUBLIC_KEY || obj.keyType != KeyType::Rsa || obj.keyBits == 0)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        const CK_ULONG bits = obj.keyBits;
        return give(&bits, sizeof(bits));
    }
    case CKA_VALUE: {
        // Certificate DER, fetched lazily from the agent (public data).
        if (obj.cls != CKO_CERTIFICATE)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        auto der = certDerOf(slot, obj);
        if (der.status != Status::Ok)
            return ckrFromStatus(der.status); // CKR_DEVICE_ERROR / _REMOVED per bus state
        return give(der.bytes.data(), der.bytes.size());
    }
    case CKA_SERIAL_NUMBER:
    case CKA_ISSUER:
    case CKA_SUBJECT: {
        // Cut from the same DER CKA_VALUE serves; one that does not parse has none.
        if (obj.cls != CKO_CERTIFICATE)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        auto der = certDerOf(slot, obj);
        if (der.status != Status::Ok)
            return ckrFromStatus(der.status);
        const auto field = certificateField(der.bytes, attr.type);
        if (!field)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(field->data(), field->size());
    }
    default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
}

} // namespace

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pTemplate == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (!slot)
        return CKR_SESSION_HANDLE_INVALID;
    if (SessionState::isDerivedHandle(hObject)) {
        const DerivedKey* key = g_lib->state.derivedKey(hSession, hObject);
        if (!key)
            return CKR_OBJECT_HANDLE_INVALID;
        CK_RV overall = CKR_OK;
        for (CK_ULONG i = 0; i < ulCount; ++i) {
            const CK_RV rv = serveDerivedKeyAttribute(*key, pTemplate[i]);
            if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                overall = CKR_ATTRIBUTE_TYPE_INVALID;
            } else if (rv != CKR_OK) {
                overall = rv;
            }
        }
        return overall;
    }
    const Object* obj = g_lib->state.resolveObject(s->slot, hObject);
    if (!obj)
        return CKR_OBJECT_HANDLE_INVALID;

    CK_RV overall = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        const CK_RV rv = serveAttribute(*slot, *obj, pTemplate[i]);
        if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            overall = CKR_ATTRIBUTE_TYPE_INVALID;
        } else if (rv != CKR_OK) {
            overall = rv; // buffer-too-small / failure
        }
    }
    return overall;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->find.active)
        return CKR_OPERATION_ACTIVE;
    s->find.matches = g_lib->state.findMatches(hSession, s->slot, pTemplate, ulCount);
    // A certificate's names live in its DER, which the model does not hold:
    // compare them as C_GetAttributeValue serves them, so a search by subject,
    // or by issuer and serial, finds that certificate and nothing else.
    if (const Slot* slot = g_lib->state.slotById(s->slot); slot != nullptr && pTemplate != NULL_PTR) {
        std::erase_if(s->find.matches, [&](CK_OBJECT_HANDLE h) {
            const Object* obj = SessionState::isDerivedHandle(h) ? nullptr : g_lib->state.resolveObject(s->slot, h);
            for (CK_ULONG i = 0; i < ulCount; ++i) {
                const CK_ATTRIBUTE& want = pTemplate[i];
                if ((want.type != CKA_SUBJECT && want.type != CKA_ISSUER && want.type != CKA_SERIAL_NUMBER) ||
                    want.pValue == NULL_PTR)
                    continue;
                if (obj == nullptr)
                    return true;
                // Size first: the template's length is the caller's, the field's is ours.
                CK_ATTRIBUTE probe{want.type, NULL_PTR, 0};
                if (serveAttribute(*slot, *obj, probe) != CKR_OK || probe.ulValueLen != want.ulValueLen)
                    return true;
                std::vector<std::uint8_t> have(probe.ulValueLen);
                probe.pValue = have.data();
                if (serveAttribute(*slot, *obj, probe) != CKR_OK ||
                    std::memcmp(have.data(), want.pValue, have.size()) != 0)
                    return true;
            }
            return false;
        });
    }
    s->find.next = 0;
    s->find.active = true;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->find.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    CK_ULONG n = 0;
    while (n < ulMaxObjectCount && s->find.next < s->find.matches.size())
        phObject[n++] = s->find.matches[s->find.next++];
    *pulObjectCount = n;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->find.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    s->find = FindCursor{};
    return CKR_OK;
    PKCS11_CATCH
}

// ===========================================================================
// Encryption (deferred — the module never encrypts; no libcrypto linked)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
 CK_ULONG_PTR pulEncryptedDataLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pEncryptedData;
    (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    (void)hSession;
    (void)pLastEncryptedPart;
    (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Decryption -> agent Decrypt (RSA PKCS#1 v1.5)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->decrypt.active)
        return CKR_OPERATION_ACTIVE;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (!slot)
        return CKR_SESSION_HANDLE_INVALID;
    // Only CKM_RSA_PKCS decrypt; reject anything else (incl. when the slot does
    // not advertise it, e.g. NAM v1 -> CKR_MECHANISM_INVALID).
    if (pMechanism->mechanism != CKM_RSA_PKCS || !slotHasMechanism(*slot, CKM_RSA_PKCS))
        return CKR_MECHANISM_INVALID;
    const Object* obj = g_lib->state.resolveObject(s->slot, hKey);
    if (!obj || obj->cls != CKO_PRIVATE_KEY)
        return CKR_KEY_HANDLE_INVALID;
    // RSA PKCS#1 v1.5 decrypts with an RSA key only, decided without the card.
    if (obj->keyType != KeyType::Rsa)
        return CKR_KEY_TYPE_INCONSISTENT;
    if (!obj->decrypt)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    s->decrypt = DecryptCursor{};
    s->decrypt.active = true;
    s->decrypt.reader = slot->readerPath;
    s->decrypt.certId = obj->certId;
    s->decrypt.keyBits = obj->keyBits;
    return CKR_OK;
    PKCS11_CATCH
}

namespace {

// Drive one C_Decrypt / C_DecryptFinal. @p ct/ctLen is the full ciphertext block
// (single-part: the C_Decrypt argument; multi-part: the C_DecryptUpdate buffer
// snapshotted under lock and passed via @p useAccumulated). RSA is a single
// public-key block, so the agent's existing single-part Decrypt RPC services
// both: multi-part is just a deferred single-part. The blocking on-card decrypt
// runs with g_mutex RELEASED (it waits on the same PIN lease as a sign), so the
// lock is held only to validate the session + capture the cursor, then again to
// record the outcome. Re-entrant blocking ops on the same session are refused.
CK_RV doDecrypt(CK_SESSION_HANDLE hSession, const std::uint8_t* ct, std::size_t ctLen, bool useAccumulated,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    if (pulDataLen == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    // --- under lock: validate + capture (reader, certId), mark in-flight ----
    std::string reader;
    std::string certId;
    std::uint32_t keyBits = 0;
    std::vector<std::uint8_t> accumulated; // the C_DecryptFinal multi-part buffer
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (!s->decrypt.active)
            return CKR_OPERATION_NOT_INITIALIZED;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        reader = s->decrypt.reader;
        certId = s->decrypt.certId;
        keyBits = s->decrypt.keyBits;
        if (useAccumulated)
            accumulated = s->decrypt.accumulated; // snapshot before releasing the lock
        // RAII: sets s->rpcInFlight + bumps the global in-flight count; cleared on
        // EVERY exit path, including a std::bad_alloc thrown by the ciphertext
        // buffer build below — otherwise the flag would leak and wedge the
        // session at CKR_OPERATION_ACTIVE.
        guard.emplace(s);
        guard->setHandle(hSession);
    }
    if (useAccumulated) {
        ct = accumulated.data();
        ctLen = accumulated.size();
    }

    // Cursor management only (the guard owns rpcInFlight + the global count).
    auto clearCursorIf = [&](bool clearCursor) {
        if (!clearCursor)
            return;
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return;
        if (Session* s = g_lib->state.session(hSession))
            s->decrypt = DecryptCursor{};
    };

    // --- lock RELEASED for the blocking on-card decrypt ----------------------
    // Size query: the modulus length, from the model, bounds any PKCS#1 v1.5
    // plaintext (PKCS#11 lets a length answer be somewhat larger than the
    // result); it never decrypts. A non-NULL buffer still goes to the card: the
    // plaintext's length is known only once decrypted.
    if (pData == NULL_PTR && keyBits != 0) {
        *pulDataLen = (keyBits + 7) / 8;
        return CKR_OK;
    }
    std::vector<std::uint8_t> ciphertext(ct, ct + ctLen);
    auto res = g_lib->client->decrypt(reader, certId, ciphertext);
    // The plaintext is the caller's once copied out; this copy is wiped on
    // every way out, as a derived secret is.
    const LibreSCRS::Agent::SecureZeroOnExit wipe{res.bytes};
    if (res.status != Status::Ok) {
        clearCursorIf(/*clearCursor=*/true);
        dropLoginOnLapsedLease(res.status, hSession);
        return ckrFromStatus(res.status, CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    if (pData == NULL_PTR) {
        *pulDataLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false); // size query keeps the operation active
        return CKR_OK;
    }
    if (*pulDataLen < res.bytes.size()) {
        *pulDataLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false);
        return CKR_BUFFER_TOO_SMALL;
    }
    std::memcpy(pData, res.bytes.data(), res.bytes.size());
    *pulDataLen = static_cast<CK_ULONG>(res.bytes.size());
    clearCursorIf(/*clearCursor=*/true);
    return CKR_OK;
}

} // namespace

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
 CK_ULONG_PTR pulDataLen)
{
    PKCS11_TRY
    return doDecrypt(hSession, pEncryptedData, ulEncryptedDataLen, /*useAccumulated=*/false, pData, pulDataLen);
    PKCS11_CATCH
}

// Multi-part decrypt buffers the ciphertext across C_DecryptUpdate calls (RSA is
// a single public-key block, so this is a small bounded buffer) and runs the one
// on-card decrypt at C_DecryptFinal. Standard tools (pkcs11-tool, NSS) drive this
// path. C_DecryptUpdate yields NO intermediate plaintext — for RSA all output
// emerges at C_DecryptFinal — so it always reports zero output bytes.
CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
 CK_ULONG_PTR pulPartLen)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->decrypt.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (s->rpcInFlight)
        return CKR_OPERATION_ACTIVE;
    if (pEncryptedPart != NULL_PTR && ulEncryptedPartLen > 0)
        s->decrypt.accumulated.insert(s->decrypt.accumulated.end(), pEncryptedPart,
                                      pEncryptedPart + ulEncryptedPartLen);
    // No intermediate plaintext for RSA; report zero output. pPart is ignored —
    // for a single-block cipher the plaintext only emerges at C_DecryptFinal.
    (void)pPart;
    if (pulPartLen != NULL_PTR)
        *pulPartLen = 0;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    PKCS11_TRY
    return doDecrypt(hSession, nullptr, 0, /*useAccumulated=*/true, pLastPart, pulLastPartLen);
    PKCS11_CATCH
}

// ===========================================================================
// Message digesting (deferred — no libcrypto)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    (void)hSession;
    (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Digest)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Signing -> agent SignRaw (raw RSA PKCS#1 v1.5; caller supplies the DigestInfo)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->sign.active)
        return CKR_OPERATION_ACTIVE;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (!slot)
        return CKR_SESSION_HANDLE_INVALID;
    const CK_MECHANISM_TYPE mech = pMechanism->mechanism;
    // Three sign mechanisms, each only where the slot advertised it: the two
    // RSA families (CKM_RSA_PKCS over a caller-built DigestInfo; CKM_SHA256_RSA_PKCS
    // over the raw message the card hashes) and CKM_ECDSA over the caller's digest.
    // The module never hashes. PSS and anything else: CKR_MECHANISM_INVALID.
    if ((mech != CKM_RSA_PKCS && mech != CKM_SHA256_RSA_PKCS && mech != CKM_ECDSA) || !slotHasMechanism(*slot, mech))
        return CKR_MECHANISM_INVALID;
    const Object* obj = g_lib->state.resolveObject(s->slot, hKey);
    if (!obj || obj->cls != CKO_PRIVATE_KEY)
        return CKR_KEY_HANDLE_INVALID;
    // The pairing is the key's family, decided without the card.
    if ((mech == CKM_ECDSA) != (obj->keyType == KeyType::Ec))
        return CKR_KEY_TYPE_INCONSISTENT;
    if (!obj->sign)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;

    s->sign = SignCursor{};
    s->sign.active = true;
    s->sign.reader = slot->readerPath;
    s->sign.certId = obj->certId;
    s->sign.mechanism = mech;
    s->sign.keyType = obj->keyType;
    s->sign.keyBits = obj->keyBits;
    return CKR_OK;
    PKCS11_CATCH
}

namespace {

// Drive one C_Sign / C_SignFinal. @p data/len is the digest-or-block to sign.
// The blocking publicKey/signRaw RPCs run with g_mutex RELEASED (a sign waits on
// a human-paced PIN prompt), so the global lock is held only to validate the
// session + capture the cursor, then again to record the outcome. Re-entrant
// blocking ops on the same session are refused.
CK_RV doSign(CK_SESSION_HANDLE hSession, const std::uint8_t* data, std::size_t len, bool useAccumulated,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    if (pulSignatureLen == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    // --- under lock: validate + capture the cursor, mark in-flight ----------
    std::string reader;
    std::string certId;
    CK_MECHANISM_TYPE mech = CKM_RSA_PKCS;
    KeyType keyType = KeyType::Other;
    std::uint32_t keyBits = 0;
    std::vector<std::uint8_t> accumulated; // the C_SignFinal multi-part buffer
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (!s->sign.active)
            return CKR_OPERATION_NOT_INITIALIZED;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        reader = s->sign.reader;
        certId = s->sign.certId;
        mech = s->sign.mechanism;
        keyType = s->sign.keyType;
        keyBits = s->sign.keyBits;
        if (useAccumulated)
            accumulated = s->sign.accumulated; // snapshot before releasing the lock
        // RAII: sets s->rpcInFlight + bumps the global in-flight count; cleared on
        // EVERY exit path, including a std::bad_alloc thrown by buildSignInput
        // below — otherwise the flag would leak + wedge the session.
        guard.emplace(s);
        guard->setHandle(hSession);
    }
    if (useAccumulated) {
        data = accumulated.data();
        len = accumulated.size();
    }

    // Cursor management only (the guard owns rpcInFlight + the global count).
    auto clearCursorIf = [&](bool clearCursor) {
        if (!clearCursor)
            return;
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return;
        if (Session* s = g_lib->state.session(hSession))
            s->sign = SignCursor{};
    };

    // --- lock RELEASED for the blocking RPCs --------------------------------
    // ECDSA takes the digest itself: SHA-256, -384 or -512. Deliberately
    // narrower than v2.40, which lets a longer input be truncated -- a SHA-1
    // digest is refused here, without the agent.
    if (mech == CKM_ECDSA && len != 32 && len != 48 && len != 64) {
        clearCursorIf(/*clearCursor=*/true);
        return CKR_DATA_LEN_RANGE;
    }
    // Length questions are answered from the model and NEVER reach the card:
    // a size query (NULL buffer) and a buffer shorter than the signature both
    // keep the operation active.
    if (const CK_ULONG sigLen = signatureLength(keyType, keyBits); sigLen != 0) {
        if (pSignature == NULL_PTR || *pulSignatureLen < sigLen) {
            const bool sizeQuery = (pSignature == NULL_PTR);
            *pulSignatureLen = sigLen;
            return sizeQuery ? CKR_OK : CKR_BUFFER_TOO_SMALL;
        }
    }

    std::vector<std::uint8_t> input = buildSignInput(data, len);
    auto res = g_lib->client->signRaw(reader, certId, agentSignMechanism(mech), input);
    if (res.status != Status::Ok) {
        clearCursorIf(/*clearCursor=*/true);
        dropLoginOnLapsedLease(res.status, hSession);
        return ckrFromStatus(res.status, CKR_DATA_LEN_RANGE);
    }
    // An ECDSA answer is r||s at the curve's width and nothing else: a
    // DER-shaped or truncated reply never reaches the caller as a signature.
    if (mech == CKM_ECDSA && res.bytes.size() != signatureLength(keyType, keyBits)) {
        clearCursorIf(/*clearCursor=*/true);
        return CKR_DEVICE_ERROR;
    }
    if (pSignature == NULL_PTR) {
        *pulSignatureLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false); // size query keeps the op active
        return CKR_OK;
    }
    if (*pulSignatureLen < res.bytes.size()) {
        *pulSignatureLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false);
        return CKR_BUFFER_TOO_SMALL;
    }
    std::memcpy(pSignature, res.bytes.data(), res.bytes.size());
    *pulSignatureLen = static_cast<CK_ULONG>(res.bytes.size());
    clearCursorIf(/*clearCursor=*/true);
    return CKR_OK;
}

} // namespace

CK_DECLARE_FUNCTION(CK_RV, C_Sign)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
 CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_TRY
    return doSign(hSession, pData, ulDataLen, /*useAccumulated=*/false, pSignature, pulSignatureLen);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->sign.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    s->sign.accumulated.insert(s->sign.accumulated.end(), pPart, pPart + ulPartLen);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_TRY
    return doSign(hSession, nullptr, 0, /*useAccumulated=*/true, pSignature, pulSignatureLen);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
 CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Verifying (deferred — no libcrypto linked)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Verify)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
 CK_ULONG_PTR pulDataLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Dual-function (deferred)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
 CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
 CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Key management (out of scope)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pTemplate;
    (void)ulCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
 CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pPublicKeyTemplate;
    (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate;
    (void)ulPrivateKeyAttributeCount;
    (void)phPublicKey;
    (void)phPrivateKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
 CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    (void)hSession;
    (void)pMechanism;
    (void)hWrappingKey;
    (void)hKey;
    (void)pWrappedKey;
    (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
 CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hUnwrappingKey;
    (void)pWrappedKey;
    (void)ulWrappedKeyLen;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    PKCS11_TRY
    // --- under lock: every check this module can make, before the agent and
    //     before any PIN prompt: the mechanism and its parameters, the base key,
    //     the peer's point (its curve is the agent's check), the template. ---
    std::string reader;
    std::string certId;
    std::string tokenSerial; // the card the secret is derived with
    std::vector<std::uint8_t> peerPoint;
    DerivedKeyTemplate wanted;
    CK_SLOT_ID slotId = 0;
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        if (pMechanism == NULL_PTR || phKey == NULL_PTR)
            return CKR_ARGUMENTS_BAD;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        const Slot* slot = g_lib->state.slotById(s->slot);
        if (!slot)
            return CKR_SESSION_HANDLE_INVALID;
        if (pMechanism->mechanism != CKM_ECDH1_DERIVE || !slotHasMechanism(*slot, CKM_ECDH1_DERIVE))
            return CKR_MECHANISM_INVALID;
        if (!s->loggedIn)
            return CKR_USER_NOT_LOGGED_IN;
        if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS))
            return CKR_MECHANISM_PARAM_INVALID;
        CK_ECDH1_DERIVE_PARAMS params{};
        std::memcpy(&params, pMechanism->pParameter, sizeof(params));
        // The raw secret only: a KDF or shared data is refused, never ignored.
        if (params.kdf != CKD_NULL || params.ulSharedDataLen != 0)
            return CKR_MECHANISM_PARAM_INVALID;
        const Object* base = g_lib->state.resolveObject(s->slot, hBaseKey);
        if (!base || base->cls != CKO_PRIVATE_KEY)
            return CKR_KEY_HANDLE_INVALID;
        if (base->keyType != KeyType::Ec)
            return CKR_KEY_TYPE_INCONSISTENT;
        if (!base->derive)
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        if (params.pPublicData == NULL_PTR)
            return CKR_MECHANISM_PARAM_INVALID;
        auto point = peerPointFromPublicData({params.pPublicData, params.ulPublicDataLen}, base->keyBits);
        if (!point)
            return CKR_MECHANISM_PARAM_INVALID;
        auto parsed = parseDerivedKeyTemplate(pTemplate, ulAttributeCount);
        if (!parsed)
            return parsed.error();
        // The secret is ceil(bits/8) bytes, known without the card: a key
        // longer than that is refused here, not after the card's ECDH.
        if (parsed->valueLen && *parsed->valueLen > (static_cast<CK_ULONG>(base->keyBits) + 7) / 8)
            return CKR_TEMPLATE_INCONSISTENT;
        reader = slot->readerPath;
        certId = base->certId;
        tokenSerial = slot->tokenSerial;
        peerPoint = std::move(*point);
        wanted = std::move(*parsed);
        slotId = s->slot;
        guard.emplace(s);
        guard->setHandle(hSession);
    }

    // --- lock RELEASED: the agent may ask for the PIN (human-paced). ---
    // Z and the key's value are wiped on every way out, an exception included;
    // what is kept is moved into the key, which wipes it when it goes.
    BytesResult res = g_lib->client->derive(reader, certId, peerPoint);
    const LibreSCRS::Agent::SecureZeroOnExit wipeSecret{res.bytes};
    if (res.status != Status::Ok) {
        dropLoginOnLapsedLease(res.status, hSession);
        return ckrFromStatus(res.status, CKR_MECHANISM_PARAM_INVALID);
    }
    std::vector<std::uint8_t> value;
    const LibreSCRS::Agent::SecureZeroOnExit wipeValue{value};
    {
        auto picked = derivedKeyValue(res.bytes, wanted);
        if (!picked)
            return picked.error();
        value = std::move(*picked);
    }

    // --- re-take the lock: keep the key for this application. The guard,
    //     declared first, is destroyed after this lock is released. ---
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    const Session* s = g_lib->state.session(hSession);
    if (s == nullptr)
        return CKR_SESSION_HANDLE_INVALID;
    // The lock was released for the agent: C_Logout, a lapsed lease,
    // C_CloseAllSessions or a card change may have run meanwhile and destroyed
    // the derived keys of this slot. A key stored now would outlive the login
    // or the card it was derived with, so the secret is wiped instead. On the
    // socket transport nothing refreshes the slots during the call, so a card
    // changed meanwhile is caught by the next refresh, which destroys the key
    // with the card it was derived with.
    const Slot* now = g_lib->state.slotById(slotId);
    if (now == nullptr || !now->tokenPresent || now->tokenSerial != tokenSerial)
        return CKR_DEVICE_REMOVED;
    if (!s->loggedIn)
        return CKR_USER_NOT_LOGGED_IN;
    DerivedKey key;
    key.slot = slotId;
    key.creator = hSession;
    key.attributes = std::move(wanted);
    key.value = std::move(value);
    *phKey = g_lib->state.addDerivedKey(std::move(key));
    return CKR_OK;
    PKCS11_CATCH
}

// ===========================================================================
// Random (deferred)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    (void)hSession;
    (void)pSeed;
    (void)ulSeedLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    (void)hSession;
    (void)RandomData;
    (void)ulRandomLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Parallel function management (legacy)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Slot event (live updates handled by re-snapshot in C_GetSlotList)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    (void)flags;
    (void)pSlot;
    (void)pReserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Function list table + C_GetFunctionList
// ===========================================================================

// Advertise PKCS#11 v2.40 for maximum loader compatibility (Java SunPKCS11 does
// not support v3.x and rejects a 3.x version in the function list). Mirrors the
// LibreMiddleware native module.
static CK_FUNCTION_LIST function_list = {
    {2, 40},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

extern "C" CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
