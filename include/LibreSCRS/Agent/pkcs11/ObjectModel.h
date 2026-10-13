// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure mapping: an agent snapshot (readers/cards/signing certs + per-cert
// capability flags) -> PKCS#11 slots / tokens / objects / mechanisms. No D-Bus,
// no card I/O, no crypto — fully unit-testable.
//
// One slot per reader. CKF_TOKEN_PRESENT iff the reader has a card. For each
// signing cert on a present card the model emits three objects sharing one
// CKA_ID: a CKO_CERTIFICATE, a CKO_PUBLIC_KEY, and a non-extractable
// CKO_PRIVATE_KEY. The private key's CKA_SIGN / CKA_DECRYPT and the token's
// mechanism set are derived ENTIRELY from the agent-reported capabilities
// (canSign / canDecrypt / signsHashOnCard), never from the card type: a
// hash-on-card token (canSign + signsHashOnCard) advertises CKM_SHA256_RSA_PKCS
// sign-only, a DigestInfo token advertises CKM_RSA_PKCS, and a card the agent
// cannot drive (canSign == canDecrypt == false) advertises no mechanisms and a
// key with neither CKA_SIGN nor CKA_DECRYPT.

#pragma once

#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief One signing certificate reported by the agent for a card.
struct CertEntry
{
    std::string certId;              ///< Opaque stable id (== sha256hex of DER).
    std::string label;               ///< Display label (CKA_LABEL): the subject CN, else certId.
    std::string holderName;          ///< The subject CN alone; empty when the cert has none.
    std::vector<std::uint8_t> ckaId; ///< Shared CKA_ID for the cert + key pair.
    bool signingCapable = false;     ///< Paired on-card key + signing-suitable keyUsage.
    bool canSign = false;            ///< Agent can drive on-card RSA sign for this key.
    bool canDecrypt = false;         ///< Agent can drive on-card RSA decrypt for this key.
    bool signsHashOnCard = false;    ///< Card hashes on-card (NAM/IAS-ECC): advertise
                                     ///< CKM_SHA256_RSA_PKCS (raw message in), not
                                     ///< CKM_RSA_PKCS (caller-built DigestInfo).
    bool alwaysAuthenticate = false; ///< The card's per-operation PIN rule for this key
                                     ///< (PKCS#15 userConsent, PIV PIN-always).
    std::uint32_t modulusBits = 0;   ///< RSA modulus size in bits (0 if unknown).
};

/// @brief One reader (+ optional card) reported by the agent.
struct ReaderState
{
    std::string readerPath; ///< The agent's handle for the reader (bus object path or socket handle).
    /// @brief The reader's PC/SC name, as the agent reports it.
    ///
    /// Display only: CK_SLOT_INFO.slotDescription and the token label's
    /// fallback. readerPath stays the key every call is addressed by. Empty
    /// when the agent reported none; the module then describes the slot by
    /// readerPath.
    std::string readerName;
    bool hasCard = false; ///< A card is seated.
    /// @brief CK_TOKEN_INFO.label: what a loader shows the user for this token.
    ///
    /// Filled by the transport with tokenLabelFor(): the display label of the
    /// card's first signing certificate -- the holder's name, as other PKCS#11
    /// modules label a personal token -- otherwise the reader's name. Empty
    /// only when the agent reported neither; the module then falls back to a
    /// fixed label.
    std::string tokenLabel;
    /// @brief CK_TOKEN_INFO.serialNumber: tells two seated cards apart.
    ///
    /// Filled by the transport with tokenSerialFor() over the agent's handle
    /// for the seated card. That handle is minted per insertion and never
    /// reused while the agent runs, so the serial is stable for as long as the
    /// card stays in the reader and differs between any two cards seated at
    /// the same time -- which is what a loader such as NSS keys a token on when
    /// two tokens carry the same label. It is not a card fingerprint: the same
    /// card re-inserted, or seen by a restarted agent, gets a new one. Empty
    /// when no card is seated.
    std::string tokenSerial;
    std::vector<CertEntry> certs; ///< Signing certs on the card (empty if none / no card).
};

/// @brief The token label a transport reports for a seated card.
///
/// The agent's card type is deliberately not used: it is a plugin identifier
/// ("opensc"), which names a driver rather than anything a user recognises.
/// The reader's name alone does not work either: two slots of one reader share
/// a name that differs only past the label field's 32 bytes.
///
/// @param certs      The card's certificates, as the transport filled them.
/// @param readerName The reader's display name.
/// @return The holder name (subject CN) of the first signing-capable
///         certificate in @p certs that has one, otherwise @p readerName.
///         Never CertEntry::label, which falls back to the certificate's hex
///         id. Not truncated here: the module fits it into the 32-byte field
///         on a UTF-8 character boundary.
[[nodiscard]] inline std::string tokenLabelFor(const std::vector<CertEntry>& certs, std::string_view readerName)
{
    for (const auto& cert : certs) {
        if (cert.signingCapable && !cert.holderName.empty()) {
            return cert.holderName;
        }
    }
    return std::string{readerName};
}

/// @brief Maximum length of CK_TOKEN_INFO.serialNumber, in bytes.
inline constexpr std::size_t kTokenSerialMaxBytes = 16;

/// @brief The token serial a transport reports for a seated card.
///
/// @param cardHandle The agent's handle for the seated card: a bus object path
///        ("/org/librescrs/Agent/card/7") or a socket handle ("obj/7").
/// @return The handle's last '/'-separated segment, which is where both
///         transports put the counter they mint per object; the fixed prefix
///         in front of it would only spend the field's 16 bytes. If that
///         segment is still longer than kTokenSerialMaxBytes, its LAST
///         kTokenSerialMaxBytes bytes: a counter differs in its trailing
///         digits, and keeping the head instead would make two cards collide.
[[nodiscard]] inline std::string tokenSerialFor(std::string_view cardHandle)
{
    if (const auto slash = cardHandle.rfind('/'); slash != std::string_view::npos) {
        cardHandle.remove_prefix(slash + 1);
    }
    if (cardHandle.size() > kTokenSerialMaxBytes) {
        cardHandle.remove_prefix(cardHandle.size() - kTokenSerialMaxBytes);
    }
    return std::string{cardHandle};
}

/// @brief A full agent enumeration snapshot.
struct AgentSnapshot
{
    std::vector<ReaderState> readers;
};

/// @brief A PKCS#11 object (cert or key) derived from a CertEntry.
struct Object
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    std::vector<std::uint8_t> ckaId;
    std::string label;
    std::string certId;              ///< Owning cert id (for lazy CKA_VALUE / agent calls).
    std::uint32_t modulusBits = 0;   ///< For key objects: RSA modulus bits.
    bool sign = false;               ///< CKA_SIGN (private key).
    bool decrypt = false;            ///< CKA_DECRYPT (private key).
    bool alwaysAuthenticate = false; ///< CKA_ALWAYS_AUTHENTICATE (private key): the card's rule.
};

/// @brief A PKCS#11 slot (one per reader) + its token state.
struct Slot
{
    std::string readerPath;
    std::string readerName; ///< See ReaderState::readerName.
    bool tokenPresent = false;
    bool protectedAuthPath = true; ///< Always true — the agent prompter collects the PIN.
    std::string tokenLabel;
    std::string tokenSerial;
    std::vector<Object> objects;               ///< Empty when no token present.
    std::vector<CK_MECHANISM_TYPE> mechanisms; ///< Capability-advertised; empty for gated tokens.
};

/// @brief The complete slot/token/object/mechanism model.
struct ObjectModel
{
    std::vector<Slot> slots;

    /// @brief Build the model from an agent snapshot (pure).
    [[nodiscard]] static ObjectModel build(const AgentSnapshot& snapshot);
};

} // namespace LibreSCRS::Pkcs11Agent
