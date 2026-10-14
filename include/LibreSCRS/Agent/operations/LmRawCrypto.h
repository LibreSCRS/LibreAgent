// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/Agent/operations/LmSeams.h>           // SigningSelection
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/PluginTypes.h> // SignMechanism
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

struct RawCryptoFlowDeps;

// Hermetic status the PKCS#11 host (Pkcs11Broker) maps onto the wire:
//   Ok           -> bytes returned
//   KeyNotFound  -> certId did not resolve / the cert carries no keyFID
//   AuthFailed   -> the card refused the PIN handed over for this operation,
//                   or reports it blocked (the plugin's PinIncorrect /
//                   PinBlocked); the host revokes the lease
//   CardError    -> communication / plugin error
//   NotSupported -> the resolving plugin does not implement the primitive
//                   (host maps to CKR_FUNCTION_NOT_SUPPORTED)
//   ConsentRequired -> never on the wire: the card marks the resolved key for
//                   consent per operation and the op was given no PIN. The key
//                   was not used and no PIN was presented; RawCryptoFlow asks
//                   for the PIN and retries.
//   InvalidInput -> the request does not fit the key: a mechanism of the other
//                   family, an input of the wrong length, or (derive) a peer
//                   point not on the key's curve. Decided before any PIN
//                   prompt; the host maps it to InvalidRequest.
enum class RawCryptoStatus : std::uint8_t {
    Ok,
    KeyNotFound,
    AuthFailed,
    CardError,
    NotSupported,
    ConsentRequired,
    InvalidInput,
};

struct RawCryptoResult
{
    RawCryptoStatus status = RawCryptoStatus::CardError; // default fails closed
    std::vector<std::uint8_t> bytes;                     // signature, plaintext or secret on Ok
    // The resolved key's card rule (CertificateData::alwaysAuthenticate), read
    // off the card this op ran against: a verification for such a key is not
    // remembered for the lease.
    bool alwaysAuthenticate = false;
};

// What the preflight decided, and the key it resolved for the operation.
struct RawCryptoPreflight
{
    RawCryptoStatus status = RawCryptoStatus::CardError; // default fails closed
    std::optional<SigningSelection> key;                 // engaged iff status == Ok
};

// The check a raw operation passes before anyone is asked for a PIN. Resolves
// certId against the card in the reader now (selectSigningCandidate -- the read
// the operation then uses, so the card is read once), reads the key family and
// size off its certificate, and refuses:
//   KeyNotFound  -- no such certificate, or it pairs with no key;
//   NotSupported -- a decryption the certificate's keyUsage forbids, or a
//                   mechanism this agent does not run;
//   InvalidInput -- a mechanism of the other family for the key (ECDSA on RSA,
//                   RSA on EC, a decryption with an EC key), a caller-built
//                   RSA-PKCS block for a key on a PACE (CAN) card, which
//                   hashes the message itself, a message to hash on the card
//                   for any other RSA key, an input of the wrong length
//                   (ECDSA: 32/48/64; RSA-PKCS sign: 1..k-11;
//                   SHA256-RSA-PKCS: not empty; RSA-PKCS decrypt: exactly k),
//                   (derive) a peer point that is not 1 + 2*ceil(bits/8) bytes,
//                   not uncompressed or not on the key's curve, or a key the
//                   plugin does not derive with.
// No PIN is asked for or presented and the key is not used. The read runs on
// the held session, so on a cold PACE channel it may need the CAN, which
// normally comes from the credential cache.
[[nodiscard]] RawCryptoPreflight preflight(const CandidateList& candidates, const std::string& certId,
                                           Mechanism mechanism, std::span<const std::uint8_t> input,
                                           LibreSCRS::SmartCard::CardSession& session);

// Raw on-card operations with a key preflight() resolved. The caller never supplies the
// PIN: @p pin is the eSign secret RawCryptoFlow collected from the agent prompter
// (PIN-as-consent), or null when the held channel is already PIN-verified for
// this lease.
//
// ONE CARD TRANSACTION PER PIN: a non-null @p pin is handed to the resolving
// plugin (CardPlugin::setCredentials "pin"), which presents it to the card
// and uses the key inside the operation's own card transaction. There is no
// separate verifyPIN call: a key the card wants the PIN for on every operation
// (PIV 9C) loses its verified state between two plugin calls. A refused PIN
// comes back as the plugin's PinIncorrect / PinBlocked => AuthFailed.
//
// PIN LIFETIME: the lease holds only a verified-state boolean; the plugin may
// hold the deposited PIN. For a key the card marks for consent per operation a
// null @p pin returns ConsentRequired without using the key, and a deposited
// PIN is erased (only the PIN; the CAN stays) when the operation ends, on
// every way out. For an ordinary key the deposited PIN stays in the plugin's
// session-keyed storage after a successful operation (the hash-on-card family
// signs only with it) and is erased by any failure — also a refusal of a PIN
// kept from an earlier operation — by a successful PIN change
// (eraseDepositedPin) and on session teardown
// (CardSessionHolder::invalidate -> clearCredentials). The lease decides who
// may use it: a null @p pin on an ordinary key means "already verified this
// lease; sign directly". An empty @p pin is refused as AuthFailed before the
// key is used: handed to the plugin it would erase the deposit, and the card
// would run the operation on whatever the held session is verified for.

// Raw on-card SIGN with the key @p key resolved by preflight(), running exactly
// @p mechanism: RsaPkcs1Sign -> SignMechanism::RSA_PKCS (the caller's complete
// block), Sha256RsaPkcs1Sign -> RSA_SHA256 (the raw message, hashed on the
// card), EcdsaSign -> ECDSA_SHA256/384/512 by the digest's length (answered as
// r||s). A plugin that lacks the mechanism answers NotSupported; nothing else
// is tried. Consent and PIN lifetime as described above.
[[nodiscard]] RawCryptoResult signRaw(const SigningSelection& key, Mechanism mechanism,
                                      std::span<const std::uint8_t> input, const LibreSCRS::Secure::String* pin,
                                      LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token);

// Raw RSA PKCS#1 v1.5 DECRYPT (@p mechanism must be RsaPkcs1Decrypt) with the
// key resolved by preflight(), which has already refused a key whose
// certificate forbids decryption. Same consent rule and PIN lifetime as signRaw.
//
// PER-FAMILY ROUTING:
//   * PKS (opensc-backed) overrides doDecipher -> Ok / plaintext.
//   * NAM (pkcs15-backed) returns DecipherResultOutcome::NotImplemented (a real
//     NAM decrypt would need MSE-CT / PSO-DECIPHER over SM, not implemented) ->
//     RawCryptoStatus::NotSupported. The NAM token does not advertise CKF_DECRYPT,
//     so the host never reaches this for a NAM key; the explicit NotSupported
//     here is the defence-in-depth backstop.
[[nodiscard]] RawCryptoResult decryptRaw(const SigningSelection& key, Mechanism mechanism,
                                         std::span<const std::uint8_t> ciphertext, const LibreSCRS::Secure::String* pin,
                                         LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token);

// ECDH (@p mechanism must be EcdhDerive) with the key resolved by preflight(),
// which has already checked @p peerPoint against the key's curve:
// CardPlugin::decipher with DecipherMechanism::ECDH_RAW, answered with the raw
// shared secret Z of ceil(bits/8) bytes; a plugin answer of another length is
// CardError and is not passed on. Z is a secret: it is copied out of the plugin's result
// through a cleansing buffer and the plugin's copy is wiped, but the returned
// bytes are a plain vector the caller wipes once it has handed them on.
// Same consent rule and PIN lifetime as signRaw.
[[nodiscard]] RawCryptoResult deriveRaw(const SigningSelection& key, Mechanism mechanism,
                                        std::span<const std::uint8_t> peerPoint, const LibreSCRS::Secure::String* pin,
                                        LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token);

// Binds this file's operations into @p deps, each in its own slot:
// preflight, signRaw, decryptRaw and deriveRaw. The agent's PKCS#11 calls run
// the raw-crypto flow with exactly these; nothing else in @p deps is touched.
void bindLmRawCrypto(RawCryptoFlowDeps& deps);

// Erases the PIN deposited for @p session (CardPlugin::setCredentials with an
// empty "pin") on every plugin in @p candidates, and nothing else. For a
// caller that made a deposited PIN stale, such as a successful PIN change.
// Never throws; a failed erase is logged.
void eraseDepositedPin(const CandidateList& candidates, LibreSCRS::SmartCard::CardSession& session) noexcept;

// True iff the X.509 certificate @p der carries a keyUsage that permits RSA
// decryption (keyEncipherment or dataEncipherment), OR carries no keyUsage
// extension / is unparseable (permissive — the on-card op stays the final
// authority). Preflight asks only for an RSA key: a certificate it cannot
// parse is classified as another kind of key and refused InvalidInput before
// this runs. Used by preflight to reject routing a decrypt to a sign-only key:
// for PKS the signature key (ksc, no keyEncipherment) is decrypt-incapable
// and sc_pkcs15_decipher hard-fails NOT_ALLOWED on it; gating here surfaces
// NotSupported (-> CKR_KEY_FUNCTION_NOT_PERMITTED) instead of a raw CardError.
// Exposed for unit testing the pure DER predicate.
[[nodiscard]] bool certKeyUsagePermitsDecrypt(std::span<const std::uint8_t> der);

// The pre-hashed ECDSA sign mechanism for a digest of exactly @p digestLength
// bytes: 32 -> ECDSA_SHA256, 48 -> ECDSA_SHA384, 64 -> ECDSA_SHA512; nullopt
// for any other length. Exposed for unit testing the pure mapping.
[[nodiscard]] std::optional<LibreSCRS::Plugin::SignMechanism>
ecdsaMechanismForDigest(std::size_t digestLength) noexcept;

} // namespace LibreSCRS::Agent::Operations
