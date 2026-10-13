// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/PluginTypes.h> // SignMechanism
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

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
enum class RawCryptoStatus : std::uint8_t {
    Ok,
    KeyNotFound,
    AuthFailed,
    CardError,
    NotSupported,
    ConsentRequired,
};

struct RawCryptoResult
{
    RawCryptoStatus status = RawCryptoStatus::CardError; // default fails closed
    std::vector<std::uint8_t> bytes;                     // signature or plaintext on Ok
    // The resolved key's card rule (CertificateData::alwaysAuthenticate), read
    // off the card this op ran against: a verification for such a key is not
    // remembered for the lease.
    bool alwaysAuthenticate = false;
};

// Raw on-card SIGN over @p input. Routes certId -> (plugin, keyFID) off
// the live @p session via selectSigningCandidate. The caller never supplies the
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
// MECHANISM FAMILY BY THE RESOLVED KEY'S ALGORITHM: the resolved
// certificate's public key decides the family. An ECDSA key takes the
// pre-hashed ECDSA path (@p input is the pre-computed digest; the plugin
// signs it with no on-card hashing). Everything else — including an
// unparseable certificate — keeps the RSA flow.
//
// THE RSA FAMILIES — self-dispatch on the resolving plugin:
//   * Hash-on-card SSCDs (NAM / IAS-ECC, pkcs15-backed) override doSign for
//     SignMechanism::RSA_SHA256 over the RAW message and own the atomic
//     verify + MSE(0x28) + PSO inside PKCS15Card::sign.
//   * DigestInfo cards (PKS / opensc-backed) do NOT override doSign for
//     RSA_SHA256: that call returns NotImplemented (no card I/O, no PIN use) and
//     we fall through to SignMechanism::RSA_PKCS over the caller-supplied
//     DigestInfo.
// The PKCS#11 module advertises exactly ONE mechanism per card, so @p input
// already carries the right form (raw message for the hash-on-card family,
// DigestInfo for the DigestInfo family).
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
[[nodiscard]] RawCryptoResult signRaw(const CandidateList& candidates, const std::string& certId,
                                      std::span<const std::uint8_t> input, const LibreSCRS::Secure::String* pin,
                                      LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token);

// Raw RSA PKCS#1 v1.5 DECRYPT of @p ciphertext. Same routing, same consent
// rule and same PIN lifetime as signRaw (a non-null @p pin is handed to the
// plugin for this operation and erased after it); then CardPlugin::decipher
// with DecipherMechanism::RSA_PKCS1_V15. A certificate whose keyUsage forbids
// decryption answers NotSupported before the consent rule, so a refused
// decryption never asks for a PIN.
//
// PER-FAMILY ROUTING:
//   * PKS (opensc-backed) overrides doDecipher -> Ok / plaintext.
//   * NAM (pkcs15-backed) returns DecipherResultOutcome::NotImplemented (a real
//     NAM decrypt would need MSE-CT / PSO-DECIPHER over SM, not implemented) ->
//     RawCryptoStatus::NotSupported. The NAM token does not advertise CKF_DECRYPT,
//     so the host never reaches this for a NAM key; the explicit NotSupported
//     here is the defence-in-depth backstop.
[[nodiscard]] RawCryptoResult decryptRaw(const CandidateList& candidates, const std::string& certId,
                                         std::span<const std::uint8_t> ciphertext, const LibreSCRS::Secure::String* pin,
                                         LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token);

// Erases the PIN deposited for @p session (CardPlugin::setCredentials with an
// empty "pin") on every plugin in @p candidates, and nothing else. For a
// caller that made a deposited PIN stale, such as a successful PIN change.
// Never throws; a failed erase is logged.
void eraseDepositedPin(const CandidateList& candidates, LibreSCRS::SmartCard::CardSession& session) noexcept;

// True iff the X.509 certificate @p der carries a keyUsage that permits RSA
// decryption (keyEncipherment or dataEncipherment), OR carries no keyUsage
// extension / is unparseable (permissive — the on-card op stays the final
// authority). Used by decryptRaw to reject routing a decrypt to a sign-only key:
// for PKS the signature key (ksc, no keyEncipherment) is decrypt-incapable
// and sc_pkcs15_decipher hard-fails NOT_ALLOWED on it; gating here surfaces
// NotSupported (-> CKR_KEY_FUNCTION_NOT_PERMITTED) instead of a raw CardError.
// Exposed for unit testing the pure DER predicate.
[[nodiscard]] bool certKeyUsagePermitsDecrypt(std::span<const std::uint8_t> der);

// True iff the X.509 certificate @p der advertises an ECDSA public key —
// the signRaw mechanism-family criterion. Unparseable DER and every other
// algorithm report false: the RSA flow stays the default and the card
// remains the final authority. Exposed for unit testing the pure DER
// predicate.
[[nodiscard]] bool certPublicKeyIsEcdsa(std::span<const std::uint8_t> der);

// The pre-hashed ECDSA sign mechanism whose canonical digest length matches
// @p digestLength: <=32 -> ECDSA_SHA256, <=48 -> ECDSA_SHA384, longer ->
// ECDSA_SHA512. The resolving plugin signs the bytes as-given (no on-card
// hashing), so the value only names the digest family for the transport.
// Exposed for unit testing the pure mapping.
[[nodiscard]] LibreSCRS::Plugin::SignMechanism ecdsaMechanismForDigestLength(std::size_t digestLength) noexcept;

} // namespace LibreSCRS::Agent::Operations
