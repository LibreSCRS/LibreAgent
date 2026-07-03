// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Hermetic status the PKCS#11 host (Pkcs11Broker) maps onto the wire:
//   Ok           -> bytes returned
//   KeyNotFound  -> certId did not resolve / the cert carries no keyFID
//   AuthFailed   -> PIN wrong / card blocked (reserved; the LM raw-sign/decipher
//                   outcome does not currently distinguish auth failures from
//                   generic plugin errors, so the per-family backends below
//                   surface CardError today — the value exists so the host->wire
//                   mapping is forward-compatible when LM gains the distinction)
//   CardError    -> communication / plugin error
//   NotSupported -> the resolving plugin does not implement the primitive
//                   (host maps to CKR_FUNCTION_NOT_SUPPORTED)
enum class RawCryptoStatus : std::uint8_t {
    Ok,
    KeyNotFound,
    AuthFailed,
    CardError,
    NotSupported,
};

struct RawCryptoResult
{
    RawCryptoStatus status = RawCryptoStatus::CardError; // default fails closed
    std::vector<std::uint8_t> bytes;                     // signature or plaintext on Ok
};

// Raw RSA PKCS#1 v1.5 SIGN over @p input. Routes certId -> (plugin, keyFID) off
// the live @p session via selectSigningCandidate. The caller never supplies the
// PIN: @p pin is the eSign secret RawCryptoFlow collected from the agent prompter
// (PIN-as-consent), or null when the held channel is already PIN-verified for
// this lease.
//
// TWO CARD FAMILIES, ONE CONSENT MODEL — self-dispatch on the resolving plugin:
//   * Hash-on-card SSCDs (NAM / IAS-ECC, pkcs15-backed) override doSign for
//     SignMechanism::RSA_SHA256 over the RAW message and own the atomic
//     verify + MSE(0x28) + PSO inside PKCS15Card::sign. The PIN is handed to the
//     plugin via the per-session setCredentials("pin") seam (the same shape as
//     the CAN); we do NOT pre-verify here, because the plugin's own applet
//     re-select would clear a separate verify.
//   * DigestInfo cards (PKS / opensc-backed) do NOT override doSign for
//     RSA_SHA256: that call returns NotImplemented (no card I/O, no PIN use) and
//     we fall through to verify the PIN on-card (CardPlugin::verifyPIN, when
//     @p pin is non-null) and sign with SignMechanism::RSA_PKCS over the
//     caller-supplied DigestInfo. The opensc sc_pkcs15_compute_signature backend
//     does not verify the PIN itself, so an unverified PSO would fail
//     security-status.
// The PKCS#11 module advertises exactly ONE mechanism per card, so @p input
// already carries the right form (raw message for the hash-on-card family,
// DigestInfo for the DigestInfo family).
//
// PIN LIFETIME: the agent never caches the PIN — the lease holds only a
// verified-state boolean. For the hash-on-card family the deposited bytes live
// in the plugin's mutable, session-keyed, mutex-guarded map for the lease and
// are wiped on teardown (CardSessionHolder::invalidate -> clearCredentials).
// A null @p pin means "already verified this lease; sign directly". A card that
// rejects a non-null @p pin => AuthFailed; a resolving plugin that lacks
// verifyPIN on the DigestInfo path => CardError (fail-closed).
[[nodiscard]] RawCryptoResult signRaw(const CandidateList& candidates, const std::string& certId,
                                      std::span<const std::uint8_t> input, const LibreSCRS::Secure::String* pin,
                                      LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token);

// Raw RSA PKCS#1 v1.5 DECRYPT of @p ciphertext. Same routing + same PIN-as-
// consent verify contract as signRaw (@p pin non-null => verifyPIN on-card
// first); then CardPlugin::decipher with DecipherMechanism::RSA_PKCS1_V15.
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

// True iff the X.509 certificate @p der carries a keyUsage that permits RSA
// decryption (keyEncipherment or dataEncipherment), OR carries no keyUsage
// extension / is unparseable (permissive — the on-card op stays the final
// authority). Used by decryptRaw to reject routing a decrypt to a sign-only key:
// for PKS the signature key (ksc, no keyEncipherment) is decrypt-incapable
// and sc_pkcs15_decipher hard-fails NOT_ALLOWED on it; gating here surfaces
// NotSupported (-> CKR_KEY_FUNCTION_NOT_PERMITTED) instead of a raw CardError.
// Exposed for unit testing the pure DER predicate.
[[nodiscard]] bool certKeyUsagePermitsDecrypt(std::span<const std::uint8_t> der);

} // namespace LibreSCRS::Agent::Operations
