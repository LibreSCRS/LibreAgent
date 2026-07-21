// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/LmRawCrypto.h>

#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/operations/LmSeams.h> // selectSigningCandidate, SigningSelection

#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>

#include <algorithm>
#include <cstdint>
#include <optional>

namespace LibreSCRS::Agent::Operations {

namespace {

RawCryptoResult err(RawCryptoStatus s)
{
    return RawCryptoResult{.status = s, .bytes = {}};
}

// LM raw-sign outcome -> hermetic status. SignResultOutcome carries no
// AuthFailed/CardBlocked distinction (PluginError is the single failure bucket),
// so a wrong PIN surfaces as CardError here — the lease/prompter layer owns the
// retry posture; RawCryptoStatus::AuthFailed is reserved for when LM grows the
// distinction. NotImplemented (the pkcs15/NAM family that does not override
// doSign) maps to NotSupported so the host returns CKR_FUNCTION_NOT_SUPPORTED.
RawCryptoStatus mapSignOutcome(LibreSCRS::Plugin::SignResultOutcome o) noexcept
{
    using O = LibreSCRS::Plugin::SignResultOutcome;
    switch (o) {
    case O::Ok:
        return RawCryptoStatus::Ok;
    case O::NotImplemented:
        return RawCryptoStatus::NotSupported;
    case O::Cancelled:
    case O::PluginError:
    case O::Unspecified:
        return RawCryptoStatus::CardError;
    }
    return RawCryptoStatus::CardError;
}

RawCryptoStatus mapDecipherOutcome(LibreSCRS::Plugin::DecipherResultOutcome o) noexcept
{
    using O = LibreSCRS::Plugin::DecipherResultOutcome;
    switch (o) {
    case O::Ok:
        return RawCryptoStatus::Ok;
    case O::NotImplemented:
        return RawCryptoStatus::NotSupported;
    case O::Cancelled:
    case O::PluginError:
    case O::Unspecified:
        return RawCryptoStatus::CardError;
    }
    return RawCryptoStatus::CardError;
}

// Verify @p pin on-card via the resolving plugin BEFORE the raw PSO. The
// opensc sc_pkcs15_compute_signature / decipher backends do not verify the PIN
// themselves, so an unverified PSO fails security-status. Returns std::nullopt on
// success (proceed to the op) or a terminal RawCryptoStatus to surface:
//   InvalidPin / Blocked / UserCancelled / MissingFields          -> AuthFailed
//   Unsupported (plugin has no verifyPIN) / PluginError /
//     Unspecified / KeyActivationFailed                           -> CardError (fail-closed)
std::optional<RawCryptoStatus> verifyPinOnCard(const LibreSCRS::Plugin::CardPlugin& plugin,
                                               LibreSCRS::SmartCard::CardSession& session,
                                               const LibreSCRS::Secure::String& pin)
{
    const auto pr = plugin.verifyPIN(session, pin);
    using O = LibreSCRS::Plugin::PINResultOutcome;
    switch (pr.outcome) {
    case O::Ok:
        return std::nullopt;
    case O::InvalidPin:
    case O::Blocked:
    case O::UserCancelled:
    case O::MissingFields:
        return RawCryptoStatus::AuthFailed;
    case O::Unsupported:
        // The resolving plugin advertises PinManagement (it is a signing
        // candidate) but did not override verifyPIN — a contract violation; fail
        // closed rather than letting an unverified PSO hit the card.
        log::warn("rawcrypto: resolving plugin does not implement verifyPIN; refusing the unverified PSO");
        return RawCryptoStatus::CardError;
    case O::PluginError:
    case O::Unspecified:
    case O::KeyActivationFailed:
        // KeyActivationFailed cannot arise from a bare verifyPIN in this
        // PKCS#11-login/raw-crypto path (no key ACTIVATE step is requested here);
        // treat it as an unexpected plugin outcome and fail closed like
        // PluginError/Unspecified rather than let an unverified PSO hit the card.
        return RawCryptoStatus::CardError;
    }
    return RawCryptoStatus::CardError;
}

} // namespace

bool certKeyUsagePermitsDecrypt(std::span<const std::uint8_t> der)
{
    auto parsed = LibreSCRS::Certificate::ParsedCertificate::fromDer(der);
    if (!parsed) {
        return true; // unparseable -> defer to the card
    }
    const auto ku = parsed->keyUsage();
    if (!ku) {
        return true; // no keyUsage extension -> permissive
    }
    using KU = LibreSCRS::Certificate::KeyUsageBit;
    for (const auto bit : *ku) {
        if (bit == KU::KeyEncipherment || bit == KU::DataEncipherment) {
            return true;
        }
    }
    return false;
}

RawCryptoResult signRaw(const CandidateList& candidates, const std::string& certId, std::span<const std::uint8_t> input,
                        const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession& session,
                        LibreSCRS::CancelToken token)
{
    // Anti-TOCTOU routing reused from the AdES path: resolve certId against the
    // card present NOW, returning the owning plugin + the exact CertificateData.
    auto selection = selectSigningCandidate(candidates, certId, session);
    if (!selection || !selection->cert.keyFID.has_value()) {
        return err(RawCryptoStatus::KeyNotFound);
    }
    // Two card families, one consent model (the caller never supplies a PIN —
    // it was collected by the agent prompter):
    //   * Hash-on-card SSCDs (NAM / IAS-ECC pkcs15) expose doSign(RSA_SHA256)
    //     over the RAW message and own the atomic verify + MSE(0x28) + PSO
    //     inside PKCS15Card::sign, so we hand them the PIN via the per-session
    //     setCredentials("pin") seam (the same shape as the CAN) and do NOT
    //     pre-verify here — a separate verify would be cleared by the plugin's
    //     own applet re-select.
    //   * DigestInfo cards (PKS / opensc) verify-then-sign with raw RSA_PKCS
    //     over a caller-supplied DigestInfo.
    // Self-dispatch: try the hash-on-card mechanism first; a plugin without it
    // returns NotImplemented (no card I/O, no PIN use) and we fall through to
    // the verify + RSA_PKCS path. PKS's opensc plugin inherits the no-op
    // setCredentials, so depositing "pin" is harmless for it. The module
    // advertises exactly one mechanism per card, so `input` already carries the
    // right form (raw message for NAM, DigestInfo for PKS).
    if (pin) {
        // setCredentials is non-const, but the candidate routing
        // holds plugins as shared_ptr<const CardPlugin> because the read-only
        // crypto NVIs (sign / decipher / verifyPIN) are const. Depositing a
        // per-session credential is a *logically const* mutation: the pkcs15
        // plugin stores it in a `mutable`, session-keyed, mutex-guarded map —
        // the very map canHandle() already writes from a const method — and the
        // loaded plugin object is not truly const, so this const_cast is
        // well-defined. PKS's opensc plugin inherits the no-op base, so this is
        // a harmless no-op for it.
        const_cast<LibreSCRS::Plugin::CardPlugin&>(*selection->plugin).setCredentials(session, "pin", *pin);
    }
    auto sr = selection->plugin->sign(session, *selection->cert.keyFID, input,
                                      LibreSCRS::Plugin::SignMechanism::RSA_SHA256, token);
    if (sr.outcome == LibreSCRS::Plugin::SignResultOutcome::NotImplemented) {
        // DigestInfo family: PIN-as-consent verify on-card before the PSO when a
        // PIN was just collected; verify + sign run back-to-back on the held
        // channel so a PIN-ALWAYS key keeps its verified state for the sign.
        if (pin) {
            if (const auto fail = verifyPinOnCard(*selection->plugin, session, *pin)) {
                return err(*fail);
            }
        }
        sr = selection->plugin->sign(session, *selection->cert.keyFID, input,
                                     LibreSCRS::Plugin::SignMechanism::RSA_PKCS, token);
    }
    RawCryptoResult out;
    out.status = mapSignOutcome(sr.outcome);
    if (out.status == RawCryptoStatus::Ok) {
        out.bytes = sr.signature;
    } else if (out.status == RawCryptoStatus::NotSupported) {
        // Neither a hash-on-card (RSA_SHA256) nor a DigestInfo (RSA_PKCS) sign
        // primitive on the resolving plugin. Surface explicitly so the host
        // returns CKR_FUNCTION_NOT_SUPPORTED rather than a silent failure.
        log::warn("rawcrypto: signRaw resolved to a plugin with no usable sign primitive");
    }
    return out;
}

RawCryptoResult decryptRaw(const CandidateList& candidates, const std::string& certId,
                           std::span<const std::uint8_t> ciphertext, const LibreSCRS::Secure::String* pin,
                           LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token)
{
    auto selection = selectSigningCandidate(candidates, certId, session);
    if (!selection || !selection->cert.keyFID.has_value()) {
        return err(RawCryptoStatus::KeyNotFound);
    }
    // Key-usage routing assertion: the resolved key must permit decrypt. For
    // PKS the signature key (ksc, no keyEncipherment) is decrypt-incapable and
    // sc_pkcs15_decipher hard-fails NOT_ALLOWED; surface NotSupported (->
    // CKR_KEY_FUNCTION_NOT_PERMITTED) rather than a raw CardError so the app gets
    // a meaningful failure. The decrypt-capable key (kxc, keyEncipherment) passes.
    if (!certKeyUsagePermitsDecrypt(selection->cert.derBytes)) {
        log::warn("rawcrypto: decryptRaw resolved to a key whose certificate keyUsage forbids decryption");
        return err(RawCryptoStatus::NotSupported);
    }
    // PIN-as-consent: verify on-card before the PSO when a PIN was just
    // collected. verify + decipher run back-to-back on the held channel.
    if (pin) {
        if (const auto fail = verifyPinOnCard(*selection->plugin, session, *pin)) {
            return err(*fail);
        }
    }
    auto dr = selection->plugin->decipher(session, *selection->cert.keyFID, ciphertext,
                                          LibreSCRS::Plugin::DecipherMechanism::RSA_PKCS1_V15, token);
    RawCryptoResult out;
    out.status = mapDecipherOutcome(dr.outcome);
    if (out.status == RawCryptoStatus::Ok) {
        // The recovered plaintext is SENSITIVE. Hold it in a cleansing
        // Secure::Buffer, copy the bytes the host must return, then let the
        // Secure::Buffer scrub its storage on scope exit; also wipe the LM
        // result vector's copy so no plaintext lingers in a non-cleansing heap
        // allocation. The host owns cleansing the bytes it ultimately hands to
        // the (trusted) PKCS#11 module over the owner-scoped socket.
        const LibreSCRS::Secure::Buffer recovered{std::span<const std::uint8_t>{dr.plaintext}};
        out.bytes.assign(recovered.data(), recovered.data() + recovered.size());
        if (!dr.plaintext.empty()) {
            std::fill(dr.plaintext.begin(), dr.plaintext.end(), std::uint8_t{0});
        }
    } else if (out.status == RawCryptoStatus::NotSupported) {
        // The resolving plugin is the pkcs15/NAM family (no doDecipher override).
        // Surface the gap explicitly so the host returns
        // CKR_FUNCTION_NOT_SUPPORTED rather than a silent failure. Mirrors the
        // matching warn in signRaw. See the header's PER-FAMILY ROUTING note.
        log::warn("rawcrypto: decryptRaw resolved to a plugin without a raw-decipher primitive (pkcs15/NAM family)");
    }
    return out;
}

} // namespace LibreSCRS::Agent::Operations
