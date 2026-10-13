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

// LM raw-sign outcome -> hermetic status. PinIncorrect / PinBlocked come from
// the plugin presenting the PIN handed over for this operation (VERIFY and the
// key operation in one card transaction): the same answer a rejected verifyPIN
// gave, AuthFailed, on which the host revokes the lease and the next operation
// asks again. Any other failure (PluginError) stays CardError. NotImplemented
// (the family that does not override doSign) maps to NotSupported so the host
// returns CKR_FUNCTION_NOT_SUPPORTED.
RawCryptoStatus mapSignOutcome(LibreSCRS::Plugin::SignResultOutcome o) noexcept
{
    using O = LibreSCRS::Plugin::SignResultOutcome;
    switch (o) {
    case O::Ok:
        return RawCryptoStatus::Ok;
    case O::NotImplemented:
        return RawCryptoStatus::NotSupported;
    case O::PinIncorrect:
    case O::PinBlocked:
        return RawCryptoStatus::AuthFailed;
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
    case O::PinIncorrect:
    case O::PinBlocked:
        // Same answer as the sign path: the card refused this operation's PIN.
        return RawCryptoStatus::AuthFailed;
    case O::Cancelled:
    case O::PluginError:
    case O::Unspecified:
        return RawCryptoStatus::CardError;
    }
    return RawCryptoStatus::CardError;
}

// Erases the PIN deposited with @p plugin for @p session. An empty value
// erases that one credential and nothing else, so the channel's other
// credentials (the CAN that re-opens secure messaging) stay. setCredentials
// may throw (allocation, a session that went away); this must not, and losing
// the erase is logged, never fatal.
void erasePinFrom(LibreSCRS::Plugin::CardPlugin& plugin, LibreSCRS::SmartCard::CardSession& session) noexcept
{
    try {
        plugin.setCredentials(session, "pin", LibreSCRS::Secure::String{});
    } catch (...) {
        try {
            log::warn("rawcrypto: could not erase the deposited PIN from the plugin");
        } catch (...) {
            // Nothing left to report through; the session is torn down with the card.
        }
    }
}

// Erases the resolved plugin's deposited PIN on every way out of one
// operation unless keepForTheLease() says it may stay. Armed whether or not
// this operation deposited a PIN: an ordinary key's PIN kept from an earlier
// operation is what the plugin presents when none is given, and a card that
// refuses it must not see it again.
class PinDepositEraser
{
public:
    PinDepositEraser(LibreSCRS::Plugin::CardPlugin& plugin, LibreSCRS::SmartCard::CardSession& session) noexcept
        : m_plugin(&plugin), m_session(session)
    {}
    ~PinDepositEraser()
    {
        if (m_plugin != nullptr) {
            erasePinFrom(*m_plugin, m_session);
        }
    }
    // Called once the outcome is known: the PIN an ordinary key just signed
    // or deciphered with stays deposited for the rest of the lease (the
    // session's teardown erases it). Any other outcome, and every exception,
    // erases it here.
    void keepForTheLease(bool keep) noexcept
    {
        if (keep) {
            m_plugin = nullptr;
        }
    }
    PinDepositEraser(const PinDepositEraser&) = delete;
    PinDepositEraser& operator=(const PinDepositEraser&) = delete;

private:
    LibreSCRS::Plugin::CardPlugin* m_plugin;
    LibreSCRS::SmartCard::CardSession& m_session;
};

// The resolved plugin, for its per-session PIN deposit. setCredentials is
// non-const, but the candidate routing holds plugins as
// shared_ptr<const CardPlugin> because the crypto NVIs (sign / decipher) are
// const. Depositing a per-session credential is a *logically const* mutation:
// the plugins keep it in session-keyed, mutex-guarded storage and the loaded
// plugin object is not truly const, so this const_cast is well-defined.
LibreSCRS::Plugin::CardPlugin& depositPlugin(const SigningSelection& selection)
{
    return const_cast<LibreSCRS::Plugin::CardPlugin&>(*selection.plugin);
}

} // namespace

void eraseDepositedPin(const CandidateList& candidates, LibreSCRS::SmartCard::CardSession& session) noexcept
{
    for (const auto& candidate : candidates) {
        if (candidate) {
            // const_cast: see depositPlugin.
            erasePinFrom(const_cast<LibreSCRS::Plugin::CardPlugin&>(*candidate), session);
        }
    }
}

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

bool certPublicKeyIsEcdsa(std::span<const std::uint8_t> der)
{
    auto parsed = LibreSCRS::Certificate::ParsedCertificate::fromDer(der);
    if (!parsed) {
        return false; // unparseable -> the RSA flow stays the default
    }
    return parsed->publicKey().algorithm == LibreSCRS::Certificate::PublicKeyAlgorithm::ECDSA;
}

LibreSCRS::Plugin::SignMechanism ecdsaMechanismForDigestLength(std::size_t digestLength) noexcept
{
    using M = LibreSCRS::Plugin::SignMechanism;
    if (digestLength <= 32) {
        return M::ECDSA_SHA256;
    }
    if (digestLength <= 48) {
        return M::ECDSA_SHA384;
    }
    return M::ECDSA_SHA512;
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
    // Consent per operation is the card's rule, read from the card in the
    // reader now -- never from the request or from a cached read. Without a
    // PIN for THIS operation such a key is not touched.
    const bool perOperation = selection->cert.alwaysAuthenticate;
    if (perOperation && pin == nullptr) {
        return RawCryptoResult{.status = RawCryptoStatus::ConsentRequired, .bytes = {}, .alwaysAuthenticate = true};
    }
    // A PIN goes to the plugin, which verifies it and uses the key in one card
    // transaction; a separate VERIFY first would let the card forget it in
    // between (PIV 9C). For a key the card marks it is erased again on every
    // way out (only the PIN; the CAN stays). For an ordinary key it stays for
    // the lease once the operation succeeded -- a hash-on-card card signs only
    // with a deposited PIN -- and is erased on any failure, also when the PIN
    // was kept from an earlier operation. The eraser is armed before the
    // deposit, so a deposit that throws half-way is erased as well.
    auto& plugin = depositPlugin(*selection);
    PinDepositEraser eraser{plugin, session};
    if (pin != nullptr && pin->empty()) {
        // An empty value would erase the deposit, and the card would run the
        // operation on whatever the held session is already verified for.
        return err(RawCryptoStatus::AuthFailed);
    }
    if (pin != nullptr) {
        plugin.setCredentials(session, "pin", *pin);
    }
    // Mechanism family by the RESOLVED KEY'S ALGORITHM (the certificate is
    // the authority): an EC key takes the pre-hashed ECDSA path — both the
    // hash-on-card probe and the DigestInfo fallback below are RSA-shaped.
    // The PKCS#11 module hands the pre-computed digest for CKM_ECDSA, so
    // @p input IS the hash.
    if (certPublicKeyIsEcdsa(selection->cert.derBytes)) {
        auto sr = selection->plugin->sign(session, *selection->cert.keyFID, input,
                                          ecdsaMechanismForDigestLength(input.size()), token);
        RawCryptoResult out;
        out.status = mapSignOutcome(sr.outcome);
        out.alwaysAuthenticate = perOperation;
        eraser.keepForTheLease(!perOperation && out.status == RawCryptoStatus::Ok);
        if (out.status == RawCryptoStatus::Ok) {
            out.bytes = sr.signature;
        } else if (out.status == RawCryptoStatus::NotSupported) {
            log::warn("rawcrypto: signRaw resolved an EC key but the plugin has no ECDSA primitive");
        }
        return out;
    }
    // Two RSA card families, one consent model (the PIN deposited above, if
    // any, is presented by the plugin inside whichever sign runs):
    //   * Hash-on-card SSCDs (NAM / IAS-ECC pkcs15) expose doSign(RSA_SHA256)
    //     over the RAW message and own the atomic verify + MSE(0x28) + PSO
    //     inside PKCS15Card::sign.
    //   * DigestInfo cards (PKS / opensc) sign with raw RSA_PKCS over a
    //     caller-supplied DigestInfo.
    // Self-dispatch: try the hash-on-card mechanism first; a plugin without it
    // returns NotImplemented (no card I/O, no PIN use) and we fall through to
    // RSA_PKCS. The module advertises exactly one mechanism per card, so
    // `input` already carries the right form (raw message for NAM, DigestInfo
    // for PKS).
    auto sr = selection->plugin->sign(session, *selection->cert.keyFID, input,
                                      LibreSCRS::Plugin::SignMechanism::RSA_SHA256, token);
    if (sr.outcome == LibreSCRS::Plugin::SignResultOutcome::NotImplemented) {
        sr = selection->plugin->sign(session, *selection->cert.keyFID, input,
                                     LibreSCRS::Plugin::SignMechanism::RSA_PKCS, token);
    }
    RawCryptoResult out;
    out.status = mapSignOutcome(sr.outcome);
    out.alwaysAuthenticate = perOperation;
    eraser.keepForTheLease(!perOperation && out.status == RawCryptoStatus::Ok);
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
    // Checked before consent: a refused decryption must not cost a PIN prompt.
    if (!certKeyUsagePermitsDecrypt(selection->cert.derBytes)) {
        log::warn("rawcrypto: decryptRaw resolved to a key whose certificate keyUsage forbids decryption");
        return err(RawCryptoStatus::NotSupported);
    }
    // The card's per-operation consent rule, as in signRaw.
    const bool perOperation = selection->cert.alwaysAuthenticate;
    if (perOperation && pin == nullptr) {
        return RawCryptoResult{.status = RawCryptoStatus::ConsentRequired, .bytes = {}, .alwaysAuthenticate = true};
    }
    // The PIN for this operation goes to the plugin and lives as in signRaw:
    // VERIFY and the decipher in one card transaction, erased on every way out
    // for a marked key, kept for the lease only after an ordinary key's success.
    auto& plugin = depositPlugin(*selection);
    PinDepositEraser eraser{plugin, session};
    if (pin != nullptr && pin->empty()) {
        return err(RawCryptoStatus::AuthFailed); // as in signRaw
    }
    if (pin != nullptr) {
        plugin.setCredentials(session, "pin", *pin);
    }
    auto dr = selection->plugin->decipher(session, *selection->cert.keyFID, ciphertext,
                                          LibreSCRS::Plugin::DecipherMechanism::RSA_PKCS1_V15, token);
    RawCryptoResult out;
    out.status = mapDecipherOutcome(dr.outcome);
    out.alwaysAuthenticate = perOperation;
    eraser.keepForTheLease(!perOperation && out.status == RawCryptoStatus::Ok);
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
