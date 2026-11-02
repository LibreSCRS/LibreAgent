// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/LmRawCrypto.h>

#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Logging.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>       // selectSigningCandidate, SigningSelection
#include <LibreSCRS/Agent/operations/RawCryptoFlow.h> // RawCryptoFlowDeps
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>  // ecPeerPointOnCertCurve

#include <LibreSCRS/Auth/AuthRequirement.h> // PreReadAuthMethod
#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PinDeposit.h> // ScopedPinDeposit
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>

#include <cstdint>
#include <optional>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

RawCryptoResult err(RawCryptoStatus s)
{
    return RawCryptoResult{.status = s, .bytes = {}};
}

// LM raw-sign outcome -> hermetic status. PinIncorrect / PinBlocked come from
// the plugin presenting the PIN handed over for this operation (VERIFY and the
// key operation in one card transaction): AuthFailed, on which the host revokes the lease and the next operation
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

// One raw operation under the PIN rule of a raw operation. A @p pin given for
// it is deposited for the operation's one card transaction (ScopedPinDeposit,
// erased unless kept for the lease); without one, the plugin presents the PIN
// an earlier operation left for the lease. Either way that PIN stays only after
// an ordinary key's success: any other outcome erases it, so a card that
// refused it never sees it again. A plugin's own throw already arrives as a
// failed outcome (CardPlugin contains it); what can still throw out of
// @p operation is this side's work around the call -- the result copy, a log
// line -- and that erases the PIN too before it propagates. An empty @p pin
// would itself erase the deposit and let the card run the operation on
// whatever the held session is already verified for: refused as a failed PIN,
// before the key is used.
template <typename Operation>
RawCryptoResult underTheOperationsPin(LibreSCRS::Plugin::CardPlugin& plugin, LibreSCRS::SmartCard::CardSession& session,
                                      const LibreSCRS::Secure::String* pin, bool perOperation, Operation&& operation)
{
    if (pin != nullptr && pin->empty()) {
        erasePinFrom(plugin, session);
        return err(RawCryptoStatus::AuthFailed);
    }
    std::optional<LibreSCRS::Plugin::ScopedPinDeposit> deposit;
    if (pin != nullptr) {
        deposit.emplace(plugin, session, *pin); // erases itself if the deposit throws half-way
    }
    try {
        RawCryptoResult out = std::forward<Operation>(operation)();
        if (!perOperation && out.status == RawCryptoStatus::Ok) {
            if (deposit) {
                deposit->keepForLease();
            }
        } else if (!deposit) {
            erasePinFrom(plugin, session);
        }
        return out;
    } catch (...) {
        if (!deposit) {
            erasePinFrom(plugin, session);
        }
        throw;
    }
}

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

void bindLmRawCrypto(RawCryptoFlowDeps& deps)
{
    deps.preflight = preflight;
    deps.signOp = signRaw;
    deps.decryptOp = decryptRaw;
    deps.deriveOp = deriveRaw;
}

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

std::optional<LibreSCRS::Plugin::SignMechanism> ecdsaMechanismForDigest(std::size_t digestLength) noexcept
{
    using M = LibreSCRS::Plugin::SignMechanism;
    switch (digestLength) {
    case 32:
        return M::ECDSA_SHA256;
    case 48:
        return M::ECDSA_SHA384;
    case 64:
        return M::ECDSA_SHA512;
    default:
        return std::nullopt;
    }
}

RawCryptoPreflight preflight(const CandidateList& candidates, const std::string& certId, Mechanism mechanism,
                             std::span<const std::uint8_t> input, LibreSCRS::SmartCard::CardSession& session)
{
    const auto refuse = [](RawCryptoStatus s) { return RawCryptoPreflight{.status = s, .key = std::nullopt}; };
    // Anti-TOCTOU routing reused from the AdES path: resolve certId against the
    // card present NOW, returning the owning plugin + the exact CertificateData.
    // Every refusal, KeyAmbiguous included, is KeyNotFound here.
    auto selection = selectSigningCandidate(candidates, certId, session);
    if (!selection || !selection->cert.keyFID.has_value()) {
        return refuse(RawCryptoStatus::KeyNotFound);
    }
    auto parsed = LibreSCRS::Certificate::ParsedCertificate::fromDer(selection->cert.derBytes);
    const CertKeyClass key = parsed ? classifyCertKey(*parsed) : CertKeyClass{};
    const std::size_t k = (key.bits + 7) / 8; // RSA modulus bytes; EC field bytes
    switch (mechanism) {
    case Mechanism::RsaPkcs1Sign:
        // PKCS#1 v1.5 type 01 padding needs at least 11 bytes of the modulus.
        if (key.type != KeyType::Rsa || input.empty() || input.size() + 11 > k) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        // A PACE card's RSA key hashes the message on the card and takes no
        // caller-built block; the PKCS#11 module offers it the hash-on-card
        // mechanism only. Refused here, before the PIN, for every client.
        if (selection->plugin->preReadAuth(session) == LibreSCRS::Auth::PreReadAuthMethod::Can) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        break;
    case Mechanism::Sha256RsaPkcs1Sign:
        // The raw message; the frame bound caps it from above. Only a PACE
        // card's RSA key hashes it on the card; any other takes a caller-built
        // block and is never handed a message to hash.
        if (key.type != KeyType::Rsa || input.empty() ||
            selection->plugin->preReadAuth(session) != LibreSCRS::Auth::PreReadAuthMethod::Can) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        break;
    case Mechanism::EcdsaSign:
        if (key.type != KeyType::Ec || !ecdsaMechanismForDigest(input.size())) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        break;
    case Mechanism::RsaPkcs1Decrypt:
        if (key.type != KeyType::Rsa) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        // For PKS the signature key (no keyEncipherment) is decrypt-incapable and
        // the card hard-fails NOT_ALLOWED; refused before consent, so a refused
        // decryption never asks for a PIN.
        if (!certKeyUsagePermitsDecrypt(selection->cert.derBytes)) {
            log::warn("rawcrypto: a decryption with a key whose certificate keyUsage forbids it");
            return refuse(RawCryptoStatus::NotSupported);
        }
        if (input.size() != k) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        break;
    case Mechanism::EcdhDerive:
        // A key agreement needs an EC key the plugin will derive with, and the
        // peer's uncompressed point on that key's curve. Checked here because
        // the plugin cannot name the curve (its field length does not), and a
        // malformed point under PACE secure messaging ends the session.
        if (key.type != KeyType::Ec || !selection->cert.canDerive) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        if (input.size() != 1 + 2 * k || input.front() != 0x04 ||
            !ecPeerPointOnCertCurve(selection->cert.derBytes, input)) {
            return refuse(RawCryptoStatus::InvalidInput);
        }
        break;
    default:
        return refuse(RawCryptoStatus::NotSupported);
    }
    return RawCryptoPreflight{.status = RawCryptoStatus::Ok, .key = std::move(*selection)};
}

RawCryptoResult signRaw(const SigningSelection& key, Mechanism mechanism, std::span<const std::uint8_t> input,
                        const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession& session,
                        LibreSCRS::CancelToken token)
{
    if (!key.plugin || !key.cert.keyFID.has_value()) {
        return err(RawCryptoStatus::KeyNotFound);
    }
    using SM = LibreSCRS::Plugin::SignMechanism;
    std::optional<SM> pluginMechanism;
    switch (mechanism) {
    case Mechanism::RsaPkcs1Sign:
        pluginMechanism = SM::RSA_PKCS;
        break;
    case Mechanism::Sha256RsaPkcs1Sign:
        pluginMechanism = SM::RSA_SHA256;
        break;
    case Mechanism::EcdsaSign:
        pluginMechanism = ecdsaMechanismForDigest(input.size());
        break;
    default:
        break;
    }
    if (!pluginMechanism) {
        return err(RawCryptoStatus::InvalidInput); // the preflight refuses these first
    }
    // Consent per operation is the card's rule, read from the card in the
    // reader now. Without a PIN for THIS operation such a key is not touched.
    const bool perOperation = key.cert.alwaysAuthenticate;
    if (perOperation && pin == nullptr) {
        return RawCryptoResult{.status = RawCryptoStatus::ConsentRequired, .bytes = {}, .alwaysAuthenticate = true};
    }
    // A PIN goes to the plugin, which verifies it and uses the key in one card
    // transaction; how long it stays there is underTheOperationsPin's rule.
    return underTheOperationsPin(depositPlugin(key), session, pin, perOperation, [&] {
        auto sr = key.plugin->sign(session, *key.cert.keyFID, input, *pluginMechanism, token);
        RawCryptoResult out;
        out.status = mapSignOutcome(sr.outcome);
        out.alwaysAuthenticate = perOperation;
        if (out.status == RawCryptoStatus::Ok) {
            out.bytes = sr.signature;
        } else if (out.status == RawCryptoStatus::NotSupported) {
            log::warn("rawcrypto: the resolving plugin does not implement the requested sign mechanism");
        }
        return out;
    });
}

namespace {

// The body decryptRaw and deriveRaw share: one CardPlugin::decipher with
// @p pluginMechanism under the consent rule and PIN lifetime of signRaw, the
// result copied out through a cleansing buffer and the plugin's copy wiped on
// every outcome (a plaintext and a derived secret alike). The caller has
// checked that the request's mechanism is the one @p pluginMechanism runs.
RawCryptoResult decipherWithKey(const SigningSelection& key, LibreSCRS::Plugin::DecipherMechanism pluginMechanism,
                                std::span<const std::uint8_t> input, const LibreSCRS::Secure::String* pin,
                                LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token,
                                const char* notSupportedWarning)
{
    // The card's per-operation consent rule, as in signRaw.
    const bool perOperation = key.cert.alwaysAuthenticate;
    if (perOperation && pin == nullptr) {
        return RawCryptoResult{.status = RawCryptoStatus::ConsentRequired, .bytes = {}, .alwaysAuthenticate = true};
    }
    // The PIN for this operation goes to the plugin and lives as in signRaw:
    // VERIFY and the decipher in one card transaction.
    return underTheOperationsPin(depositPlugin(key), session, pin, perOperation, [&] {
        auto dr = key.plugin->decipher(session, *key.cert.keyFID, input, pluginMechanism, token);
        RawCryptoResult out;
        out.status = mapDecipherOutcome(dr.outcome);
        out.alwaysAuthenticate = perOperation;
        if (out.status == RawCryptoStatus::Ok) {
            // SENSITIVE: copied out through a cleansing Secure::Buffer, so no
            // intermediate copy lingers; the returned vector is the host's to
            // wipe once it has handed the bytes on (Pkcs11Broker does).
            const LibreSCRS::Secure::Buffer recovered{std::span<const std::uint8_t>{dr.plaintext}};
            out.bytes.assign(recovered.data(), recovered.data() + recovered.size());
        } else if (out.status == RawCryptoStatus::NotSupported) {
            log::warn(notSupportedWarning);
        }
        LibreSCRS::Agent::secureZero(dr.plaintext);
        return out;
    });
}

} // namespace

RawCryptoResult decryptRaw(const SigningSelection& key, Mechanism mechanism, std::span<const std::uint8_t> ciphertext,
                           const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession& session,
                           LibreSCRS::CancelToken token)
{
    if (!key.plugin || !key.cert.keyFID.has_value()) {
        return err(RawCryptoStatus::KeyNotFound);
    }
    if (mechanism != Mechanism::RsaPkcs1Decrypt) {
        return err(RawCryptoStatus::InvalidInput);
    }
    // NotSupported is the pkcs15/NAM family (no doDecipher override), surfaced
    // so the host returns CKR_FUNCTION_NOT_SUPPORTED rather than a silent
    // failure. See the header's PER-FAMILY ROUTING note.
    return decipherWithKey(key, LibreSCRS::Plugin::DecipherMechanism::RSA_PKCS1_V15, ciphertext, pin, session, token,
                           "rawcrypto: decryptRaw resolved to a plugin without a raw-decipher primitive "
                           "(pkcs15/NAM family)");
}

RawCryptoResult deriveRaw(const SigningSelection& key, Mechanism mechanism, std::span<const std::uint8_t> peerPoint,
                          const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession& session,
                          LibreSCRS::CancelToken token)
{
    if (!key.plugin || !key.cert.keyFID.has_value()) {
        return err(RawCryptoStatus::KeyNotFound);
    }
    if (mechanism != Mechanism::EcdhDerive) {
        return err(RawCryptoStatus::InvalidInput); // the preflight refuses these first
    }
    auto out = decipherWithKey(key, LibreSCRS::Plugin::DecipherMechanism::ECDH_RAW, peerPoint, pin, session, token,
                               "rawcrypto: deriveRaw resolved to a plugin without ECDH for this key");
    // The secret is ceil(bits/8) bytes of the key's curve -- what the wire
    // promises every client. A plugin answer of another length is not passed on.
    if (out.status == RawCryptoStatus::Ok) {
        const auto parsed = LibreSCRS::Certificate::ParsedCertificate::fromDer(key.cert.derBytes);
        const CertKeyClass curve = parsed ? classifyCertKey(*parsed) : CertKeyClass{};
        if (curve.type != KeyType::Ec || out.bytes.size() != (curve.bits + 7) / 8) {
            LibreSCRS::Agent::secureZero(out.bytes);
            out.bytes.clear();
            out.status = RawCryptoStatus::CardError;
            log::warn("rawcrypto: the plugin answered a key agreement with a secret of the wrong length");
        }
    }
    return out;
}

} // namespace LibreSCRS::Agent::Operations
