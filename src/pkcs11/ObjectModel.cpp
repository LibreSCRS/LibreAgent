// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>

namespace LibreSCRS::Pkcs11Agent {

ObjectModel ObjectModel::build(const AgentSnapshot& snapshot)
{
    ObjectModel model;
    model.slots.reserve(snapshot.readers.size());

    for (const auto& reader : snapshot.readers) {
        Slot slot;
        slot.readerPath = reader.readerPath;
        slot.readerName = reader.readerName;
        slot.tokenPresent = reader.hasCard;
        slot.protectedAuthPath = true; // the agent prompter is the protected auth path
        slot.tokenLabel = reader.tokenLabel;
        slot.tokenSerial = reader.tokenSerial;

        if (!reader.hasCard) {
            model.slots.push_back(std::move(slot));
            continue;
        }

        bool anyRsaSign = false;
        bool anyRsaDecrypt = false;
        bool anyRsaHashOnCard = false;
        bool anyEcSign = false;

        for (const auto& cert : reader.certs) {
            using LibreSCRS::Agent::KeyType;
            // Only RSA and EC keys the agent can sign with surface as objects;
            // an Other key has no attributes this module could serve.
            const bool isRsa = cert.keyType == KeyType::Rsa;
            const bool isEc = cert.keyType == KeyType::Ec;
            if (!(isRsa || isEc) || !cert.signingCapable)
                continue;

            // CKO_CERTIFICATE — public DER, fetched lazily by the module.
            Object certObj;
            certObj.cls = CKO_CERTIFICATE;
            certObj.ckaId = cert.ckaId;
            certObj.label = cert.label;
            certObj.certId = cert.certId;
            slot.objects.push_back(std::move(certObj));

            // CKO_PUBLIC_KEY — sharing the cert's CKA_ID.
            Object pubObj;
            pubObj.cls = CKO_PUBLIC_KEY;
            pubObj.ckaId = cert.ckaId;
            pubObj.label = cert.label;
            pubObj.certId = cert.certId;
            pubObj.keyType = cert.keyType;
            pubObj.keyBits = cert.keyBits;
            slot.objects.push_back(std::move(pubObj));

            // CKO_PRIVATE_KEY — non-extractable; capabilities gated by the agent.
            Object privObj;
            privObj.cls = CKO_PRIVATE_KEY;
            privObj.ckaId = cert.ckaId;
            privObj.label = cert.label;
            privObj.certId = cert.certId;
            privObj.keyType = cert.keyType;
            privObj.keyBits = cert.keyBits;
            privObj.sign = cert.canSign;
            privObj.decrypt = isRsa && cert.canDecrypt; // decryption is RSA's alone
            privObj.alwaysAuthenticate = cert.alwaysAuthenticate;
            slot.objects.push_back(std::move(privObj));

            if (isRsa) {
                anyRsaSign = anyRsaSign || cert.canSign;
                anyRsaDecrypt = anyRsaDecrypt || cert.canDecrypt;
                anyRsaHashOnCard = anyRsaHashOnCard || (cert.canSign && cert.signsHashOnCard);
            } else {
                anyEcSign = anyEcSign || cert.canSign;
            }
        }

        // Mechanism table is capability-advertised per card family. For RSA
        // keys: at most one RSA mechanism per slot, never both, chosen by where
        // the SHA-256 digest is computed. A token whose keys are all
        // capability-gated (no canSign, no canDecrypt) advertises NOTHING.
        // The module is libcrypto-free in BOTH cases: it never hashes — it
        // forwards the caller's bytes verbatim and the CARD or the CALLER owns
        // the digest.
        //
        //  * DigestInfo family (opensc/PKS, PreReadAuthMethod "None"): advertise
        //    CKM_RSA_PKCS. The caller supplies the complete, ready-to-pad block
        //    (a full DigestInfo for sign, or the ciphertext for decrypt) and the
        //    agent runs the raw private-key op on-card. The combined
        //    CKM_SHAxxx_RSA_PKCS mechanisms are NOT advertised here — the module
        //    cannot build the DigestInfo, so honouring them would sign a
        //    never-hashed message. NSS/Firefox, the openssl engine and the LM
        //    AdES path all drive CKM_RSA_PKCS with a pre-built DigestInfo.
        //  * Hash-on-card family (pkcs15/NAM IAS-ECC SSCD, PreReadAuthMethod
        //    "Can"): advertise CKM_SHA256_RSA_PKCS, sign-only. The card
        //    REJECTS a caller-supplied DigestInfo and instead hashes the RAW
        //    message itself, so the caller supplies the message bytes and the
        //    module relays them verbatim (still no host-side hashing). Decrypt is
        //    not advertised (the pkcs15 plugin has no decipher primitive).
        if (anyRsaHashOnCard) {
            slot.mechanisms.push_back(CKM_SHA256_RSA_PKCS);
        } else if (anyRsaSign || anyRsaDecrypt) {
            // CKM_RSA_PKCS covers raw RSA PKCS#1 v1.5 sign AND/OR decrypt; the
            // per-key CKA_SIGN / CKA_DECRYPT flags decide which the caller may use.
            slot.mechanisms.push_back(CKM_RSA_PKCS);
        }
        // An EC key signs the caller's digest (CKM_ECDSA); the card never hashes for it.
        if (anyEcSign) {
            slot.mechanisms.push_back(CKM_ECDSA);
        }

        model.slots.push_back(std::move(slot));
    }

    return model;
}

} // namespace LibreSCRS::Pkcs11Agent
