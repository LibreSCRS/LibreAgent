// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <memory>

namespace LibreSCRS::Agent::Operations {

namespace {

// Big-endian, unpadded (no leading zero byte) — the PKCS#11 CKA_* convention.
std::vector<std::uint8_t> bnToBytes(const BIGNUM* bn)
{
    if (bn == nullptr) {
        return {};
    }
    const int n = BN_num_bytes(bn);
    if (n <= 0) {
        return {};
    }
    std::vector<std::uint8_t> out(static_cast<std::size_t>(n));
    // BN_bn2bin writes big-endian with no leading zeros — exactly CKA_* form.
    BN_bn2bin(bn, out.data());
    return out;
}

} // namespace

std::optional<RsaPublicKey> rsaPublicKeyFromCertDer(std::span<const std::uint8_t> der)
{
    if (der.empty()) {
        return std::nullopt;
    }
    const unsigned char* p = der.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert{d2i_X509(nullptr, &p, static_cast<long>(der.size())), &X509_free};
    if (!cert) {
        return std::nullopt;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey{X509_get_pubkey(cert.get()), &EVP_PKEY_free};
    if (!pkey || EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
        return std::nullopt; // not RSA -> host maps to NotSupported
    }
    // OpenSSL 3 param API: fetch n + e without touching the deprecated RSA struct.
    BIGNUM* nBn = nullptr;
    BIGNUM* eBn = nullptr;
    const bool gotN = EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_N, &nBn) == 1;
    const bool gotE = EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, &eBn) == 1;
    std::unique_ptr<BIGNUM, decltype(&BN_free)> nGuard{nBn, &BN_free};
    std::unique_ptr<BIGNUM, decltype(&BN_free)> eGuard{eBn, &BN_free};
    if (!gotN || !gotE) {
        return std::nullopt;
    }
    RsaPublicKey out;
    out.modulus = bnToBytes(nBn);
    out.exponent = bnToBytes(eBn);
    if (out.modulus.empty() || out.exponent.empty()) {
        return std::nullopt;
    }
    return out;
}

} // namespace LibreSCRS::Agent::Operations
