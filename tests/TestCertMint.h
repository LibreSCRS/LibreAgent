// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// Mint keys and self-signed certificates at test time, for the suites that
// need a real certificate of a given key family. One helper rather than a copy
// per suite: the key families under test (RSA, RSASSA-PSS, NIST EC, brainpool,
// Ed25519) are the same everywhere.

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace LibreSCRS::Agent::Test {

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

/// An EC key on @p group ("P-256", "P-384", "P-521", "brainpoolP256r1").
inline PkeyPtr ecKey(const char* group)
{
    return PkeyPtr{EVP_EC_gen(group), &EVP_PKEY_free};
}

inline PkeyPtr rsaKey(unsigned bits = 2048)
{
    return PkeyPtr{EVP_RSA_gen(bits), &EVP_PKEY_free};
}

/// A key of an algorithm with no parameters ("ED25519") or of RSASSA-PSS
/// ("RSA-PSS", 2048 bits).
inline PkeyPtr namedKey(const char* algorithm)
{
    const std::string_view name{algorithm};
    if (name == "RSA-PSS") {
        return PkeyPtr{EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA-PSS", static_cast<std::size_t>(2048)), &EVP_PKEY_free};
    }
    return PkeyPtr{EVP_PKEY_Q_keygen(nullptr, nullptr, algorithm), &EVP_PKEY_free};
}

/// A self-signed v3 certificate over @p key; @p keyUsage is an OpenSSL
/// keyUsage value ("critical,digitalSignature") or nullptr for none.
inline std::vector<std::uint8_t> selfSignedCert(EVP_PKEY* key, const char* commonName, const char* keyUsage = nullptr)
{
    std::vector<std::uint8_t> out;
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x2026);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (keyUsage != nullptr) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
        if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, keyUsage)) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    const int base = EVP_PKEY_get_base_id(key);
    const EVP_MD* md = (base == EVP_PKEY_ED25519 || base == EVP_PKEY_ED448) ? nullptr : EVP_sha256();
    if (X509_sign(x, key, md) > 0) {
        unsigned char* der = nullptr;
        const int len = i2d_X509(x, &der);
        if (len > 0) {
            out.assign(der, der + len);
        }
        OPENSSL_free(der);
    }
    X509_free(x);
    return out;
}

/// The key's public point as OpenSSL encodes it (uncompressed: 04||X||Y).
inline std::vector<std::uint8_t> encodedPublicPoint(EVP_PKEY* key)
{
    std::size_t len = 0;
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0, &len);
    std::vector<std::uint8_t> out(len);
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out.data(), out.size(), &len);
    out.resize(len);
    return out;
}

} // namespace LibreSCRS::Agent::Test
