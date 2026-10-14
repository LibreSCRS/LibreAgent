// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/RsaPublicKey.h>

#include <LibreSCRS/Agent/KeyType.h> // the NIST curve table

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

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

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

X509Ptr parseCert(std::span<const std::uint8_t> der)
{
    if (der.empty()) {
        return X509Ptr{nullptr, &X509_free};
    }
    const unsigned char* p = der.data();
    return X509Ptr{d2i_X509(nullptr, &p, static_cast<long>(der.size())), &X509_free};
}

// The NIST curve of an EC key, from the agent's one curve table.
const NistCurve* nistCurveOf(EVP_PKEY* pkey)
{
    char group[80] = {};
    std::size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &len) != 1) {
        return nullptr;
    }
    return nistCurveByGroup(std::string_view{group, len});
}

std::vector<std::uint8_t> sha1(std::span<const std::uint8_t> in)
{
    std::vector<std::uint8_t> out(SHA_DIGEST_LENGTH);
    unsigned int n = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &n, EVP_sha1(), nullptr) != 1) {
        return {};
    }
    out.resize(n);
    return out;
}

// The key's X and Y at fixed width. The encoded point is the source; a
// certificate that carries a compressed point is read through the coordinate
// parameters, padded to the field width rather than shortened.
bool fixedWidthCoordinates(EVP_PKEY* pkey, std::size_t width, std::vector<std::uint8_t>& x,
                           std::vector<std::uint8_t>& y)
{
    std::size_t len = 0;
    std::vector<std::uint8_t> point(1 + 2 * width);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, point.data(), point.size(), &len) ==
            1 &&
        len == point.size() && point[0] == 0x04) {
        x.assign(point.begin() + 1, point.begin() + 1 + static_cast<std::ptrdiff_t>(width));
        y.assign(point.begin() + 1 + static_cast<std::ptrdiff_t>(width), point.end());
        return true;
    }
    BIGNUM* xBn = nullptr;
    BIGNUM* yBn = nullptr;
    const bool gotX = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &xBn) == 1;
    const bool gotY = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &yBn) == 1;
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> xGuard{xBn, &BN_clear_free};
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> yGuard{yBn, &BN_clear_free};
    if (!gotX || !gotY) {
        return false;
    }
    x.assign(width, 0);
    y.assign(width, 0);
    return BN_bn2binpad(xBn, x.data(), static_cast<int>(width)) == static_cast<int>(width) &&
           BN_bn2binpad(yBn, y.data(), static_cast<int>(width)) == static_cast<int>(width);
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
    // BN_clear_free, not BN_free: one policy for BIGNUM release in this tree,
    // so no call site has to be right about which values are secret. These two
    // are public (an RSA modulus and its exponent); the cost is a memset of a
    // few hundred bytes against a free that costs an order of magnitude more.
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> nGuard{nBn, &BN_clear_free};
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> eGuard{eBn, &BN_clear_free};
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

std::optional<EcPublicKey> ecPublicKeyFromCertDer(std::span<const std::uint8_t> der)
{
    const auto cert = parseCert(der);
    if (!cert) {
        return std::nullopt;
    }
    PkeyPtr pkey{X509_get_pubkey(cert.get()), &EVP_PKEY_free};
    if (!pkey || EVP_PKEY_get_base_id(pkey.get()) != EVP_PKEY_EC) {
        return std::nullopt;
    }
    const NistCurve* curve = nistCurveOf(pkey.get());
    if (curve == nullptr) {
        return std::nullopt; // brainpool and every other curve: not served
    }
    EcPublicKey out;
    out.crv = std::string{curve->crv};
    if (!fixedWidthCoordinates(pkey.get(), curve->fieldBytes, out.x, out.y)) {
        return std::nullopt;
    }
    return out;
}

std::optional<CertPublicKey> publicKeyFromCertDer(std::span<const std::uint8_t> der)
{
    if (auto rsa = rsaPublicKeyFromCertDer(der)) {
        return CertPublicKey{std::move(*rsa)};
    }
    if (auto ec = ecPublicKeyFromCertDer(der)) {
        return CertPublicKey{std::move(*ec)};
    }
    return std::nullopt;
}

namespace {

// The key ID as OpenSC computes it; empty only when this OpenSSL refuses SHA-1.
std::vector<std::uint8_t> sha1KeyIdOf(std::span<const std::uint8_t> der)
{
    const auto cert = parseCert(der);
    if (!cert) {
        return sha1(der); // unreadable: the certificate's own digest
    }
    PkeyPtr pkey{X509_get_pubkey(cert.get()), &EVP_PKEY_free};
    if (pkey && EVP_PKEY_get_base_id(pkey.get()) == EVP_PKEY_RSA) {
        if (const auto rsa = rsaPublicKeyFromCertDer(der)) {
            return sha1(rsa->modulus); // unpadded, as PKCS#15 and OpenSC hash it
        }
    }
    if (const auto ec = ecPublicKeyFromCertDer(der)) {
        return sha1(ec->x);
    }
    const ASN1_BIT_STRING* bits = X509_get0_pubkey_bitstr(cert.get());
    if (bits != nullptr && bits->length > 0) {
        return sha1(std::span<const std::uint8_t>{bits->data, static_cast<std::size_t>(bits->length)});
    }
    return sha1(der);
}

} // namespace

std::vector<std::uint8_t> fallbackKeyIdFromCertDer(std::span<const std::uint8_t> der)
{
    auto id = sha1KeyIdOf(der);
    if (!id.empty()) {
        return id;
    }
    // An OpenSSL that refuses SHA-1: the certificate's SHA-256 instead -- the
    // bytes of its certId, which the agent computes for every certificate and
    // without which it reports none.
    std::vector<std::uint8_t> digest(32);
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, der.data(), der.size(), digest.data(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    return digest;
}

bool ecPeerPointOnCertCurve(std::span<const std::uint8_t> der, std::span<const std::uint8_t> point)
{
    const auto cert = parseCert(der);
    if (!cert) {
        return false;
    }
    PkeyPtr pkey{X509_get_pubkey(cert.get()), &EVP_PKEY_free};
    if (!pkey || EVP_PKEY_get_base_id(pkey.get()) != EVP_PKEY_EC) {
        return false;
    }
    const NistCurve* curve = nistCurveOf(pkey.get());
    if (curve == nullptr || point.size() != 1 + 2 * curve->fieldBytes || point.front() != 0x04) {
        return false;
    }
    PkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free};
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) {
        return false;
    }
    std::string group{curve->group};
    std::vector<std::uint8_t> pub(point.begin(), point.end());
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group.data(), 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size()),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* peer = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &peer, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        return false; // OpenSSL refuses a point that is not on the curve
    }
    PkeyPtr peerGuard{peer, &EVP_PKEY_free};
    PkeyCtxPtr check{EVP_PKEY_CTX_new_from_pkey(nullptr, peer, nullptr), &EVP_PKEY_CTX_free};
    return check && EVP_PKEY_public_check(check.get()) == 1;
}

} // namespace LibreSCRS::Agent::Operations
