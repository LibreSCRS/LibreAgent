// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/util/Sha256Hex.h>
#include <LibreSCRS/Agent/util/HexEncode.h>
#include <openssl/evp.h>
#include <array>
#include <cstddef>
#include <stdexcept>

namespace LibreSCRS::Agent {

namespace {
constexpr std::size_t kSha256Bytes = 32;
} // namespace

std::string sha256Hex(std::span<const std::uint8_t> bytes)
{
    std::array<std::uint8_t, kSha256Bytes> digest{};
    // EVP_Q_digest is the OpenSSL 3.0+ single-call digest API: no manual
    // EVP_MD_CTX_new / DigestInit / DigestUpdate / DigestFinal dance, no
    // ENGINE/property string, and zero-byte input is accepted (returns
    // SHA-256("")). Returns 1 on success, 0 on failure.
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, bytes.data(), bytes.size(), digest.data(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    // certId is lowercase hex, no separator.
    return toHex(digest, /*separator=*/'\0', /*upper=*/false);
}

} // namespace LibreSCRS::Agent
