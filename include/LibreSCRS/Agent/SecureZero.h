// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace LibreSCRS::Agent {

/// @brief Zero @p bytes with writes the optimizer may not drop as dead stores
///        (unlike a plain fill before the memory is freed).
///
/// The one zeroization routine of the agent stack: the wire codec, the PKCS#11
/// facade (which links no crypto library) and both transports use it for
/// secret-bearing buffers -- a decrypted block, a derived secret, a prompter
/// reply. Std-only and inline, so a component that links nothing else can
/// call it.
/// @since 5.0
inline void secureZero(std::span<std::uint8_t> bytes) noexcept
{
    volatile std::uint8_t* p = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        p[i] = 0;
    }
}

/// @brief Wipes a byte buffer with secureZero when the scope ends, on every
///        way out including an exception.
///
/// The one scope form of secureZero: the PKCS#11 facade links no crypto
/// library, so Secure::Buffer is not available there. The buffer is held by
/// reference and wiped as it is at scope end. It must not reallocate while
/// guarded -- a growth or a longer assignment frees the old storage unwiped --
/// but it may be moved from, which leaves nothing behind to wipe.
/// @since 5.0
class SecureZeroOnExit
{
public:
    explicit SecureZeroOnExit(std::vector<std::uint8_t>& bytes) noexcept : m_bytes(bytes) {}
    ~SecureZeroOnExit()
    {
        secureZero(m_bytes);
    }

    SecureZeroOnExit(const SecureZeroOnExit&) = delete;
    SecureZeroOnExit& operator=(const SecureZeroOnExit&) = delete;
    SecureZeroOnExit(SecureZeroOnExit&&) = delete;
    SecureZeroOnExit& operator=(SecureZeroOnExit&&) = delete;

private:
    std::vector<std::uint8_t>& m_bytes;
};

} // namespace LibreSCRS::Agent
