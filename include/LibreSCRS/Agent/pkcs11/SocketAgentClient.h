// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketAgentClient — AgentClient over the framed CBOR wire.
//
// The wire already carries every question this module asks, so what was missing
// was a client that asks them blockingly. This is that client, and it is the
// second implementation of one interface rather than a second module.

#pragma once

#include <LibreSCRS/Agent/pkcs11/AgentClient.h>

#include <cstdint>
#include <memory>
#include <string>

namespace LibreSCRS::Pkcs11Agent {

/// @brief What the agent is given for a human-paced call, in seconds.
///        A PIN prompt plus the on-card operation behind it.
inline constexpr int kInteractiveTimeoutSecs = 600;
/// @brief What it is given for public data nobody has to be asked about.
inline constexpr int kPublicDataTimeoutSecs = 60;

/// @brief The two deadlines a socket call can be given.
///
/// They are two and not one because a PIN prompt is paced by a person and a
/// public-data read is not. A single budget is wrong whichever value it takes:
/// short enough to notice a stalled read is shorter than a human, and long
/// enough for a human leaves a dead agent hanging the loader.
///
/// At namespace scope rather than nested, because a nested type's default
/// member initialisers are not usable in the enclosing class's own member
/// declarations -- the class is still incomplete there.
struct SocketTimeouts
{
    int publicDataSecs = kPublicDataTimeoutSecs;
    int interactiveSecs = kInteractiveTimeoutSecs;
};

/// @brief Blocking, single-threaded AgentClient over the framed CBOR wire.
///
/// Deliberately has NO reader thread and NO event subscription: presence is
/// re-read with GetState on every snapshot(), which the loader only asks for
/// when it enumerates slots. That keeps the client fully blocking, the way the
/// Swift client this mirrors is, and removes a thread from a library a browser
/// dlopens.
class SocketAgentClient final : public AgentClient
{
public:
    /// @param socketPath absolute path, ALWAYS supplied by the host's factory.
    ///        There is deliberately no default and no environment lookup in
    ///        this library: the one platform-specific fact (where the agent's
    ///        container really is) is resolved by the host that already knows
    ///        it, and a default here would be a second, wrong answer on exactly
    ///        that platform.
    explicit SocketAgentClient(std::string socketPath, SocketTimeouts timeouts = {});
    ~SocketAgentClient() override;

    [[nodiscard]] bool connected() const noexcept override;
    [[nodiscard]] AgentSnapshot snapshot() override;
    [[nodiscard]] BytesResult certDer(const std::string& reader, const std::string& certId) override;
    [[nodiscard]] PublicKeyResult publicKey(const std::string& reader, const std::string& certId) override;
    [[nodiscard]] LoginResult login(const std::string& reader) override;
    Status logout(const std::string& reader) override;
    [[nodiscard]] BytesResult signRaw(const std::string& reader, const std::string& certId,
                                      std::span<const std::uint8_t> input) override;
    [[nodiscard]] BytesResult decrypt(const std::string& reader, const std::string& certId,
                                      std::span<const std::uint8_t> ciphertext) override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace LibreSCRS::Pkcs11Agent
