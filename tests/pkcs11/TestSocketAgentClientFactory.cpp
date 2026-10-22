// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// This tree's answer to AgentClientFactory.h, for the module the suites here
// dlopen.
//
// It is deliberately NOT part of any exported component. A definition shipped
// inside an archive would either collide with a real host's own or, worse,
// silently win and send that host looking for the agent at a path this file
// invented -- which on the platform that has a real container path would be the
// one place the agent is not.

#include <LibreSCRS/Agent/pkcs11/AgentClientFactory.h>
#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>
#include <LibreSCRS/Agent/pkcs11/pkcs11.h>

#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

namespace LibreSCRS::Pkcs11Agent {

namespace {

// Re-reads the slots right after a derive returns, before C_DeriveKey takes its
// lock back. The socket client serves a presence read from its cache while a
// call holds the socket, so a card change during a derive is otherwise seen
// only by a refresh that happens to land in that window; this puts one there.
class RefreshAfterDerive final : public AgentClient
{
public:
    explicit RefreshAfterDerive(std::unique_ptr<AgentClient> inner) : m_inner(std::move(inner)) {}

    bool connected() const noexcept override
    {
        return m_inner->connected();
    }
    AgentSnapshot snapshot() override
    {
        return m_inner->snapshot();
    }
    BytesResult certDer(const std::string& reader, const std::string& certId) override
    {
        return m_inner->certDer(reader, certId);
    }
    PublicKeyResult publicKey(const std::string& reader, const std::string& certId,
                              LibreSCRS::Agent::KeyType keyType) override
    {
        return m_inner->publicKey(reader, certId, keyType);
    }
    LoginResult login(const std::string& reader) override
    {
        return m_inner->login(reader);
    }
    Status logout(const std::string& reader) override
    {
        return m_inner->logout(reader);
    }
    std::optional<bool> loginActive(const std::string& reader) override
    {
        return m_inner->loginActive(reader);
    }
    BytesResult signRaw(const std::string& reader, const std::string& certId, LibreSCRS::Agent::Mechanism mechanism,
                        std::span<const std::uint8_t> input) override
    {
        return m_inner->signRaw(reader, certId, mechanism, input);
    }
    BytesResult decrypt(const std::string& reader, const std::string& certId,
                        std::span<const std::uint8_t> ciphertext) override
    {
        return m_inner->decrypt(reader, certId, ciphertext);
    }
    BytesResult derive(const std::string& reader, const std::string& certId,
                       std::span<const std::uint8_t> peerPoint) override
    {
        BytesResult out = m_inner->derive(reader, certId, peerPoint);
        CK_ULONG count = 0;
        (void)C_GetSlotList(CK_FALSE, nullptr, &count);
        return out;
    }

private:
    std::unique_ptr<AgentClient> m_inner;
};

} // namespace

std::unique_ptr<AgentClient> makeAgentClient()
{
    const char* sock = std::getenv("LIBRESCRS_AGENT_SOCK");
    auto client = std::make_unique<SocketAgentClient>(std::string{sock != nullptr ? sock : ""});
    if (std::getenv("LIBRESCRS_TEST_REFRESH_AFTER_DERIVE") != nullptr)
        return std::make_unique<RefreshAfterDerive>(std::move(client));
    return client;
}

} // namespace LibreSCRS::Pkcs11Agent
