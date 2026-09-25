// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// A scripted agent peer on a temporary AF_UNIX socket, with no Qt in it.
//
// This project already has two doubles for this seam and neither can stand in
// here: one talks over a bus, the other links Qt. The module this fake serves
// may link neither, so a third one exists -- and it is the framed CBOR wire it
// speaks, encoded by the same server-role encoders the real agent uses, so
// every byte it emits is canonical by construction rather than by hand.
//
// Threading: one accept thread and one blocking connection thread per client.
// The client under test is blocking and single-threaded by design, so nothing
// here needs an event loop.
//
// What it can be told to do, and why each one is here rather than convenient:
//   * delay a named call -- so a timeout budget can be shown to be two budgets
//     and not one;
//   * refuse a named call with a chosen SyncError -- a double that always
//     succeeds hides the half of the mapping that matters;
//   * push an unrelated event into the middle of an operation -- a client that
//     never sees an interleaved frame has not been shown to discard one.

#include <LibreSCRS/Agent/wire/ClientCodec.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/SyncError.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace LibreSCRS::Agent::Test {

// The canned answers this double gives, named so a suite states what it expects
// rather than repeating a literal. They are deliberately the SAME values the
// bus double serves: the two suites that drive the C ABI are one set of claims
// about the module, and a different constant on each side would turn a real
// disagreement into two green suites.
inline const std::vector<std::uint8_t> kCannedSig = {0xAA, 0xBB, 0xCC, 0xDD};
inline const std::vector<std::uint8_t> kCannedPlain = {0x11, 0x22, 0x33};
inline const std::vector<std::uint8_t> kCannedDer = {0x30, 0x82, 0x01};
inline const std::vector<std::uint8_t> kCannedExponent = {0x01, 0x00, 0x01};
inline constexpr const char* kCertId = "cert-abc";
inline constexpr const char* kReader0 = "/org/librescrs/Agent/reader/0";
inline constexpr const char* kCard0 = "/org/librescrs/Agent/card/0";
/// keyEncipherment | dataEncipherment -- what a decryptable key carries.
inline constexpr std::uint32_t kDecryptableKeyUsage = 0x0C;

/// A 2048-bit big-endian modulus whose top byte is non-zero (the CKA_*
/// unpadded convention).
[[nodiscard]] inline std::vector<std::uint8_t> cannedModulus()
{
    std::vector<std::uint8_t> n(256, 0x00);
    n[0] = 0xC4;
    for (std::size_t i = 1; i < n.size(); ++i)
        n[i] = static_cast<std::uint8_t>(i & 0xFF);
    return n;
}

/// @brief Connect a blocking SOCK_STREAM AF_UNIX socket to @p path.
/// @return the fd, or -1. The caller owns and closes it.
[[nodiscard]] int connectTo(const std::string& path);

/// @brief A short, unique socket path. sun_path is 104 bytes on Darwin and
///        108 on Linux, and the shortest of those is the one to fit.
[[nodiscard]] std::string makeSocketPath(const char* tag);

/// @brief Which call a script entry applies to. These are the wire's own
///        request names; the fake refuses to invent any others.
enum class Call : std::uint8_t {
    Hello,
    GetState,
    ReadCertificates,
    GetCertDer,
    PkPublicKey,
    PkLogin,
    PkLogout,
    PkSignRaw,
    PkDecrypt,
};

/// @brief One scripted certificate a ReadCertificates operation returns.
struct FakeCert
{
    std::string certId;
    std::string subjectCn;
    bool signingCapable = true;
    std::uint32_t keyUsageBits = 0;
    std::uint32_t trustStatus = 255;
};

/// @brief One scripted reader, and the card (if any) seated in it.
struct FakeReader
{
    std::string handle;
    std::string name;
    bool hasCard = false;
    std::string card;
    Wire::PreReadAuth preAuth = Wire::PreReadAuth::None;
    std::vector<FakeCert> certs;
};

class FakeSocketAgent
{
public:
    FakeSocketAgent();
    ~FakeSocketAgent();

    FakeSocketAgent(const FakeSocketAgent&) = delete;
    FakeSocketAgent& operator=(const FakeSocketAgent&) = delete;

    /// @brief Add a reader with no card.
    void addReader(std::string handle, std::string name = "Fake reader");
    /// @brief Add a reader with a card seated in it.
    void addReader(std::string handle, bool hasCard, std::string card,
                   Wire::PreReadAuth preAuth = Wire::PreReadAuth::None);
    /// @brief Attach a signing certificate to a card.
    void addCert(const std::string& card, std::string certId, bool signingCapable = true,
                 std::uint32_t keyUsageBits = 0);

    /// @brief Make @p call sleep before it answers.
    void delayCall(Call call, std::chrono::milliseconds d);
    /// @brief Make @p call answer with an error reply carrying @p e.
    void failCall(Call call, Wire::SyncError e);
    /// @brief Push one CardAdded event between OpStarted and OpFinished of the
    ///        next ReadCertificates. A client that does not discard it will
    ///        mistake it for its own reply.
    void interleaveEventInsideNextOperation(bool on = true);
    /// @brief Answer Hello with these feature tokens.
    void setFeatures(std::vector<std::string> features);
    /// @brief Answer the next Hello with a protocol the client did not ask for.
    void refuseNextHello(bool on = true);
    /// @brief Attach one file descriptor to the next reply.
    ///
    /// Nothing on this seam carries a descriptor, so a client that quietly
    /// accepted one would be accepting a file it never asked for and leaking
    /// it. Only a fake can produce that frame.
    void attachDescriptorToNextReply(bool on = true);

    /// @brief Bind on a caller-chosen path instead of the generated one. Must
    ///        be called before start(): a harness that has to hand the path to
    ///        another process needs to choose it, not read it back.
    void setPath(std::string path);

    /// @brief Bind, listen, and start accepting. Idempotent.
    void start();
    /// @brief Stop accepting, join every thread, unlink the socket.
    void stop();

    [[nodiscard]] const std::string& path() const noexcept
    {
        return m_path;
    }
    /// @brief How many requests of @p call have been served.
    [[nodiscard]] int callCount(Call call) const;
    /// @brief The bytes of the most recent PkSignRaw. A canned signature alone
    ///        would pass even if the module had sent the wrong input.
    [[nodiscard]] std::vector<std::uint8_t> lastSignInput() const;
    /// @brief The most recent Hello this fake served. A client that means to
    ///        opt out of presence events has to be caught on the wire; a fake
    ///        that only counted the call would pass either way.
    [[nodiscard]] Wire::Hello lastHello() const;

    /// @brief Take the card out of the first reader that has one.
    void removeCard();
    /// @brief Put it back, with the certificates it had.
    void insertCard();

private:
    void acceptLoop();
    void serve(int fd);
    [[nodiscard]] bool answer(int fd, const Wire::RequestEnvelope& env);
    void applyScript(Call call);
    [[nodiscard]] std::optional<Wire::SyncError> scriptedFailure(Call call) const;
    [[nodiscard]] Wire::StateReply buildState() const;
    [[nodiscard]] std::vector<Wire::CertInfo> buildCerts(const std::string& card) const;

    std::string m_path;
    int m_listen = -1;
    std::atomic<bool> m_running{false};
    std::thread m_acceptor;
    std::vector<std::thread> m_conns;

    mutable std::mutex m_mutex;
    std::vector<FakeReader> m_readers;
    std::vector<FakeReader> m_removed; ///< cards taken out, for insertCard()
    std::vector<std::uint8_t> m_lastSignInput;
    Wire::Hello m_lastHello;
    std::map<Call, std::chrono::milliseconds> m_delays;
    std::map<Call, Wire::SyncError> m_failures;
    std::map<Call, int> m_counts;
    std::vector<std::string> m_features;
    bool m_interleave = false;
    bool m_refuseHello = false;
    bool m_attachFd = false;
    std::uint64_t m_nextOp = 1;
};

} // namespace LibreSCRS::Agent::Test
