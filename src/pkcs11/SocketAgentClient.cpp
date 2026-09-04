// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>

#include <LibreSCRS/Agent/wire/ClientCodec.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/SyncError.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <variant>

namespace LibreSCRS::Pkcs11Agent {
namespace W = LibreSCRS::Agent::Wire;

namespace {

// RFC 5280 4.2.1.3 KeyUsage bit ordinals (== the agent's frozen keyUsageBits
// mask). Decrypt needs keyEncipherment OR dataEncipherment. The same two
// constants the bus client uses, for the same reason: the bit is the contract,
// the card name is not.
constexpr std::uint32_t kKeyEnciphermentBit = 1U << 2;
constexpr std::uint32_t kDataEnciphermentBit = 1U << 3;

/// Map a wire refusal onto the module's own vocabulary.
///
/// One name has no counterpart and that is a fact about the wire, not a bug in
/// this table: the socket contract has no token for "the user cancelled the
/// prompt", so a cancelled prompt arrives as the generic communication failure
/// and cannot be told apart from one. The bus transport does have that name and
/// does produce CKR_FUNCTION_CANCELED. Making the two agree needs a new token on
/// the wire and its four mirrors, which is a change to the contract rather than
/// to this file.
[[nodiscard]] Status mapWireError(W::SyncError e) noexcept
{
    switch (e) {
    case W::SyncError::UserNotLoggedIn:
        return Status::UserNotLoggedIn;
    case W::SyncError::NotAuthorized:
        return Status::NotAuthorized;
    case W::SyncError::AuthFailed:
        return Status::AuthFailed;
    case W::SyncError::KeyNotFound:
        return Status::KeyNotFound;
    case W::SyncError::UnknownCard:
        return Status::UnknownCard;
    case W::SyncError::NotSupported:
    case W::SyncError::UnsupportedOnThisCard:
        return Status::NotSupported;
    case W::SyncError::RateLimited:
        return Status::RateLimited;
    case W::SyncError::CommunicationError:
        return Status::Communication;
    default:
        return Status::GeneralError;
    }
}

[[nodiscard]] Status statusOf(const W::ErrInfo& info) noexcept
{
    if (const auto* sync = std::get_if<W::SyncError>(&info.code))
        return mapWireError(*sync);
    // A numeric ErrorCode on this seam means an async failure classification
    // arrived where a synchronous refusal was expected; there is nothing in the
    // module's vocabulary that is more specific than "general".
    return Status::GeneralError;
}

} // namespace

struct SocketAgentClient::Impl
{
    std::string path;
    SocketTimeouts budgets;
    int fd = -1;
    bool handshakeOk = false;
    std::uint64_t nextRequestId = 1;
    // Public-key results are immutable for the life of a card and the loader
    // asks for them per attribute read, so they are cached exactly as the bus
    // client caches them.
    std::map<std::string, PublicKeyResult> keyCache;

    // One connection, so one call at a time -- and that is exactly why a
    // presence read must not queue behind one. The module deliberately drops
    // its own global lock across a human-paced call so an unrelated C_* is not
    // stalled behind a PIN prompt; a client that made the socket the new global
    // lock would put that stall straight back, one layer down. Measured: with a
    // signature parked for three seconds, C_GetSlotList took 2.7 s.
    std::mutex callMutex;
    std::mutex cacheMutex;
    AgentSnapshot cachedSnapshot;
    bool haveSnapshot = false;

    ~Impl()
    {
        closeSocket();
    }

    void closeSocket() noexcept
    {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
        handshakeOk = false;
    }

    [[nodiscard]] bool setTimeout(int secs) const noexcept
    {
        timeval tv{};
        tv.tv_sec = secs;
        tv.tv_usec = 0;
        const bool r = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
        const bool s = ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
        return r && s;
    }

    /// Connect and shake hands. Order matters: the budgets are set BEFORE the
    /// first byte, or the handshake itself is the one call with no deadline.
    bool connect()
    {
        if (fd >= 0)
            return handshakeOk;
        const int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0)
            return false;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.empty() || path.size() >= sizeof(addr.sun_path)) {
            ::close(s);
            return false;
        }
        std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
        if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(s);
            return false;
        }
#ifdef SO_NOSIGPIPE
        // Darwin has no MSG_NOSIGNAL; without this a peer that closed would
        // take the whole loading process down with SIGPIPE.
        const int on = 1;
        (void)::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
        fd = s;
        (void)setTimeout(budgets.publicDataSecs);

        // The feature tokens are READ, not assumed. Nothing optional is
        // required today, but a handshake that failed must surface as
        // DeviceRemoved rather than as a quiet zero slots.
        const auto reply =
            call(W::Hello{W::kProtocolVersion, std::string{"librescrs-pkcs11-agent"}}, budgets.publicDataSecs);
        if (!reply.has_value())
            return false;
        if (!std::holds_alternative<W::HelloAck>(*reply))
            return false;
        handshakeOk = true;
        return true;
    }

    std::vector<W::CertInfo> readCertificates(const std::string& card)
    {
        // ReadCertificates is an OPERATION, not a call: OpStarted names an op id,
        // the list arrives as an OpResultReady event for that id, and OpFinished
        // closes it. Reading only the first frame would leave two frames in the
        // socket for the next call to mistake for its own.
        std::vector<W::CertInfo> out;
        const auto started = call(W::ReadCertificates{card}, budgets.publicDataSecs);
        if (!started.has_value())
            return out;
        const auto* op = std::get_if<W::OpStarted>(&*started);
        if (op == nullptr)
            return out;
        const std::uint64_t opId = op->op;

        for (;;) {
            auto frame = W::recvFrame(fd);
            if (!frame.has_value()) {
                closeSocket();
                return out;
            }
            if (!frame->fds.empty()) {
                closeSocket();
                return {};
            }
            const auto decoded = W::parseEvent(frame->body, {});
            if (!decoded.has_value()) {
                // A reply frame here is a reply to nothing this client is waiting
                // for; keep reading rather than treating it as our result.
                if (W::parseReply(frame->body, {}).has_value())
                    continue;
                closeSocket();
                return {};
            }
            if (const auto* ready = std::get_if<W::OpResultReady>(&decoded->event)) {
                if (ready->op != opId)
                    continue;
                if (const auto* list = std::get_if<W::CertListResult>(&ready->result))
                    out = list->certs;
                continue;
            }
            if (const auto* fin = std::get_if<W::OpFinished>(&decoded->event)) {
                if (fin->op != opId)
                    continue;
                if (fin->status != Agent::Operations::OperationStatus::Ok)
                    return {};
                return out;
            }
            // Anything else arriving inside our operation is someone else's news.
        }
    }

    /// Send one request and read frames until this request's reply arrives.
    ///
    /// Events that land in the middle belong to nobody here -- this client
    /// keeps no subscription -- and are discarded. An unrecognised reply arm or
    /// event is not an error: append tolerance is the wire's contract.
    [[nodiscard]] std::optional<W::ReplyVariant> call(const W::Request& request, int timeoutSecs)
    {
        if (fd < 0)
            return std::nullopt;
        if (!setTimeout(timeoutSecs))
            return std::nullopt;

        const std::uint64_t id = nextRequestId++;
        const auto body = W::encodeRequest(request, id);
        if (!W::sendFrame(fd, body).has_value()) {
            closeSocket();
            return std::nullopt;
        }

        for (;;) {
            auto frame = W::recvFrame(fd);
            if (!frame.has_value()) {
                closeSocket();
                return std::nullopt;
            }
            // No payload on this seam rides a descriptor. One that does is
            // either a different contract or an attempt to hand this process a
            // file it never asked for; the frame is refused and the descriptors
            // are closed rather than dropped, which UniqueFd does on scope exit.
            if (!frame->fds.empty()) {
                closeSocket();
                return std::nullopt;
            }
            if (auto decoded = W::parseReply(frame->body, {})) {
                if (decoded->requestId != id)
                    continue; // a reply to something else: not ours to read.
                return std::move(decoded->reply);
            }
            if (W::parseEvent(frame->body, {}).has_value())
                continue; // an event arriving inside our call. Discard it.
            // Neither a reply nor an event: the peer is not speaking this
            // contract any more.
            closeSocket();
            return std::nullopt;
        }
    }
};

SocketAgentClient::SocketAgentClient(std::string socketPath, SocketTimeouts timeouts) : m_impl(std::make_unique<Impl>())
{
    m_impl->path = std::move(socketPath);
    m_impl->budgets = timeouts;
    (void)m_impl->connect();
}

SocketAgentClient::~SocketAgentClient() = default;

bool SocketAgentClient::connected() const noexcept
{
    return m_impl && m_impl->fd >= 0 && m_impl->handshakeOk;
}

AgentSnapshot SocketAgentClient::snapshot()
{
    AgentSnapshot snap;

    // A presence read NEVER waits for the socket. If another call owns it --
    // a PIN prompt, a signature on the card -- the answer is what was last
    // seen, which is what a snapshot is. Blocking here would stall an
    // application's slot enumeration behind a human, which is the failure the
    // module drops its own lock to avoid.
    std::unique_lock<std::mutex> lock{m_impl->callMutex, std::try_to_lock};
    if (!lock.owns_lock()) {
        const std::lock_guard cache{m_impl->cacheMutex};
        return m_impl->cachedSnapshot;
    }

    if (!m_impl->connect())
        return snap;

    const auto stateReply = m_impl->call(W::GetState{}, m_impl->budgets.publicDataSecs);
    if (!stateReply.has_value())
        return snap;
    const auto* state = std::get_if<W::StateReply>(&*stateReply);
    if (state == nullptr)
        return snap;

    // Addressing is split on this wire and that is a real difference, not a
    // rename: certificates are read per CARD, while every Pk* call names a
    // READER. The reader->card mapping is the state reply's own.
    std::map<std::string, const W::CardState*> cardsByHandle;
    for (const auto& c : state->cards)
        cardsByHandle.emplace(c.handle, &c);

    for (const auto& r : state->readers) {
        ReaderState reader;
        reader.readerPath = r.handle;
        reader.hasCard = r.hasCard;
        if (!r.hasCard || !r.card.has_value()) {
            snap.readers.push_back(std::move(reader));
            continue;
        }
        const auto it = cardsByHandle.find(*r.card);
        const W::PreReadAuth preAuth = (it == cardsByHandle.end()) ? W::PreReadAuth::None : it->second->preAuth;

        // The capability gate, spelled exactly as the other transport spells
        // it: sign is driveable for both credential families, decrypt only for
        // the one whose plugin has a decipher primitive, and the hash-on-card
        // family selects a different advertised mechanism.
        const bool canDriveSigning = (preAuth == W::PreReadAuth::None || preAuth == W::PreReadAuth::Can);
        const bool canDriveDecrypt = (preAuth == W::PreReadAuth::None);
        const bool hashesOnCard = (preAuth == W::PreReadAuth::Can);

        const auto certs = m_impl->readCertificates(*r.card);
        std::uint8_t ckaId = 1;
        for (const auto& e : certs) {
            if (!e.signingCapable)
                continue;
            CertEntry ce;
            ce.certId = e.certId;
            ce.signingCapable = true;
            ce.ckaId = {ckaId++};
            ce.label = e.certId;
            if (const auto sg = e.fields.find("subject"); sg != e.fields.end()) {
                if (const auto cn = sg->second.find("cn"); cn != sg->second.end())
                    ce.label = cn->second.value;
            }
            const bool keyUsagePermitsDecrypt = (e.keyUsageBits & (kKeyEnciphermentBit | kDataEnciphermentBit)) != 0;
            ce.canSign = canDriveSigning;
            ce.canDecrypt = canDriveDecrypt && keyUsagePermitsDecrypt;
            ce.signsHashOnCard = hashesOnCard;
            reader.certs.push_back(std::move(ce));
        }
        snap.readers.push_back(std::move(reader));
    }
    {
        const std::lock_guard cache{m_impl->cacheMutex};
        m_impl->cachedSnapshot = snap;
        m_impl->haveSnapshot = true;
    }
    return snap;
}

BytesResult SocketAgentClient::certDer(const std::string& reader, const std::string& certId)
{
    const std::lock_guard<std::mutex> lock{m_impl->callMutex};
    BytesResult out;
    if (!m_impl->connect()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    const auto reply = m_impl->call(W::GetCertDer{reader, certId}, m_impl->budgets.publicDataSecs);
    if (!reply.has_value()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    if (const auto* err = std::get_if<W::ErrInfo>(&*reply)) {
        out.status = statusOf(*err);
        return out;
    }
    const auto* der = std::get_if<W::CertDerReply>(&*reply);
    if (der == nullptr)
        return out;
    out.status = Status::Ok;
    out.bytes = der->der;
    return out;
}

PublicKeyResult SocketAgentClient::publicKey(const std::string& reader, const std::string& certId)
{
    const std::lock_guard<std::mutex> lock{m_impl->callMutex};
    if (const auto hit = m_impl->keyCache.find(certId); hit != m_impl->keyCache.end())
        return hit->second;

    PublicKeyResult out;
    if (!m_impl->connect()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    const auto reply = m_impl->call(W::PkPublicKey{reader, certId}, m_impl->budgets.publicDataSecs);
    if (!reply.has_value()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    if (const auto* err = std::get_if<W::ErrInfo>(&*reply)) {
        out.status = statusOf(*err);
        return out;
    }
    const auto* pk = std::get_if<W::PublicKeyReply>(&*reply);
    if (pk == nullptr)
        return out;
    // EC keys are reserved on this wire and not produced; the module serves RSA
    // attributes only, on both transports.
    const auto* rsa = std::get_if<W::RsaPublicKey>(pk);
    if (rsa == nullptr) {
        out.status = Status::NotSupported;
        return out;
    }
    out.status = Status::Ok;
    out.modulus = rsa->n;
    out.exponent = rsa->e;
    m_impl->keyCache.emplace(certId, out);
    return out;
}

LoginResult SocketAgentClient::login(const std::string& reader)
{
    const std::lock_guard<std::mutex> lock{m_impl->callMutex};
    LoginResult out;
    if (!m_impl->connect()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    const auto reply = m_impl->call(W::PkLogin{reader}, m_impl->budgets.interactiveSecs);
    if (!reply.has_value()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    if (const auto* err = std::get_if<W::ErrInfo>(&*reply)) {
        out.status = statusOf(*err);
        return out;
    }
    if (!std::holds_alternative<W::AckReply>(*reply))
        return out;
    out.status = Status::Ok;
    // The socket contract's PkLogin carries no lease duration; zero means "the
    // agent did not say", which is what the module already treats as no hint.
    out.idleTimeoutSecs = 0;
    return out;
}

Status SocketAgentClient::logout(const std::string& reader)
{
    const std::lock_guard<std::mutex> lock{m_impl->callMutex};
    if (!m_impl->connect())
        return Status::DeviceRemoved;
    const auto reply = m_impl->call(W::PkLogout{reader}, m_impl->budgets.interactiveSecs);
    if (!reply.has_value())
        return Status::DeviceRemoved;
    if (const auto* err = std::get_if<W::ErrInfo>(&*reply))
        return statusOf(*err);
    return std::holds_alternative<W::AckReply>(*reply) ? Status::Ok : Status::GeneralError;
}

BytesResult SocketAgentClient::signRaw(const std::string& reader, const std::string& certId,
                                       std::span<const std::uint8_t> input)
{
    const std::lock_guard<std::mutex> lock{m_impl->callMutex};
    BytesResult out;
    if (!m_impl->connect()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    const auto reply =
        m_impl->call(W::PkSignRaw{reader, certId, {input.begin(), input.end()}}, m_impl->budgets.interactiveSecs);
    if (!reply.has_value()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    if (const auto* err = std::get_if<W::ErrInfo>(&*reply)) {
        out.status = statusOf(*err);
        return out;
    }
    const auto* sig = std::get_if<W::RawSignatureReply>(&*reply);
    if (sig == nullptr)
        return out;
    out.status = Status::Ok;
    out.bytes = sig->sig;
    return out;
}

BytesResult SocketAgentClient::decrypt(const std::string& reader, const std::string& certId,
                                       std::span<const std::uint8_t> ciphertext)
{
    const std::lock_guard<std::mutex> lock{m_impl->callMutex};
    BytesResult out;
    if (!m_impl->connect()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    const auto reply = m_impl->call(W::PkDecrypt{reader, certId, {ciphertext.begin(), ciphertext.end()}},
                                    m_impl->budgets.interactiveSecs);
    if (!reply.has_value()) {
        out.status = Status::DeviceRemoved;
        return out;
    }
    if (const auto* err = std::get_if<W::ErrInfo>(&*reply)) {
        out.status = statusOf(*err);
        return out;
    }
    const auto* plain = std::get_if<W::RawSignatureReply>(&*reply);
    if (plain == nullptr)
        return out;
    out.status = Status::Ok;
    out.bytes = plain->sig;
    return out;
}

} // namespace LibreSCRS::Pkcs11Agent
