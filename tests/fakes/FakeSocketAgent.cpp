// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "fakes/FakeSocketAgent.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string_view>

namespace LibreSCRS::Agent::Test {
namespace W = LibreSCRS::Agent::Wire;

namespace {

// The three card capability bits this fake needs to advertise. A card whose
// PKI bit is clear is a card the agent cannot drive, which is a case the slot
// model is required to answer differently -- so the bit is scripted, not
// assumed.
constexpr std::uint32_t kCapPki = 1U << 1;

void sleepFor(std::chrono::milliseconds d)
{
    if (d.count() > 0)
        std::this_thread::sleep_for(d);
}

} // namespace

std::string makeSocketPath(const char* tag)
{
    // Short by construction: sun_path is 104 bytes on Darwin, and a path built
    // from TMPDIR plus a long test name has overrun it before.
    static std::mt19937_64 rng{std::random_device{}()};
    const char* tmp = std::getenv("TMPDIR");
    std::string dir = (tmp != nullptr && *tmp != '\0') ? tmp : "/tmp";
    if (!dir.empty() && dir.back() == '/')
        dir.pop_back();
    return dir + "/fsa-" + tag + "-" + std::to_string(::getpid()) + "-" + std::to_string(rng() % 100000U) + ".sock";
}

int connectTo(const std::string& path)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return -1;
    }
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

FakeSocketAgent::FakeSocketAgent() : m_path(makeSocketPath("agent")), m_features{"credentials", "login-state"} {}

FakeSocketAgent::~FakeSocketAgent()
{
    stop();
}

void FakeSocketAgent::addReader(std::string handle, std::string name)
{
    const std::lock_guard lock{m_mutex};
    m_readers.push_back(FakeReader{std::move(handle), std::move(name), false, {}, W::PreReadAuth::None, {}});
}

void FakeSocketAgent::addReader(std::string handle, bool hasCard, std::string card, W::PreReadAuth preAuth)
{
    const std::lock_guard lock{m_mutex};
    m_readers.push_back(FakeReader{std::move(handle), "Fake reader", hasCard, std::move(card), preAuth, {}});
}

void FakeSocketAgent::setReaderName(const std::string& handle, std::string name)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        if (r.handle == handle) {
            r.name = std::move(name);
            return;
        }
    }
}

void FakeSocketAgent::addCert(const std::string& card, std::string certId, bool signingCapable,
                              std::uint32_t keyUsageBits, std::string subjectCn)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        if (r.card == card) {
            r.certs.push_back(FakeCert{std::move(certId), std::move(subjectCn), signingCapable, keyUsageBits, 255});
            r.certs.back().keyId.assign(r.certs.back().certId.begin(), r.certs.back().certId.end());
            return;
        }
    }
}

void FakeSocketAgent::setAlwaysAuthenticate(const std::string& certId, bool on)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        for (auto& c : r.certs) {
            if (c.certId == certId)
                c.alwaysAuthenticate = on;
        }
    }
}

void FakeSocketAgent::setKeyFacts(const std::string& certId, std::vector<std::uint8_t> keyId, KeyType type,
                                  std::uint32_t bits, bool canDerive)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        for (auto& c : r.certs) {
            if (c.certId == certId) {
                c.keyId = keyId;
                c.keyType = type;
                c.keyBits = bits;
                c.canDerive = canDerive;
            }
        }
    }
}

void FakeSocketAgent::setEcPoint(const std::string& certId, std::string crv, std::vector<std::uint8_t> x,
                                 std::vector<std::uint8_t> y)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        for (auto& c : r.certs) {
            if (c.certId == certId) {
                c.crv = crv;
                c.ecX = x;
                c.ecY = y;
                c.ecPointSeated = true;
            }
        }
    }
}

void FakeSocketAgent::setCertDer(const std::string& certId, std::vector<std::uint8_t> der)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        for (auto& c : r.certs) {
            if (c.certId == certId)
                c.der = der;
        }
    }
}

void FakeSocketAgent::delayCall(Call call, std::chrono::milliseconds d)
{
    const std::lock_guard lock{m_mutex};
    m_delays[call] = d;
}

void FakeSocketAgent::failCall(Call call, W::SyncError e)
{
    const std::lock_guard lock{m_mutex};
    m_failures[call] = e;
}

void FakeSocketAgent::interleaveEventInsideNextOperation(bool on)
{
    const std::lock_guard lock{m_mutex};
    m_interleave = on;
}

void FakeSocketAgent::setFeatures(std::vector<std::string> features)
{
    const std::lock_guard lock{m_mutex};
    m_features = std::move(features);
}

void FakeSocketAgent::refuseNextHello(bool on)
{
    const std::lock_guard lock{m_mutex};
    m_refuseHello = on;
}

void FakeSocketAgent::attachDescriptorToNextReply(bool on)
{
    const std::lock_guard lock{m_mutex};
    m_attachFd = on;
}

std::vector<std::uint8_t> FakeSocketAgent::lastSignInput() const
{
    const std::lock_guard lock{m_mutex};
    return m_lastSignInput;
}

std::string FakeSocketAgent::lastSignMechanism() const
{
    const std::lock_guard lock{m_mutex};
    return m_lastSignMechanism;
}

std::vector<std::uint8_t> FakeSocketAgent::lastDerivePoint() const
{
    const std::lock_guard lock{m_mutex};
    return m_lastDerivePoint;
}

void FakeSocketAgent::setSignResponder(std::function<std::vector<std::uint8_t>(const W::PkSignRaw&)> f)
{
    const std::lock_guard lock{m_mutex};
    m_signResponder = std::move(f);
}

void FakeSocketAgent::setDeriveResponder(std::function<std::vector<std::uint8_t>(const W::PkDerive&)> f)
{
    const std::lock_guard lock{m_mutex};
    m_deriveResponder = std::move(f);
}

Wire::Hello FakeSocketAgent::lastHello() const
{
    const std::lock_guard lock{m_mutex};
    return m_lastHello;
}

void FakeSocketAgent::removeCard()
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        if (!r.hasCard)
            continue;
        m_removed.push_back(r);
        r.hasCard = false;
        r.card.clear();
        r.certs.clear();
        return;
    }
}

void FakeSocketAgent::insertCard()
{
    const std::lock_guard lock{m_mutex};
    if (m_removed.empty())
        return;
    const FakeReader saved = m_removed.back();
    m_removed.pop_back();
    for (auto& r : m_readers) {
        if (r.handle == saved.handle) {
            r = saved;
            return;
        }
    }
}

void FakeSocketAgent::swapCard(std::string card)
{
    const std::lock_guard lock{m_mutex};
    for (auto& r : m_readers) {
        if (r.hasCard) {
            r.card = std::move(card);
            return;
        }
    }
}

void FakeSocketAgent::expireLogin(const std::string& reader)
{
    const std::lock_guard lock{m_mutex};
    m_loggedIn.erase(reader);
}

int FakeSocketAgent::callCount(Call call) const
{
    const std::lock_guard lock{m_mutex};
    const auto it = m_counts.find(call);
    return it == m_counts.end() ? 0 : it->second;
}

void FakeSocketAgent::setPath(std::string path)
{
    m_path = std::move(path);
}

void FakeSocketAgent::start()
{
    if (m_running.load())
        return;
    ::unlink(m_path.c_str());
    m_listen = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_listen < 0)
        return;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, m_path.c_str(), m_path.size() + 1);
    if (::bind(m_listen, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(m_listen, 4) != 0) {
        ::close(m_listen);
        m_listen = -1;
        return;
    }
    m_running.store(true);
    m_acceptor = std::thread{[this] { acceptLoop(); }};
}

void FakeSocketAgent::stop()
{
    if (!m_running.exchange(false))
        return;
    // Shut the listener down before joining: accept() is blocking, and closing
    // the fd out from under it is the portable way to wake it.
    if (m_listen >= 0) {
        ::shutdown(m_listen, SHUT_RDWR);
        ::close(m_listen);
        m_listen = -1;
    }
    if (m_acceptor.joinable())
        m_acceptor.join();
    for (auto& t : m_conns) {
        if (t.joinable())
            t.join();
    }
    m_conns.clear();
    ::unlink(m_path.c_str());
}

void FakeSocketAgent::acceptLoop()
{
    while (m_running.load()) {
        const int fd = ::accept(m_listen, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        m_conns.emplace_back([this, fd] { serve(fd); });
    }
}

void FakeSocketAgent::serve(int fd)
{
    while (m_running.load()) {
        auto frame = W::recvFrame(fd);
        if (!frame.has_value())
            break;
        // A frame that arrives with descriptors is not something this seam ever
        // sends, so the fake never produces one either -- but it closes any it
        // is handed rather than leaking them into the test process.
        const auto env = W::parseRequest(frame->body);
        if (!env.has_value())
            break;
        if (!answer(fd, *env))
            break;
    }
    ::close(fd);
}

std::optional<W::SyncError> FakeSocketAgent::scriptedFailure(Call call) const
{
    const std::lock_guard lock{m_mutex};
    const auto it = m_failures.find(call);
    if (it == m_failures.end())
        return std::nullopt;
    return it->second;
}

void FakeSocketAgent::applyScript(Call call)
{
    std::chrono::milliseconds d{0};
    {
        const std::lock_guard lock{m_mutex};
        ++m_counts[call];
        const auto it = m_delays.find(call);
        if (it != m_delays.end())
            d = it->second;
    }
    sleepFor(d);
}

W::StateReply FakeSocketAgent::buildState() const
{
    const std::lock_guard lock{m_mutex};
    W::StateReply reply;
    for (const auto& r : m_readers) {
        W::ReaderState rs;
        rs.handle = r.handle;
        rs.name = r.name;
        rs.hasCard = r.hasCard;
        if (r.hasCard)
            rs.card = r.card;
        reply.readers.push_back(std::move(rs));
        if (r.hasCard) {
            W::CardState cs;
            cs.handle = r.card;
            cs.reader = r.handle;
            cs.caps = kCapPki;
            cs.preAuth = r.preAuth;
            reply.cards.push_back(std::move(cs));
        }
    }
    return reply;
}

std::vector<W::CertInfo> FakeSocketAgent::buildCerts(const std::string& card) const
{
    const std::lock_guard lock{m_mutex};
    std::vector<W::CertInfo> out;
    for (const auto& r : m_readers) {
        if (r.card != card)
            continue;
        for (const auto& c : r.certs) {
            W::CertInfo ci;
            ci.certId = c.certId;
            ci.signingCapable = c.signingCapable;
            ci.keyUsageBits = c.keyUsageBits;
            ci.trustStatus = c.trustStatus;
            ci.alwaysAuthenticate = c.alwaysAuthenticate;
            ci.keyId = c.keyId;
            ci.keyType = c.keyType;
            ci.keyBits = c.keyBits;
            ci.canDerive = c.canDerive;
            // The subject CN is the label the module shows, and it rides the
            // grouped `fields` dict rather than a field of its own -- the same
            // shape the bus surface uses, so the two clients read one place.
            // An empty CN is a subject without one, and is left out.
            if (!c.subjectCn.empty())
                ci.fields["subject"]["cn"] = W::CertField{"subject.cn", "Subject", c.subjectCn};
            out.push_back(std::move(ci));
        }
    }
    return out;
}

bool FakeSocketAgent::answer(int fd, const W::RequestEnvelope& env)
{
    const auto send = [this, fd](const W::CborValue& v) {
        bool withFd = false;
        {
            const std::lock_guard lock{m_mutex};
            if (m_attachFd) {
                m_attachFd = false;
                withFd = true;
            }
        }
        if (!withFd)
            return W::sendFrame(fd, v.encode()).has_value();
        // /dev/null, because the point is that a descriptor arrived at all --
        // what it points at is not part of the claim.
        const int spare = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (spare < 0)
            return false;
        const int one[] = {spare};
        const bool ok = W::sendFrame(fd, v.encode(), one).has_value();
        ::close(spare);
        return ok;
    };
    const auto refuse = [&](W::SyncError e) {
        W::ErrInfo info;
        info.code = e;
        return send(W::makeErrorReply(env.req, info));
    };

    if (const auto* hello = std::get_if<W::Hello>(&env.body)) {
        applyScript(Call::Hello);
        bool refuseIt = false;
        std::vector<std::string> feats;
        {
            const std::lock_guard lock{m_mutex};
            refuseIt = m_refuseHello;
            m_refuseHello = false;
            feats = m_features;
            m_lastHello = *hello;
        }
        if (refuseIt || hello->proto != W::kProtocolVersion)
            return refuse(W::SyncError::UnsupportedProtocol);
        return send(W::makeReply(env.req, W::HelloAck{"0.0-fake", feats}));
    }

    if (std::holds_alternative<W::GetState>(env.body)) {
        applyScript(Call::GetState);
        if (const auto e = scriptedFailure(Call::GetState))
            return refuse(*e);
        return send(W::makeReply(env.req, buildState()));
    }

    if (const auto* rc = std::get_if<W::ReadCertificates>(&env.body)) {
        applyScript(Call::ReadCertificates);
        if (const auto e = scriptedFailure(Call::ReadCertificates))
            return refuse(*e);
        // An operation is three frames, not one. A fake that replied with the
        // list inline would let a client that never drives an operation pass
        // every later test in this plan.
        std::uint64_t op = 0;
        bool interleave = false;
        {
            const std::lock_guard lock{m_mutex};
            op = m_nextOp++;
            interleave = m_interleave;
            m_interleave = false;
        }
        if (!send(W::makeReply(env.req, W::OpStarted{op})))
            return false;
        if (interleave) {
            W::CardState stray;
            stray.handle = "interleaved-card";
            stray.reader = "interleaved-reader";
            if (!send(W::toCbor(W::CardAdded{stray})))
                return false;
        }
        if (!send(W::toCbor(W::OpResultReady{op, W::CertListResult{buildCerts(rc->card)}})))
            return false;
        return send(W::toCbor(W::OpFinished{op, Operations::OperationStatus::Ok, ErrorCode::None, {}, {}}));
    }

    if (const auto* get = std::get_if<W::GetCertDer>(&env.body)) {
        applyScript(Call::GetCertDer);
        if (const auto e = scriptedFailure(Call::GetCertDer))
            return refuse(*e);
        std::vector<std::uint8_t> der = kCannedDer;
        {
            const std::lock_guard lock{m_mutex};
            for (const auto& r : m_readers) {
                for (const auto& c : r.certs) {
                    if (c.certId == get->cert && !c.der.empty())
                        der = c.der;
                }
            }
        }
        return send(W::makeReply(env.req, W::CertDerReply{der}));
    }

    if (const auto* pk = std::get_if<W::PkPublicKey>(&env.body)) {
        applyScript(Call::PkPublicKey);
        if (const auto e = scriptedFailure(Call::PkPublicKey))
            return refuse(*e);
        std::optional<W::PublicKeyReply> ec;
        bool ecWithoutPoint = false;
        {
            const std::lock_guard lock{m_mutex};
            for (const auto& r : m_readers) {
                for (const auto& c : r.certs) {
                    if (c.certId != pk->cert || c.keyType != KeyType::Ec)
                        continue;
                    if (c.ecPointSeated)
                        ec = W::PublicKeyReply{W::EcPublicKey{c.crv, c.ecX, c.ecY}};
                    else
                        ecWithoutPoint = true;
                }
            }
        }
        if (ec)
            return send(W::makeReply(env.req, *ec));
        if (ecWithoutPoint)
            return refuse(W::SyncError::KeyNotFound);
        return send(W::makeReply(env.req, W::PublicKeyReply{W::RsaPublicKey{cannedModulus(), kCannedExponent}}));
    }

    if (std::holds_alternative<W::PkLogin>(env.body)) {
        applyScript(Call::PkLogin);
        if (const auto e = scriptedFailure(Call::PkLogin))
            return refuse(*e);
        {
            const std::lock_guard lock{m_mutex};
            m_loggedIn.insert(std::get<W::PkLogin>(env.body).reader);
        }
        return send(W::makeReply(env.req, W::AckReply{}));
    }

    if (std::holds_alternative<W::PkLogout>(env.body)) {
        applyScript(Call::PkLogout);
        if (const auto e = scriptedFailure(Call::PkLogout))
            return refuse(*e);
        {
            const std::lock_guard lock{m_mutex};
            m_loggedIn.erase(std::get<W::PkLogout>(env.body).reader);
        }
        return send(W::makeReply(env.req, W::AckReply{}));
    }

    if (const auto* ls = std::get_if<W::PkLoginState>(&env.body)) {
        applyScript(Call::PkLoginState);
        if (const auto e = scriptedFailure(Call::PkLoginState))
            return refuse(*e);
        bool active = false;
        {
            const std::lock_guard lock{m_mutex};
            active = m_loggedIn.contains(ls->reader);
        }
        return send(W::makeReply(env.req, W::LoginStateReply{active}));
    }

    if (const auto* sr = std::get_if<W::PkSignRaw>(&env.body)) {
        applyScript(Call::PkSignRaw);
        if (const auto e = scriptedFailure(Call::PkSignRaw))
            return refuse(*e);
        // The canned signature is a constant, but what arrived is recorded:
        // a canned answer alone would pass even if the module had sent the
        // wrong bytes, so the suite asserts the INPUT, not only the output.
        std::function<std::vector<std::uint8_t>(const W::PkSignRaw&)> responder;
        {
            const std::lock_guard lock{m_mutex};
            m_lastSignInput = sr->data;
            m_lastSignMechanism = sr->mech;
            responder = m_signResponder;
        }
        // Called outside the lock: a responder may sign with a real key.
        return send(W::makeReply(env.req, W::RawSignatureReply{responder ? responder(*sr) : kCannedSig}));
    }

    if (const auto* dec = std::get_if<W::PkDecrypt>(&env.body)) {
        applyScript(Call::PkDecrypt);
        if (const auto e = scriptedFailure(Call::PkDecrypt))
            return refuse(*e);
        (void)dec;
        return send(W::makeReply(env.req, W::RawSignatureReply{kCannedPlain}));
    }

    if (const auto* dv = std::get_if<W::PkDerive>(&env.body)) {
        applyScript(Call::PkDerive);
        if (const auto e = scriptedFailure(Call::PkDerive))
            return refuse(*e);
        std::function<std::vector<std::uint8_t>(const W::PkDerive&)> responder;
        {
            const std::lock_guard lock{m_mutex};
            m_lastDerivePoint = dv->data;
            responder = m_deriveResponder;
        }
        // Called outside the lock: a responder may derive with a real key.
        return send(W::makeReply(env.req, W::DerivedSecretReply{responder ? responder(*dv) : kCannedSecret}));
    }

    // Anything else this seam never asks for.
    return refuse(W::SyncError::NotSupported);
}

} // namespace LibreSCRS::Agent::Test
