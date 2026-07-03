// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Guard: EVERY worker closure that can outlive the AgentCore aggregate must
// value-capture the SINGLE crypto-worker context (prompter + prompt gate +
// credential cache + lease + shutdown token) WHOLE, deref its members rather than
// the aggregate's, and SKIP its completion on the shutdown-cancel path — so an
// abandoned worker that unblocks after the aggregate is gone touches only co-owned
// memory and never drives its completion into a torn-down broker / reply channel.
// The broker's PIN-state callbacks AND its login continuation must co-own the lease
// SHARE, never the broker `this`. Reads the shipped source so the ownership
// invariant survives refactors, mirroring TransportCaptureGuardTest.

#include <cstddef>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

namespace {
std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::size_t countOf(const std::string& hay, const std::string& needle)
{
    std::size_t n = 0;
    for (std::size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + 1)) {
        ++n;
    }
    return n;
}
} // namespace

TEST(RawCryptoCaptureGuard, RawWorkerClosureCoOwnsTheWholeContext)
{
    const std::string src = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(src.empty()) << "AgentCore source path not wired";

    // The single context share is taken before the enqueue and value-captured by
    // the closure (instead of the four separate per-member shares).
    EXPECT_NE(src.find("auto ctx = m_cryptoCtx"), std::string::npos)
        << "the worker closures must value-capture the single crypto-worker context";

    // The raw flow must run against the context's co-owned members, never the raw
    // aggregate members.
    EXPECT_NE(src.find("*ctx->prompter"), std::string::npos)
        << "the raw flow must run against the co-owned prompter (*ctx->prompter)";
    EXPECT_NE(src.find("*ctx->serializer"), std::string::npos)
        << "the raw flow must run against the co-owned prompt gate (*ctx->serializer)";
    EXPECT_NE(src.find("*ctx->credentials"), std::string::npos)
        << "the raw flow must run against the co-owned credential cache (*ctx->credentials)";
    EXPECT_NE(src.find("ctx->shutdown"), std::string::npos)
        << "the raw flow must be wired with the context's shutdown-cancel token (ctx->shutdown)";

    // The pre-fix per-member captures must be gone.
    EXPECT_EQ(src.find("auto prompter = m_prompter"), std::string::npos)
        << "the pre-fix separate prompter share must be gone (folded into the context)";
    EXPECT_EQ(src.find("auto serializer = m_serializer"), std::string::npos)
        << "the pre-fix separate serializer share must be gone (folded into the context)";
    EXPECT_EQ(src.find("auto credentials = m_credentials"), std::string::npos)
        << "the pre-fix separate credential-cache share must be gone (folded into the context)";
    EXPECT_EQ(src.find("&m_credentials"), std::string::npos)
        << "the worker closure must co-own the context, not take a raw &m_credentials";
}

TEST(RawCryptoCaptureGuard, EveryWorkerClosureCapturesContextAndSkipsOnShutdown)
{
    const std::string src = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(src.empty()) << "AgentCore source path not wired";

    // Three worker closures can outlive the aggregate: the raw sign/decrypt path,
    // the cert-DER path (also serving the PublicKey caller, which routes through
    // exportCertDerOnWorker), and the login path. Each takes its own context share.
    EXPECT_GE(countOf(src, "auto ctx = m_cryptoCtx"), 3u)
        << "raw, cert-DER, and login worker closures must each capture the context";

    // Each closure must add the uniform shutdown skip before invoking its
    // completion, so an abandoned worker never drives a torn-down broker / reply.
    EXPECT_GE(countOf(src, "ctx->shutdown.isCancelled()"), 3u)
        << "raw, cert-DER, and login worker closures must each skip completion on shutdown-cancel";

    // The login worker closure must capture the context (not just `done`).
    EXPECT_NE(src.find("[done, ctx](Operations::CardSessionHolder& holder)"), std::string::npos)
        << "the login worker closure must value-capture the context, not only `done`";
    // The cert-DER worker closure must capture the context (not just certId + done).
    EXPECT_NE(src.find("[certId, done = std::move(done), ctx]"), std::string::npos)
        << "the cert-DER worker closure must value-capture the context";
}

TEST(RawCryptoCaptureGuard, CryptoContextCoOwnsTheSigningEngineAndConfig)
{
    const std::string src = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(src.empty()) << "AgentCore source path not wired";

    // The config + signing-engine provider are shared_ptr the AgentCore ctor folds
    // into the single crypto-worker context, so an abandoned qualified-sign worker
    // co-owns both through its captured context share (its seam's post-unblock
    // snapshot() + recordLastTsaUrlUsed touch them).
    EXPECT_NE(src.find(".config = m_config"), std::string::npos)
        << "the crypto context must co-own the config share (.config = m_config)";
    EXPECT_NE(src.find(".signingEngine = m_signingEngine"), std::string::npos)
        << "the crypto context must co-own the signing-engine share (.signingEngine = m_signingEngine)";
    // The provider is built from the co-owned config share, so its own ConfigStore&
    // is backed by the same object the context keeps alive.
    EXPECT_NE(src.find("std::make_shared<Operations::SigningEngineProvider>(*m_config)"), std::string::npos)
        << "the signing-engine provider must be built from the co-owned config share";
    // The pre-fix value members must be gone (they left the engine/config freed with
    // the aggregate while a zombie sign worker was still parked).
    EXPECT_EQ(src.find("m_signingEngine(m_config)"), std::string::npos)
        << "the pre-fix value-member signing engine must be gone (folded into the context)";
}

TEST(RawCryptoCaptureGuard, BrokerPinStateCoOwnsTheLeaseShare)
{
    const std::string src = slurp(LIBREAGENT_PKCS11BROKER_CPP);
    ASSERT_FALSE(src.empty()) << "Pkcs11Broker source path not wired";

    // The lease-scoped PIN-state callbacks — value-captured by the raw-crypto worker
    // via the pinState — must co-own the lease SHARE (so an abandoned worker touches
    // the lease through its own share), never capture the broker `this` (which the
    // zombie would deref after the broker is freed).
    EXPECT_NE(src.find(".isVerified = [lease = m_deps.lease, key]"), std::string::npos)
        << "isVerified must co-own the lease share, not capture the broker `this`";
    EXPECT_NE(src.find(".markVerified = [lease = m_deps.lease, key]"), std::string::npos)
        << "markVerified must co-own the lease share, not capture the broker `this`";
    EXPECT_NE(src.find(".clearVerified = [lease = m_deps.lease, key]"), std::string::npos)
        << "clearVerified must co-own the lease share, not capture the broker `this`";
    EXPECT_EQ(src.find(".isVerified = [this, key]"), std::string::npos)
        << "the pre-fix pinState captured the broker `this`; that must be gone";
}

TEST(RawCryptoCaptureGuard, LoginContinuationCoOwnsTheLeaseShareNotTheBroker)
{
    const std::string src = slurp(LIBREAGENT_PKCS11BROKER_CPP);
    ASSERT_FALSE(src.empty()) << "Pkcs11Broker source path not wired";

    // The login continuation runs on the (abandonable) worker thread and grants the
    // lease; it must co-own the lease SHARE + clock seam, never the broker `this`.
    EXPECT_NE(src.find("m_deps.login(reader, [lease = m_deps.lease, now = m_deps.now"), std::string::npos)
        << "the login continuation must co-own the lease share + clock seam, not the broker `this`";
    EXPECT_EQ(src.find("m_deps.login(reader, [this, reply, caller"), std::string::npos)
        << "the pre-fix login continuation captured the broker `this`; that must be gone";
}

TEST(RawCryptoCaptureGuard, CompletionWrapperRechecksShutdownBeforeBrokerDeref)
{
    const std::string broker = slurp(LIBREAGENT_PKCS11BROKER_CPP);
    ASSERT_FALSE(broker.empty()) << "Pkcs11Broker source path not wired";

    // The runCrypto completion wrapper keeps a raw broker `this` for its
    // AuthFailed lease revoke, so it must value-capture the co-owned shutdown
    // token and re-check it immediately before that deref: the worker's own
    // pre-completion skip cannot catch a cancellation that lands while the
    // wrapper is already in flight.
    EXPECT_NE(broker.find("shutdown = m_deps.shutdown"), std::string::npos)
        << "the runCrypto completion wrapper must value-capture a shutdown-token copy";
    const auto recheck = broker.find("if (shutdown.isCancelled())");
    const auto revoke = broker.find("m_deps.lease->revoke(key)");
    EXPECT_NE(recheck, std::string::npos)
        << "the completion wrapper must re-check the shutdown token before the lease revoke";
    ASSERT_NE(revoke, std::string::npos) << "the AuthFailed lease revoke must exist";
    EXPECT_LT(recheck, revoke) << "the re-check must sit BEFORE the broker deref (the lease revoke)";

    // The aggregate wires the broker's token from the same shutdown state every
    // worker closure checks.
    const std::string core = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(core.empty()) << "AgentCore source path not wired";
    EXPECT_NE(core.find(".shutdown = m_cryptoCtx->shutdown"), std::string::npos)
        << "AgentCore must wire Deps::shutdown from the crypto-worker context token";
}
