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
//
// Matching is STRUCTURAL, not free-text: the source is comment-stripped (string
// literals honoured) and whitespace-collapsed, then each closure's capture list is
// extracted between its introducer '[' and the matching ']' — located either by a
// unique code anchor directly preceding the lambda or by the worker-closure
// parameter list. Comments can therefore neither satisfy nor break an assertion,
// and line re-wrapping is immaterial. The captures themselves ARE the ownership
// contract, so renaming a CAPTURED variable legitimately fails this guard, while
// renames of unrelated identifiers and comment churn do not.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <fstream>
#include <gtest/gtest.h>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

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

// Replaces //-line and /**/-block comments with a single space, honouring string
// and character literals (a comment marker inside a literal is code). Known
// gaps: raw string literals are not handled, and a digit separator (e.g. 1'000)
// is misread as opening a character literal. The guarded sources contain
// neither; if one slips in, the mangled code text makes an anchor stop
// matching, so the guard fails LOUDLY rather than false-passing.
std::string stripComments(const std::string& src)
{
    enum class State { Code, LineComment, BlockComment, StringLit, CharLit };
    std::string out;
    out.reserve(src.size());
    State state = State::Code;
    for (std::size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        const char next = i + 1 < src.size() ? src[i + 1] : '\0';
        switch (state) {
        case State::Code:
            if (c == '/' && next == '/') {
                state = State::LineComment;
                out += ' ';
                ++i;
            } else if (c == '/' && next == '*') {
                state = State::BlockComment;
                out += ' ';
                ++i;
            } else {
                if (c == '"') {
                    state = State::StringLit;
                } else if (c == '\'') {
                    state = State::CharLit;
                }
                out += c;
            }
            break;
        case State::LineComment:
            if (c == '\n') {
                state = State::Code;
                out += c;
            }
            break;
        case State::BlockComment:
            if (c == '*' && next == '/') {
                state = State::Code;
                ++i;
            }
            break;
        case State::StringLit:
        case State::CharLit:
            out += c;
            if (c == '\\' && next != '\0') {
                out += next;
                ++i;
            } else if ((state == State::StringLit && c == '"') || (state == State::CharLit && c == '\'')) {
                state = State::Code;
            }
            break;
        }
    }
    return out;
}

// Collapses every whitespace run to a single space so multi-line expressions
// match single-line needles regardless of formatting / re-wrapping.
std::string collapseWhitespace(const std::string& src)
{
    std::string out;
    out.reserve(src.size());
    bool pendingSpace = false;
    for (const char c : src) {
        if (std::isspace(static_cast<unsigned char>(c)) != 0) {
            pendingSpace = true;
            continue;
        }
        if (pendingSpace && !out.empty()) {
            out += ' ';
        }
        pendingSpace = false;
        out += c;
    }
    return out;
}

// The comment-stripped, whitespace-collapsed code text every matcher runs on.
std::string codeText(const std::string& src)
{
    return collapseWhitespace(stripComments(src));
}

// Splits a capture-list body at top-level commas (nested (), [], {} respected),
// trimming surrounding spaces from each capture.
std::vector<std::string> splitCaptures(const std::string& list)
{
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    const auto flush = [&out, &cur] {
        const auto b = cur.find_first_not_of(' ');
        if (b != std::string::npos) {
            const auto e = cur.find_last_not_of(' ');
            out.push_back(cur.substr(b, e - b + 1));
        }
        cur.clear();
    };
    for (const char c : list) {
        if (c == '(' || c == '[' || c == '{') {
            ++depth;
        } else if (c == ')' || c == ']' || c == '}') {
            --depth;
        }
        if (c == ',' && depth == 0) {
            flush();
        } else {
            cur += c;
        }
    }
    flush();
    return out;
}

// Captures of the lambda introduced by the first '[' after @p anchor. The anchor
// must occur exactly once in @p code — ambiguity yields nullopt so the guard
// fails loudly instead of silently matching the wrong site. A stray earlier '['
// between the anchor and the intended lambda is caught by the content assertions
// downstream.
std::optional<std::vector<std::string>> capturesAfter(const std::string& code, const std::string& anchor)
{
    if (countOf(code, anchor) != 1) {
        return std::nullopt;
    }
    const auto open = code.find('[', code.find(anchor) + anchor.size());
    if (open == std::string::npos) {
        return std::nullopt;
    }
    int depth = 0;
    for (std::size_t i = open; i < code.size(); ++i) {
        if (code[i] == '[') {
            ++depth;
        } else if (code[i] == ']' && --depth == 0) {
            return splitCaptures(code.substr(open + 1, i - open - 1));
        }
    }
    return std::nullopt;
}

// Capture lists of every lambda whose parameter list is exactly the worker-closure
// signature `(Operations::CardSessionHolder& holder)`, in source order.
std::vector<std::vector<std::string>> holderWorkerCaptures(const std::string& code)
{
    const std::string params = "](Operations::CardSessionHolder& holder)";
    std::vector<std::vector<std::string>> out;
    for (std::size_t pos = code.find(params); pos != std::string::npos; pos = code.find(params, pos + 1)) {
        int depth = 0;
        for (std::size_t i = pos + 1; i-- > 0;) { // back-scan from the ']' at pos to its matching '['
            if (code[i] == ']') {
                ++depth;
            } else if (code[i] == '[' && --depth == 0) {
                out.push_back(splitCaptures(code.substr(i + 1, pos - i - 1)));
                break;
            }
        }
    }
    return out;
}

bool hasCapture(const std::vector<std::string>& captures, const std::string& capture)
{
    return std::find(captures.begin(), captures.end(), capture) != captures.end();
}

bool hasLambda(const std::vector<std::vector<std::string>>& lambdas, const std::vector<std::string>& captures)
{
    return std::find(lambdas.begin(), lambdas.end(), captures) != lambdas.end();
}

std::string fmtCaptures(const std::vector<std::string>& captures)
{
    std::string out = "[";
    for (std::size_t i = 0; i < captures.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += captures[i];
    }
    return out + "]";
}
} // namespace

// --- matcher self-tests -----------------------------------------------------
// Prove the two failure modes the free-text matcher had are closed: a removed
// capture is flagged even when a stale comment still carries the old literal,
// and a pattern living only in comments (or comment churn around the real
// closure) can neither satisfy nor break the matcher. Fixtures are embedded
// strings; the real sources are never copied or edited.

namespace {
// The login-worker shape with the `ctx` capture REMOVED, while a stale comment
// still carries the old full literal — the exact false-pass shape the free-text
// matcher had (the comment text satisfies the substring find).
constexpr const char* kFixtureCaptureRemoved = R"(
    // was: [done, ctx](Operations::CardSessionHolder& holder)
    auto ctx = m_cryptoCtx;
    const bool queued = m_opManager.enqueueOnReaderWorker(
        rc->readerId, rc->readerName, [done](Operations::CardSessionHolder& holder) {
            auto acquired = holder.acquire();
            done(acquired ? LoginOutcome::Ok : LoginOutcome::CardError);
        });
)";

// The pinState shape where the co-owned-share text appears ONLY in comments: the
// real code still captures the broker `this` (the pre-fix bug), decorated with
// comment churn around and inside the callback.
constexpr const char* kFixtureShareOnlyInComments = R"(
    // Each callback CO-OWNS the lease share:
    //   .isVerified = [lease = m_deps.lease, key]
    const LeasePinState pinState{
        .isVerified = /* co-owned */ [this, /* per-call */ key]() { return isPinVerified(key); },
    };
)";

// A CORRECT closure surrounded by comment churn (including a stale bracketed
// literal and inline comments) and with unrelated identifiers renamed vs the
// shipped code (m_scheduler, readerRef).
constexpr const char* kFixtureBenignChurn = R"(
    // Reworded rationale churn; historically this read:
    //   [done](Operations::CardSessionHolder& holder)
    // and casually mentions [this] plus unrelated brackets.
    auto ctx = m_cryptoCtx; /* keep-alive share */
    const bool ok = m_scheduler.enqueueOnWorker(
        readerRef.id, readerRef.name, /* hop */ [done, ctx](Operations::CardSessionHolder& holder) {
            if (ctx->shutdown.isCancelled()) {
                return; // teardown skip
            }
            done(holder.acquire());
        });
)";
} // namespace

TEST(RawCryptoCaptureGuardSelfTest, FlagsARemovedCaptureDespiteAStaleCommentLiteral)
{
    const std::string fixture = kFixtureCaptureRemoved;
    // The free-text needle the guard used to rely on IS present — but only inside
    // the stale comment, so a substring find would false-pass the removed capture.
    ASSERT_NE(fixture.find("[done, ctx](Operations::CardSessionHolder& holder)"), std::string::npos);

    const auto lambdas = holderWorkerCaptures(codeText(fixture));
    ASSERT_EQ(lambdas.size(), 1u) << "comment text must not parse as a worker closure";
    EXPECT_FALSE(hasCapture(lambdas.front(), "ctx"))
        << "the matcher must report the removed ctx capture, so the guard fails; got " << fmtCaptures(lambdas.front());
    EXPECT_EQ(lambdas.front(), (std::vector<std::string>{"done"}));
}

TEST(RawCryptoCaptureGuardSelfTest, IsNotFooledByThePatternLivingOnlyInAComment)
{
    const std::string fixture = kFixtureShareOnlyInComments;
    // The old free-text pattern IS in the source — inside a comment only, so a
    // substring find would false-pass the broker-`this` capture underneath it.
    ASSERT_NE(fixture.find(".isVerified = [lease = m_deps.lease, key]"), std::string::npos);

    const auto captures = capturesAfter(codeText(fixture), ".isVerified =");
    ASSERT_TRUE(captures.has_value()) << "comment churn must not hide (or duplicate) the real callback anchor";
    EXPECT_EQ(*captures, (std::vector<std::string>{"this", "key"}))
        << "the matcher must report the REAL captures (the broker `this`), not the comment's; got "
        << fmtCaptures(*captures);
    EXPECT_FALSE(hasCapture(*captures, "lease = m_deps.lease"));
}

TEST(RawCryptoCaptureGuardSelfTest, PassesOnBenignCommentChurnAndUnrelatedRenames)
{
    // Only the captures are the contract: comment churn next to (and inside) the
    // closure and renames of unrelated identifiers must keep the guard green.
    // Renaming a CAPTURED variable, by contrast, legitimately fails the guard.
    const auto lambdas = holderWorkerCaptures(codeText(kFixtureBenignChurn));
    ASSERT_EQ(lambdas.size(), 1u) << "comment churn must neither hide the real closure nor mint phantom ones";
    EXPECT_EQ(lambdas.front(), (std::vector<std::string>{"done", "ctx"}));
}

// --- production guards --------------------------------------------------------

TEST(RawCryptoCaptureGuard, RawWorkerClosureCoOwnsTheWholeContext)
{
    const std::string raw = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(raw.empty()) << "AgentCore source path not wired";
    const std::string code = codeText(raw);

    // The single context share is taken before the enqueue and value-captured by
    // the closure (instead of the four separate per-member shares).
    EXPECT_NE(code.find("auto ctx = m_cryptoCtx;"), std::string::npos)
        << "the worker closures must value-capture the single crypto-worker context";

    // The raw flow must run against the context's co-owned members, never the raw
    // aggregate members.
    EXPECT_NE(code.find("*ctx->prompter"), std::string::npos)
        << "the raw flow must run against the co-owned prompter (*ctx->prompter)";
    EXPECT_NE(code.find("*ctx->serializer"), std::string::npos)
        << "the raw flow must run against the co-owned prompt gate (*ctx->serializer)";
    EXPECT_NE(code.find("*ctx->credentials"), std::string::npos)
        << "the raw flow must run against the co-owned credential cache (*ctx->credentials)";
    EXPECT_NE(code.find("ctx->shutdown"), std::string::npos)
        << "the raw flow must be wired with the context's shutdown-cancel token (ctx->shutdown)";

    // The pre-fix per-member captures must be gone. Checked against the
    // comment-stripped code, so a comment recounting the history cannot trip them.
    EXPECT_EQ(code.find("auto prompter = m_prompter"), std::string::npos)
        << "the pre-fix separate prompter share must be gone (folded into the context)";
    EXPECT_EQ(code.find("auto serializer = m_serializer"), std::string::npos)
        << "the pre-fix separate serializer share must be gone (folded into the context)";
    EXPECT_EQ(code.find("auto credentials = m_credentials"), std::string::npos)
        << "the pre-fix separate credential-cache share must be gone (folded into the context)";
    EXPECT_EQ(code.find("&m_credentials"), std::string::npos)
        << "the worker closure must co-own the context, not take a raw &m_credentials";
}

TEST(RawCryptoCaptureGuard, EveryWorkerClosureCapturesContextAndSkipsOnShutdown)
{
    const std::string raw = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(raw.empty()) << "AgentCore source path not wired";
    const std::string code = codeText(raw);

    // Three worker closures can outlive the aggregate: the raw sign/decrypt path,
    // the cert-DER path (also serving the PublicKey caller, which routes through
    // exportCertDerOnWorker), and the login path. Each takes its own context share.
    EXPECT_GE(countOf(code, "auto ctx = m_cryptoCtx;"), 3u)
        << "raw, cert-DER, and login worker closures must each capture the context";

    // Each closure must add the uniform shutdown skip before invoking its
    // completion, so an abandoned worker never drives a torn-down broker / reply.
    EXPECT_GE(countOf(code, "ctx->shutdown.isCancelled()"), 3u)
        << "raw, cert-DER, and login worker closures must each skip completion on shutdown-cancel";

    // Structural rule: EVERY worker closure — unmistakable by its parameter list —
    // must value-capture the context share.
    const auto lambdas = holderWorkerCaptures(code);
    ASSERT_GE(lambdas.size(), 3u) << "the raw, cert-DER, and login worker closures must all exist";
    for (const auto& captures : lambdas) {
        EXPECT_TRUE(hasCapture(captures, "ctx"))
            << "every worker closure must value-capture the context share; got " << fmtCaptures(captures);
    }
    // The login worker closure must capture the context (not just `done`).
    EXPECT_TRUE(hasLambda(lambdas, {"done", "ctx"}))
        << "the login worker closure must value-capture exactly [done, ctx]";
    // The cert-DER worker closure must capture the context (not just certId + done).
    EXPECT_TRUE(hasLambda(lambdas, {"certId", "done = std::move(done)", "ctx"}))
        << "the cert-DER worker closure must value-capture exactly [certId, done = std::move(done), ctx]";
}

TEST(RawCryptoCaptureGuard, CryptoContextCoOwnsTheSigningEngineAndConfig)
{
    const std::string raw = slurp(LIBREAGENT_AGENTCORE_CPP);
    ASSERT_FALSE(raw.empty()) << "AgentCore source path not wired";
    const std::string code = codeText(raw);

    // The config + signing-engine provider are shared_ptr the AgentCore ctor folds
    // into the single crypto-worker context, so an abandoned qualified-sign worker
    // co-owns both through its captured context share (its seam's post-unblock
    // snapshot() + recordLastTsaUrlUsed touch them).
    EXPECT_NE(code.find(".config = m_config"), std::string::npos)
        << "the crypto context must co-own the config share (.config = m_config)";
    EXPECT_NE(code.find(".signingEngine = m_signingEngine"), std::string::npos)
        << "the crypto context must co-own the signing-engine share (.signingEngine = m_signingEngine)";
    // The provider is built from the co-owned config share, so its own ConfigStore&
    // is backed by the same object the context keeps alive.
    EXPECT_NE(code.find("std::make_shared<Operations::SigningEngineProvider>(*m_config)"), std::string::npos)
        << "the signing-engine provider must be built from the co-owned config share";
    // The pre-fix value members must be gone (they left the engine/config freed with
    // the aggregate while a zombie sign worker was still parked).
    EXPECT_EQ(code.find("m_signingEngine(m_config)"), std::string::npos)
        << "the pre-fix value-member signing engine must be gone (folded into the context)";
}

TEST(RawCryptoCaptureGuard, BrokerPinStateCoOwnsTheLeaseShare)
{
    const std::string raw = slurp(LIBREAGENT_PKCS11BROKER_CPP);
    ASSERT_FALSE(raw.empty()) << "Pkcs11Broker source path not wired";
    const std::string code = codeText(raw);

    // The lease-scoped PIN-state callbacks — value-captured by the raw-crypto worker
    // via the pinState — must co-own the lease SHARE (so an abandoned worker touches
    // the lease through its own share), never capture the broker `this` (which the
    // zombie would deref after the broker is freed). Exact capture-list equality:
    // it pins the co-owned share AND makes the pre-fix `this` capture impossible.
    const std::vector<std::string> leaseShare{"lease = m_deps.lease", "key"};
    for (const char* anchor : {".isVerified =", ".markVerified =", ".clearVerified ="}) {
        const auto captures = capturesAfter(code, anchor);
        ASSERT_TRUE(captures.has_value()) << anchor << " callback not found exactly once in the broker";
        EXPECT_EQ(*captures, leaseShare) << anchor
                                         << " must co-own the lease share, not capture the broker `this`; got "
                                         << fmtCaptures(*captures);
    }
}

TEST(RawCryptoCaptureGuard, LoginContinuationCoOwnsTheLeaseShareNotTheBroker)
{
    const std::string raw = slurp(LIBREAGENT_PKCS11BROKER_CPP);
    ASSERT_FALSE(raw.empty()) << "Pkcs11Broker source path not wired";
    const std::string code = codeText(raw);

    // The login continuation runs on the (abandonable) worker thread and grants the
    // lease; it must co-own the lease SHARE + clock seam, never the broker `this`.
    const auto captures = capturesAfter(code, "m_deps.login(");
    ASSERT_TRUE(captures.has_value()) << "the login continuation lambda not found exactly once in the broker";
    EXPECT_TRUE(hasCapture(*captures, "lease = m_deps.lease"))
        << "the login continuation must co-own the lease share; got " << fmtCaptures(*captures);
    EXPECT_TRUE(hasCapture(*captures, "now = m_deps.now"))
        << "the login continuation must capture the clock seam by value; got " << fmtCaptures(*captures);
    EXPECT_FALSE(hasCapture(*captures, "this"))
        << "the pre-fix login continuation captured the broker `this`; that must be gone";
}

TEST(RawCryptoCaptureGuard, CompletionWrapperRechecksShutdownBeforeBrokerDeref)
{
    const std::string rawBroker = slurp(LIBREAGENT_PKCS11BROKER_CPP);
    ASSERT_FALSE(rawBroker.empty()) << "Pkcs11Broker source path not wired";
    const std::string broker = codeText(rawBroker);

    // The runCrypto completion wrapper keeps a raw broker `this` for its AuthFailed
    // lease revoke, so it must value-capture the co-owned shutdown token and re-check
    // it immediately before that deref: the worker's own pre-completion skip cannot
    // catch a cancellation that lands while the wrapper is already in flight.
    const auto captures = capturesAfter(broker, "seam(");
    ASSERT_TRUE(captures.has_value()) << "the runCrypto completion wrapper (the seam continuation) not found";
    EXPECT_TRUE(hasCapture(*captures, "shutdown = m_deps.shutdown"))
        << "the runCrypto completion wrapper must value-capture a shutdown-token copy; got " << fmtCaptures(*captures);
    EXPECT_TRUE(hasCapture(*captures, "this"))
        << "the ordering guard below anchors on the wrapper's raw broker `this` (its lease revoke); revisit this "
           "test if the wrapper no longer keeps one";

    // Ordering INSIDE the wrapper (comment-stripped positions, scoped to after the
    // wrapper's anchor): the token re-check must sit BEFORE the broker deref.
    const auto wrapperPos = broker.find("seam(");
    const auto recheck = broker.find("if (shutdown.isCancelled())", wrapperPos);
    const auto revoke = broker.find("m_deps.lease->revoke(key)", wrapperPos);
    EXPECT_NE(recheck, std::string::npos)
        << "the completion wrapper must re-check the shutdown token before the lease revoke";
    ASSERT_NE(revoke, std::string::npos) << "the AuthFailed lease revoke must exist";
    EXPECT_LT(recheck, revoke) << "the re-check must sit BEFORE the broker deref (the lease revoke)";

    // The aggregate wires the broker's token from the same shutdown state every
    // worker closure checks.
    const std::string core = codeText(slurp(LIBREAGENT_AGENTCORE_CPP));
    ASSERT_FALSE(core.empty()) << "AgentCore source path not wired";
    EXPECT_NE(core.find(".shutdown = m_cryptoCtx->shutdown"), std::string::npos)
        << "AgentCore must wire Deps::shutdown from the crypto-worker context token";
}
