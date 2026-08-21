// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentOperation over a real DBusTransport + FakeAgent: happy path, the
// Finished-before-Result race recovered via GetResult, the error path, and
// Cancel(). Adapted from the lifted KDE suite of the same name to the
// scrubbed public API: the five per-kind `*ResultReady` signals were dropped
// (results are settled before `finished()` by construction — poll the typed
// getter after it fires instead of spying on a signal); `finished()` itself
// carries no arguments (poll status()/errorCode()/messageFallback()); the
// typed getters were renamed/reshaped (certId->id, subjectCn->subject, a
// `PhotoMap` became `std::vector<PhotoItem>` via move-once `takePhotos()`,
// the signed artifact is a move-once `takeSignedArtifact()` FdHandle); there
// is no `ErrorText` module in this library (label/message tables stay in the
// GUI host) — the error-path case asserts the agent's own `messageFallback()`
// directly instead of resolving it through a presentation-layer lookup.

#include <LibreSCRS/AgentClient/AgentCapabilities.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentOperation.h>
#include <LibreSCRS/AgentClient/CredentialTypes.h>

#include "fakes/ClientOnHarness.h"
#include "fakes/TestBus.h"

#include <QSignalSpy>
#include <algorithm>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

namespace {
// Read the full contents of a sealed-artifact fd via mmap (the recipient
// contract: mmap-read then close).
QByteArray readArtifact(int fd)
{
    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
        return {};
    }
    void* p = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        return {};
    }
    QByteArray out(static_cast<const char*>(p), static_cast<int>(st.st_size));
    ::munmap(p, static_cast<size_t>(st.st_size));
    return out;
}
} // namespace

using namespace LibreSCRS::AgentClient;
using namespace LibreSCRS::AgentClient::Fakes;

namespace {
AgentOperation* startSign(AgentCard& card)
{
    int fd = ::open("/dev/null", O_RDONLY);
    EXPECT_GE(fd, 0);
    return card.sign(QStringLiteral("certid"), FdHandle{fd}, SignOptions{});
}
} // namespace

TEST(AgentOperation, HappyPathResultThenFinishedOk)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 20; // result + finished arrive after we subscribe
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = startSign(*card);
    ASSERT_NE(op, nullptr);

    QSignalSpy finishedSpy(op, &AgentOperation::finished);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    EXPECT_GE(finishedSpy.count(), 1);
    EXPECT_TRUE(op->takeSignedArtifact().valid());
}

TEST(AgentOperation, LateSubscribeRaceRecoversViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.raceResultBeforeReturn = true; // op fires Result + Finished before Sign() returns the path
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // By the time sign() returns and AgentOperation subscribes, the fake has
    // ALREADY emitted Result + Finished. The terminal-triple probe in the
    // AgentOperation ctor must recover the outcome AND pull the artifact
    // through GetResult().
    AgentOperation* op = startSign(*card);
    ASSERT_NE(op, nullptr);

    EXPECT_TRUE(op->isFinished()); // recovered synchronously in the ctor
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    FdHandle artifact = op->takeSignedArtifact();
    ASSERT_TRUE(artifact.valid()) << "GetResult recovery did not surface the artifact fd";

    // byte-correctness — the recovered fd must carry the scripted artifact,
    // and the recovered meta must carry the resolved fields.
    EXPECT_EQ(readArtifact(artifact.get()), QByteArrayLiteral("FAKE-SIGNED-ARTIFACT"));
    EXPECT_EQ(op->signMeta().value(QStringLiteral("format")).toString(), QStringLiteral("pades"));
    EXPECT_EQ(op->signMeta().value(QStringLiteral("level")).toString(), QStringLiteral("b-b"));
}

TEST(AgentOperation, ErrorPathSurfacesErrorCode)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 10;
    cfg.finalStatus = 2;     // Error
    cfg.finalErrorCode = 17; // RateLimited
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = startSign(*card);
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::RateLimited);
    EXPECT_FALSE(op->takeSignedArtifact().valid());
    // The agent's own fallback text is exactly what a consumer would render
    // (no ErrorText presentation lookup in this library — see file header).
    EXPECT_EQ(op->messageFallback(), QStringLiteral("agent fallback"));
}

// a non-Sign op (Identity) that finishes Ok but whose typed Result was
// never delivered (lost/late signal) must fail LOUDLY — Identity has no
// GetResult recovery payload here, so a silent finished(Ok) would hand the
// caller an empty field list indistinguishable from a genuinely empty read.
// We surface a CommunicationError instead, and the identity result stays
// empty.
TEST(AgentOperation, NonSignLostResultFinishesLoudlyNotSilentlyEmpty)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 10;
    cfg.suppressResult = true; // finish Ok WITHOUT emitting the Identity Result
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error) << "lost Result must surface as a failure, not a silent Ok";
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError);
    EXPECT_TRUE(op->identityResult().isEmpty());
}

// A variant via the late-subscribe terminal-triple path: the Identity op
// finishes Ok before the client subscribes (no Result on the wire, no GetResult
// on Identity), so the ctor recovery must ALSO fail loudly.
TEST(AgentOperation, NonSignLateSubscribeLostResultIsLoud)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.raceResultBeforeReturn = true; // finish before ReadIdentity() returns the path
    cfg.suppressResult = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    EXPECT_TRUE(op->isFinished()); // recovered synchronously in the ctor
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError);
    EXPECT_TRUE(op->identityResult().isEmpty());
}

// A Sign op that finishes Ok but whose Result is lost AND whose GetResult yields
// nothing (NoResult / grace window elapsed) must not claim Ok with a null fd:
// the signed artifact stays invalid and the outcome is reported as a failure,
// not a crash.
TEST(AgentOperation, SignLostResultAndGetResultNoResultIsLoudNotCrash)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.raceResultBeforeReturn = true; // finish before Sign() returns the path
    cfg.suppressResult = true;         // no Result + no kept artifact -> GetResult returns NoResult
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = startSign(*card);
    ASSERT_NE(op, nullptr);

    EXPECT_TRUE(op->isFinished());
    EXPECT_FALSE(op->takeSignedArtifact().valid()) << "GetResult returned NoResult; the fd must stay invalid";
    EXPECT_EQ(op->status(), OperationStatus::Error);
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError);
}

// A GetPhoto op delivers the Photo1 `a{sh}` sealed-memfd map. The FakeAgent
// scripts one entry ("personal:photo") holding known bytes; the recovered fd
// (via the move-once takePhotos()) must read back exactly those bytes.
TEST(AgentOperation, GetPhotoDeliversSealedMemfdMap)
{
    const QByteArray kPhotoBytes = QByteArrayLiteral("\x89PNG\r\n\x1a\n-fake-image-bytes");

    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 20; // result + finished arrive after we subscribe
    cfg.photoBytes = kPhotoBytes;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);

    std::vector<PhotoItem> photos = op->takePhotos();
    ASSERT_EQ(photos.size(), 1u);
    EXPECT_EQ(photos[0].key, QStringLiteral("personal:photo"));
    ASSERT_TRUE(photos[0].fd.valid());
    EXPECT_EQ(readArtifact(photos[0].fd.get()), kPhotoBytes);
    EXPECT_TRUE(op->takePhotos().empty()) << "move-out semantics: gone after the first take";
}

// --- Late-subscriber GetResult recovery for the inline typed results --------
//
// Identity1/Certificates1/Photo1 have a GetResult pull mirroring Sign1's: when
// the one-shot typed Result is lost/raced but the op finished Ok, the client
// re-serves the retained payload via GetResult instead of a loud
// CommunicationError. The FakeAgent's lostSignalRecoverable mode models this
// deterministically — the op finishes Ok, NEVER signals the Result, and its
// GetResult serves the full payload.

// Terminal-Ok-without-Result path: the client subscribes FIRST (operationDelayMs),
// the op finishes Ok with no Result signal, and finalizeTerminal recovers the
// identity field list via Identity1.GetResult.
TEST(AgentOperation, IdentityLostSignalRecoversViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 20;        // client subscribes before the op fires
    cfg.lostSignalRecoverable = true; // finish Ok, no Result signal, GetResult serves
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok) << "the lost Result is recovered, so the read is Ok, not loud-failed";
    const QList<FieldGroup> groups = op->identityResult();
    const auto personal = std::find_if(groups.cbegin(), groups.cend(),
                                       [](const FieldGroup& g) { return g.key == QStringLiteral("personal"); });
    ASSERT_NE(personal, groups.cend());
    const auto givenName = std::find_if(personal->fields.cbegin(), personal->fields.cend(),
                                        [](const Field& f) { return f.key == QStringLiteral("given_name"); });
    ASSERT_NE(givenName, personal->fields.cend());
    EXPECT_EQ(givenName->value, QStringLiteral("Ana"));
}

// Ctor recovery path: the op finishes Ok before readIdentity() returns the path
// (raceResultBeforeReturn) AND never signals the Result (lostSignalRecoverable),
// so the AgentOperation ctor's terminal-triple probe recovers the payload via
// Identity1.GetResult synchronously.
TEST(AgentOperation, IdentityLostSignalCtorPathRecoversViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.raceResultBeforeReturn = true; // finished before the path returns
    cfg.lostSignalRecoverable = true;  // and never signalled the Result
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readIdentity();
    ASSERT_NE(op, nullptr);

    EXPECT_TRUE(op->isFinished()); // recovered synchronously in the ctor
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    const QList<FieldGroup> groups = op->identityResult();
    EXPECT_TRUE(std::any_of(groups.cbegin(), groups.cend(), [](const FieldGroup& g) {
        return g.key == QStringLiteral("personal");
    })) << "the ctor recovery must pull the identity map via Identity1.GetResult";
}

TEST(AgentOperation, CertificatesLostSignalRecoversViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.certScript = {{QStringLiteral("cert-A"), true, QStringLiteral("Ana Signer")}};
    cfg.operationDelayMs = 20;
    cfg.lostSignalRecoverable = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->readCertificates();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    const QList<CertificateInfo> certs = op->certificatesResult();
    ASSERT_EQ(certs.size(), 1);
    EXPECT_EQ(certs.at(0).id, QStringLiteral("cert-A"));
    EXPECT_EQ(certs.at(0).subject, QStringLiteral("Ana Signer"));
}

// Photo recovery re-serves a REAL sealed memfd (re-sealed from the retained
// bytes) — the recovered fd must read back exactly the scripted image bytes.
TEST(AgentOperation, PhotoLostSignalRecoversViaGetResultWithSealedMemfd)
{
    const QByteArray kPhotoBytes = QByteArrayLiteral("\x89PNG\r\n\x1a\n-recovered-image-bytes");

    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 20;
    cfg.photoBytes = kPhotoBytes;
    cfg.lostSignalRecoverable = true;
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    std::vector<PhotoItem> photos = op->takePhotos();
    ASSERT_EQ(photos.size(), 1u);
    EXPECT_EQ(photos[0].key, QStringLiteral("personal:photo"));
    ASSERT_TRUE(photos[0].fd.valid());
    EXPECT_EQ(readArtifact(photos[0].fd.get()), kPhotoBytes) << "the recovered sealed memfd carries the photo bytes";
}

// Negative: the typed Result is lost AND GetResult is unavailable (NoResult —
// the same error-reply shape a version-skewed agent WITHOUT the method returns
// via UnknownMethod, handled identically by the client). The op must NOT claim
// Ok with an empty payload; it surfaces a loud CommunicationError (the final
// fallback). Covers a non-Identity inline interface (Photo).
TEST(AgentOperation, PhotoLostResultAndGetResultUnavailableIsLoud)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::IdentityData;
    cfg.operationDelayMs = 10;
    cfg.suppressResult = true; // no Result signal AND nothing retained -> GetResult NoResult
    cfg.photoBytes = QByteArrayLiteral("unrecoverable");
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->getPhoto();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error) << "a lost Result with no GetResult recovery must fail loudly";
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError);
    EXPECT_TRUE(op->takePhotos().empty());
}

// --- Operation.Credentials1 typed result (the divergent interface) ----------
//
// Unlike Sign/Identity/Certificates/Photo (whose Result fires only on Ok),
// the credentials Result fires for EVERY completed attempt — including the
// "soft-fail" outcomes (invalidPin/blocked) that finish Error — and carries a
// two-out-arg payload (a{sv} result, aa{sv} records). These cases pin the four
// divergences: (1) the 2-arg slot demarshals (a{sv}, aa{sv}); (2) the Result is
// delivered on an Error terminal; (3) finalizeTerminal recovers regardless of
// Ok/Error and NEVER rewrites a real non-Ok terminal into a comms error just
// because status != Ok — the loud CommunicationError fires ONLY when there is
// genuinely no recoverable payload; (4) an empty records list is a legitimate
// mutation result, not a "no result".

// The one listed record the credentials mutation cases target: the fake
// resolves ManagePin ids against the CURRENT listing snapshot, so the mutated
// id must have been listed first. (The mutation's own Result carries no
// records — records ride ListCredentials results alone.)
QVariantMap listedUserPinRecord()
{
    return QVariantMap{{QStringLiteral("id"), QStringLiteral("user:0x86")},
                       {QStringLiteral("kind"), QStringLiteral("user")},
                       {QStringLiteral("state"), QStringLiteral("operational")}};
}

// Issue a ListCredentials and wait for it to COMPLETE. Completion — not the
// method returning an operation path — is what makes ids resolvable: the agent
// writes its snapshot at the end of the read (CredentialListFlow), so a client
// that lists and mutates in the same turn is refused as if it had never listed.
[[nodiscard]] bool listAndAwait(AgentCard* card)
{
    AgentOperation* op = card->listCredentials();
    return op != nullptr && waitFor([op]() { return op->isFinished(); });
}

// Divergence (2)+(3): a ManagePin attempt whose Result is {invalidPin, retries_left=2}
// but whose Finished is Error(CredentialWrong). The per-attempt Result must be
// delivered, and the REAL terminal (Error/CredentialWrong) preserved — NOT
// rewritten to CommunicationError.
TEST(AgentOperation, CredentialsResultDeliveredOnErrorTerminal)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.operationDelayMs = 20; // client subscribes before the op fires the live Result
    cfg.credResult = QVariantMap{{QStringLiteral("outcome"), QStringLiteral("invalidPin")},
                                 {QStringLiteral("retries_left"), 2},
                                 {QStringLiteral("blocked"), false}};
    cfg.credRecords = {listedUserPinRecord()}; // the listing must carry the mutated id
    cfg.finalStatus = 2;                       // Error (a soft-fail: wrong PIN)
    cfg.finalErrorCode = 2;                    // CredentialWrong
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // Contract: list-before-mutate, and the listing must have FINISHED.
    ASSERT_TRUE(listAndAwait(card));
    AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error) << "the real terminal is preserved, not rewritten to a comms error";
    EXPECT_EQ(op->errorCode(), ErrorCode::CredentialWrong);
    EXPECT_EQ(op->pinResult().outcome, CredentialOutcome::InvalidPin);
    ASSERT_TRUE(op->pinResult().retriesLeft.has_value());
    EXPECT_EQ(*op->pinResult().retriesLeft, 2);
    EXPECT_FALSE(op->pinResult().blocked);
    EXPECT_TRUE(op->credentialsResult().isEmpty()) << "a mutation carries no records, only the a{sv} result";
}

// Divergence (1)+(4): ListCredentials delivers the aa{sv} records; the demarshaled
// CredentialRecord carries the typed kind/state/flags.
TEST(AgentOperation, ListCredentialsResultDeliversRecords)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.operationDelayMs = 20;
    cfg.credResult = QVariantMap{{QStringLiteral("outcome"), QStringLiteral("ok")}, {QStringLiteral("blocked"), false}};
    cfg.credRecords = {QVariantMap{{QStringLiteral("id"), QStringLiteral("user:0x86")},
                                   {QStringLiteral("kind"), QStringLiteral("user")},
                                   {QStringLiteral("state"), QStringLiteral("operational")},
                                   {QStringLiteral("can_change"), true},
                                   {QStringLiteral("unblockable"), false},
                                   {QStringLiteral("activatable"), false},
                                   {QStringLiteral("key_activation_pending"), false},
                                   {QStringLiteral("key_activatable"), false},
                                   {QStringLiteral("probe_safe"), true}}};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = card->listCredentials();
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok);
    const CredentialList records = op->credentialsResult();
    ASSERT_EQ(records.size(), 1);
    const CredentialRecord& r = records.at(0);
    EXPECT_EQ(r.id, QStringLiteral("user:0x86"));
    EXPECT_EQ(r.kind, CredentialKind::User);
    EXPECT_EQ(r.state, CredentialState::Operational);
    EXPECT_TRUE(r.canChange);
    EXPECT_TRUE(r.probeSafe);
    EXPECT_FALSE(r.unblockable);
}

// Divergence (3)+(4): the live Result signal is LOST but the payload is RETAINED,
// so finalizeTerminal recovers it via Operation.Credentials1.GetResult (the
// 2-out-arg pull). An EMPTY records list is legitimate for a mutation — the
// presence of a Result reply is the signal, not a non-empty records list — so
// the op stays Ok.
TEST(AgentOperation, CredentialsLostSignalRecoversViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.operationDelayMs = 20;
    cfg.lostSignalRecoverable = true; // finish, SUPPRESS the Result signal, RETAIN for GetResult
    cfg.credResult = QVariantMap{{QStringLiteral("outcome"), QStringLiteral("ok")},
                                 {QStringLiteral("blocked"), false},
                                 {QStringLiteral("pin_activated"), true}};
    // The listing carries the mutated id; the MUTATION's own result still has
    // empty records (a legitimate mutation result — the fake, like the real
    // agent, never attaches records to a mutation Result).
    cfg.credRecords = {listedUserPinRecord()};
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // Contract: list-before-mutate, and the listing must have FINISHED.
    ASSERT_TRUE(listAndAwait(card));
    AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Ok) << "the lost Result is recovered via GetResult, so the op stays Ok";
    EXPECT_EQ(op->pinResult().outcome, CredentialOutcome::Ok);
    ASSERT_TRUE(op->pinResult().pinActivated.has_value());
    EXPECT_TRUE(*op->pinResult().pinActivated);
    EXPECT_TRUE(op->credentialsResult().isEmpty()) << "empty-records is valid; it must not be treated as no result";
}

// Ctor-recovery path: the op finishes (Error, with a soft-fail payload) before
// managePin() returns the path AND never signals the Result, so the ctor's
// terminal-triple probe recovers the payload via GetResult synchronously and
// preserves the REAL Error terminal.
TEST(AgentOperation, CredentialsLostSignalCtorPathRecoversViaGetResult)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.raceResultBeforeReturn = true; // finished before managePin() returns the path
    cfg.lostSignalRecoverable = true;  // and never signalled the Result
    cfg.credResult = QVariantMap{{QStringLiteral("outcome"), QStringLiteral("invalidPin")},
                                 {QStringLiteral("retries_left"), 1},
                                 {QStringLiteral("blocked"), false}};
    cfg.credRecords = {listedUserPinRecord()}; // the listing must carry the mutated id
    cfg.finalStatus = 2;
    cfg.finalErrorCode = 2; // CredentialWrong
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // Contract: list-before-mutate, and the listing must have FINISHED.
    ASSERT_TRUE(listAndAwait(card));
    AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(op, nullptr);

    EXPECT_TRUE(op->isFinished()); // recovered synchronously in the ctor
    EXPECT_EQ(op->status(), OperationStatus::Error) << "the real terminal survives ctor recovery";
    EXPECT_EQ(op->errorCode(), ErrorCode::CredentialWrong);
    EXPECT_EQ(op->pinResult().outcome, CredentialOutcome::InvalidPin);
    ASSERT_TRUE(op->pinResult().retriesLeft.has_value());
    EXPECT_EQ(*op->pinResult().retriesLeft, 1);
}

// Negative (divergence 3, the loud fallback): the Result is lost AND nothing is
// retained (GetResult -> NoResult, the same error-reply shape a version-skewed
// agent WITHOUT the method returns). Even on an Ok wire terminal, a credentials
// op with no recoverable payload is a genuine comms fault — surfaced loudly, not
// a silent empty success.
TEST(AgentOperation, CredentialsLostResultAndGetResultUnavailableIsLoud)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::PinManagement;
    cfg.operationDelayMs = 10;
    cfg.suppressResult = true; // no Result signal AND nothing retained -> GetResult NoResult
    cfg.credResult = QVariantMap{{QStringLiteral("outcome"), QStringLiteral("ok")}};
    cfg.credRecords = {listedUserPinRecord()}; // the listing must carry the mutated id
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    // Contract: list-before-mutate, and the listing must have FINISHED.
    ASSERT_TRUE(listAndAwait(card));
    AgentOperation* op = card->managePin(QStringLiteral("user:0x86"), PinVerb::Change);
    ASSERT_NE(op, nullptr);

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Error) << "a credentials op with no recoverable payload is a comms fault";
    EXPECT_EQ(op->errorCode(), ErrorCode::CommunicationError);
    EXPECT_EQ(op->pinResult().outcome, CredentialOutcome::Unspecified);
    EXPECT_TRUE(op->credentialsResult().isEmpty());
}

TEST(AgentOperation, CancelInvokesOperationCancel)
{
    FakeAgent::Config cfg;
    cfg.capabilities = Cap::Pki;
    cfg.operationDelayMs = 5000; // never fires on its own within the test
    Harness h(cfg);

    auto client = makeClient(h);
    AgentCard* card = client->card(h.cardPath());
    ASSERT_NE(card, nullptr);
    AgentOperation* op = startSign(*card);
    ASSERT_NE(op, nullptr);
    ASSERT_FALSE(op->isFinished());

    op->cancel();

    ASSERT_TRUE(waitFor([&]() { return op->isFinished(); }));
    EXPECT_EQ(op->status(), OperationStatus::Cancelled);
}
