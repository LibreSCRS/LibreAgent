// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// OperationLauncher is the one place a card operation is assembled and queued
// for every host. Two properties are pinned here.
//
// Completeness: every dependency of every operation is filled from the core,
// the seams or the request. Each check binds the operation's Deps with a
// structured binding of its exact arity, so adding a member to a Deps stops
// this file compiling until the new member is checked here too -- and the
// check fails until the launcher fills it. A member with a default value is
// the case a compiler cannot see on its own.
//
// Launch: the operation runs on the reader's worker with the worker's holder,
// answers through the host's channel under the id the host was given, co-owns
// what an abandoned operation's unwind touches, honours the shutdown token,
// and a full reader queue is refused as RateLimited.
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/OperationArtifact.h>
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include "fakes/FakeAuthorizer.h"
#include "fakes/FakeCredentialDepositor.h"
#include "fakes/FakeCredentialManager.h"
#include "fakes/FakePrompter.h"
#include "fakes/ScratchDir.h"

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

class NeutralResolver final : public CapabilityResolver
{};

class StubReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback = {}) override
    {
        return {};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class StubCertReader final : public CertificateReader
{
public:
    CertReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class StubTrustVerifier final : public TrustVerifier
{
public:
    TrustVerdict verify(std::span<const std::uint8_t>, std::span<const std::vector<std::uint8_t>>) override
    {
        return {};
    }
};

class StubSigner final : public Signer
{
public:
    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams&, const CandidateList&,
                     LibreSCRS::Auth::CredentialProvider, LibreSCRS::CancelToken) override
    {
        return {};
    }
};

// What the operation sent back through the host's channel. Written on the
// reader's worker, read by the test thread.
struct ChannelRecord
{
    std::mutex mutex;
    std::vector<OperationStatus> finishes;
    std::vector<std::string> finishKeys;
    int results{0};

    int finishCount()
    {
        std::lock_guard lk(mutex);
        return static_cast<int>(finishes.size());
    }
};

class RecordingChannel final : public OperationChannel
{
public:
    explicit RecordingChannel(std::shared_ptr<ChannelRecord> record) : m_record(std::move(record)) {}

    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus status, ErrorCode, std::string_view msgKey, std::string_view) noexcept override
    {
        std::lock_guard lk(m_record->mutex);
        m_record->finishes.push_back(status);
        m_record->finishKeys.emplace_back(msgKey);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        std::lock_guard lk(m_record->mutex);
        ++m_record->results;
        return true;
    }

private:
    std::shared_ptr<ChannelRecord> m_record;
};

constexpr const char* kReader = "reader-A";
const std::string kCardKey = "card-7";
const CallerToken kCaller{":1.5"};

class OperationLauncherTest : public ::testing::Test
{
protected:
    OperationLauncherTest()
    {
        core.emplace(
            resolver, authorizer, prompter, dir() / "agent.conf", dir() / "cache",
            [](const std::string&) -> std::optional<ReaderCard> { return std::nullopt; },
            [](const std::string&) -> std::optional<ObjectId> { return std::nullopt; });
        core->operationManager().setSessionFactoryForTest(
            [](const std::string& reader)
                -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
                return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(reader);
            });
        core->presenceModel().onReaderAdded(kReader);
        target = OperationTarget{
            .card = ReaderCard{.readerId = core->presenceModel().readerIdFor(kReader),
                               .readerName = kReader,
                               .cardKey = kCardKey},
            .caller = kCaller,
            .requester = "firefox",
        };
        launcher.emplace(*core, seams(), transportShare);
    }

    ~OperationLauncherTest() override
    {
        releaseWorker();
        launcher.reset();
        core.reset();
        fs::remove_all(dir());
    }

    const fs::path m_dir = LibreSCRS::Agent::Testing::makeScratchDir("libreagent-operation-launcher-");
    [[nodiscard]] const fs::path& dir() const
    {
        return m_dir;
    }

    OperationSeams seams()
    {
        return OperationSeams{
            .reader = reader,
            .certReader = certReader,
            .trustVerifier = trustVerifier,
            .signer = signer,
            .credentials = credentials,
            .depositor = depositor,
        };
    }

    OperationLauncher::ChannelFactory recordingChannel()
    {
        return [this](OperationId id, const std::shared_ptr<OperationState>& state) {
            ++channelsBuilt;
            builtIds.push_back(id);
            builtStates.push_back(state);
            return std::make_unique<RecordingChannel>(record);
        };
    }

    // Park the reader's worker inside a probe until releaseWorker(), so what is
    // launched meanwhile stays queued.
    void blockWorker()
    {
        auto started = std::make_shared<std::atomic<bool>>(false);
        ASSERT_TRUE(core->operationManager().enqueueOnReaderWorker(target.card.readerId, kReader,
                                                                   [started, gate = gate](CardSessionHolder&) {
                                                                       started->store(true);
                                                                       while (!gate->load()) {
                                                                           std::this_thread::sleep_for(1ms);
                                                                       }
                                                                   }));
        ASSERT_TRUE(waitFor([&] { return started->load(); })) << "the worker did not pick up the blocking probe";
    }

    void releaseWorker()
    {
        gate->store(true);
    }

    // Everything queued before this call has run once it returns.
    void drainWorker()
    {
        auto ran = std::make_shared<std::atomic<bool>>(false);
        // A full queue refuses the probe until the worker has made room.
        ASSERT_TRUE(waitFor([&] {
            return core->operationManager().enqueueOnReaderWorker(target.card.readerId, kReader,
                                                                  [ran](CardSessionHolder&) { ran->store(true); });
        })) << "the worker never made room";
        ASSERT_TRUE(waitFor([&] { return ran->load(); })) << "the worker did not drain";
    }

    template <class Predicate>
    static bool waitFor(Predicate done)
    {
        const auto start = std::chrono::steady_clock::now();
        while (!done()) {
            if (std::chrono::steady_clock::now() - start > 5s) {
                return false;
            }
            std::this_thread::sleep_for(2ms);
        }
        return true;
    }

    std::unique_ptr<CardSessionHolder> makeHolder()
    {
        return std::make_unique<CardSessionHolder>(
            kReader,
            [](const std::string& r)
                -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
                return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
            },
            [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; });
    }

    static SignParams someParams()
    {
        SignParams params;
        params.certId = "cert-1";
        params.inputDocument = {0x25, 0x50, 0x44, 0x46};
        params.format = "pades";
        return params;
    }

    NeutralResolver resolver;
    FakeAuthorizer authorizer;
    std::shared_ptr<FakePrompter> prompter = std::make_shared<FakePrompter>();
    std::shared_ptr<StubReader> reader = std::make_shared<StubReader>();
    std::shared_ptr<StubCertReader> certReader = std::make_shared<StubCertReader>();
    std::shared_ptr<StubTrustVerifier> trustVerifier = std::make_shared<StubTrustVerifier>();
    std::shared_ptr<StubSigner> signer = std::make_shared<StubSigner>();
    std::shared_ptr<FakeCredentialManager> credentials = std::make_shared<FakeCredentialManager>();
    std::shared_ptr<FakeCredentialDepositor> depositor = std::make_shared<FakeCredentialDepositor>();
    std::shared_ptr<int> transportShare = std::make_shared<int>(0);
    // Declared before the core: the worker the core joins on teardown reads them.
    std::shared_ptr<std::atomic<bool>> gate = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<ChannelRecord> record = std::make_shared<ChannelRecord>();
    std::optional<AgentCore> core;
    std::optional<OperationLauncher> launcher;
    OperationTarget target;
    int channelsBuilt{0};
    std::vector<OperationId> builtIds;
    std::vector<std::shared_ptr<OperationState>> builtStates;
};

// --- completeness ------------------------------------------------------------

TEST_F(OperationLauncherTest, AReadIdentityGetsEveryDependency)
{
    auto holder = makeHolder();
    int cardTypes = 0;
    auto deps = launcher->depsFor(
        holder.get(), target, OperationLauncher::ReadIdentity{.onCardType = [&](const std::string&) { ++cardTypes; }});
    // A new member of ReadIdentityOperation::Deps is a compile error here.
    auto& [dHolder, dReader, dDepositor, dPrompter, dSerializer, dCredentials, dReadCache, dCardKey, dReaderName,
           dRequester, dArtifact, dOnCardType] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dReader, reader.get());
    EXPECT_EQ(&dDepositor, depositor.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredentials, &core->credentialCache());
    EXPECT_EQ(&dReadCache, &core->cardReadCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kIdentity);
    ASSERT_TRUE(dOnCardType);
    dOnCardType("rs-eid");
    EXPECT_EQ(cardTypes, 1) << "the host's card-type sink is the one the operation calls";
}

TEST_F(OperationLauncherTest, AGetPhotoGetsEveryDependency)
{
    auto holder = makeHolder();
    int cardTypes = 0;
    auto deps = launcher->depsFor(holder.get(), target,
                                  OperationLauncher::GetPhoto{.onCardType = [&](const std::string&) { ++cardTypes; }});
    auto& [dHolder, dReader, dDepositor, dPrompter, dSerializer, dCredentials, dReadCache, dCardKey, dReaderName,
           dRequester, dArtifact, dOnCardType] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dReader, reader.get());
    EXPECT_EQ(&dDepositor, depositor.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredentials, &core->credentialCache());
    EXPECT_EQ(&dReadCache, &core->cardReadCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kPhoto);
    ASSERT_TRUE(dOnCardType);
    dOnCardType("rs-eid");
    EXPECT_EQ(cardTypes, 1);
}

TEST_F(OperationLauncherTest, AReadCertificatesGetsEveryDependency)
{
    auto holder = makeHolder();
    auto deps = launcher->depsFor(holder.get(), target, OperationLauncher::ReadCertificates{});
    auto& [dHolder, dCertReader, dTrustVerifier, dPrompter, dSerializer, dCredentials, dReadCache, dCardKey,
           dReaderName, dRequester, dArtifact] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dCertReader, certReader.get());
    EXPECT_EQ(&dTrustVerifier, trustVerifier.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredentials, &core->credentialCache());
    EXPECT_EQ(&dReadCache, &core->cardReadCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kCertificates);
}

TEST_F(OperationLauncherTest, AReadTokenInfoGetsEveryDependency)
{
    auto holder = makeHolder();
    auto deps = launcher->depsFor(holder.get(), target, OperationLauncher::ReadTokenInfo{});
    auto& [dHolder, dReader, dPrompter, dSerializer, dCredentials, dCardKey, dReaderName, dRequester, dArtifact] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dReader, reader.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredentials, &core->credentialCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kTokenInfo);
}

TEST_F(OperationLauncherTest, ASignGetsEveryDependency)
{
    auto holder = makeHolder();
    auto deps = launcher->depsFor(holder.get(), target, OperationLauncher::Sign{.params = someParams()});
    auto& [dHolder, dSigner, dPrompter, dSerializer, dCredentials, dCardKey, dReaderName, dRequester, dParams] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dSigner, signer.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredentials, &core->credentialCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dParams.certId, "cert-1");
    EXPECT_EQ(dParams.inputDocument, someParams().inputDocument);
    EXPECT_EQ(dParams.format, "pades");
}

TEST_F(OperationLauncherTest, ASignBatchGetsEveryDependency)
{
    auto holder = makeHolder();
    std::vector<BatchDocumentInput> documents{{.displayName = "a.pdf", .bytes = {1}},
                                              {.displayName = "b.pdf", .bytes = {2}}};
    auto deps = launcher->depsFor(holder.get(), target,
                                  OperationLauncher::SignBatch{.params = someParams(), .documents = documents});
    auto& [dHolder, dSigner, dPrompter, dSerializer, dCredentials, dCardKey, dReaderName, dRequester, dParams,
           dDocuments] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dSigner, signer.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredentials, &core->credentialCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dParams.certId, "cert-1");
    ASSERT_EQ(dDocuments.size(), 2u);
    EXPECT_EQ(dDocuments[1].displayName, "b.pdf");
}

TEST_F(OperationLauncherTest, AListCredentialsGetsEveryDependency)
{
    auto holder = makeHolder();
    auto deps = launcher->depsFor(holder.get(), target, OperationLauncher::ListCredentials{});
    auto& [dHolder, dCredentials, dPrompter, dSerializer, dCredCache, dSnapshotCache, dCardKey, dReaderName, dRequester,
           dArtifact] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dCredentials, credentials.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredCache, &core->credentialCache());
    EXPECT_EQ(&dSnapshotCache, &core->credentialSnapshotCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kCredentials);
}

TEST_F(OperationLauncherTest, AManagePinGetsEveryDependency)
{
    auto holder = makeHolder();
    CredentialSnapshot snapshot;
    snapshot.version = 3;
    auto deps = launcher->depsFor(
        holder.get(), target,
        OperationLauncher::ManagePin{
            .request = PinManageRequest{.cardKey = kCardKey, .pinId = "pin-1", .verb = "change", .activateKey = false},
            .snapshot = snapshot,
        });
    auto& [dHolder, dCredentials, dPrompter, dSerializer, dCredCache, dSnapshotCache, dReadCache, dCardKey, dReaderName,
           dRequester, dArtifact, dRequest, dSnapshot] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dCredentials, credentials.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredCache, &core->credentialCache());
    EXPECT_EQ(&dSnapshotCache, &core->credentialSnapshotCache());
    EXPECT_EQ(&dReadCache, &core->cardReadCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kCredentials);
    EXPECT_EQ(dRequest.pinId, "pin-1");
    EXPECT_EQ(dRequest.verb, "change");
    EXPECT_EQ(dSnapshot.version, 3u);
}

TEST_F(OperationLauncherTest, AnActivateSigningKeyGetsEveryDependency)
{
    auto holder = makeHolder();
    auto deps = launcher->depsFor(holder.get(), target, OperationLauncher::ActivateSigningKey{});
    auto& [dHolder, dCredentials, dPrompter, dSerializer, dCredCache, dSnapshotCache, dReadCache, dCardKey, dReaderName,
           dRequester, dArtifact] = deps;
    EXPECT_EQ(dHolder, holder.get());
    EXPECT_EQ(&dCredentials, credentials.get());
    EXPECT_EQ(&dPrompter, prompter.get());
    EXPECT_EQ(&dSerializer, &core->promptSerializer());
    EXPECT_EQ(&dCredCache, &core->credentialCache());
    EXPECT_EQ(&dSnapshotCache, &core->credentialSnapshotCache());
    EXPECT_EQ(&dReadCache, &core->cardReadCache());
    EXPECT_EQ(dCardKey, kCardKey);
    EXPECT_EQ(dReaderName, kReader);
    EXPECT_EQ(dRequester, "firefox");
    EXPECT_EQ(dArtifact, Artifact::kCredentials);
}

// --- seams -------------------------------------------------------------------

TEST_F(OperationLauncherTest, EverySeamButTheDepositorIsRequired)
{
    const auto without = [this](auto member) {
        OperationSeams s = seams();
        s.*member = nullptr;
        return s;
    };
    EXPECT_THROW(OperationLauncher(*core, without(&OperationSeams::reader)), std::invalid_argument);
    EXPECT_THROW(OperationLauncher(*core, without(&OperationSeams::certReader)), std::invalid_argument);
    EXPECT_THROW(OperationLauncher(*core, without(&OperationSeams::trustVerifier)), std::invalid_argument);
    EXPECT_THROW(OperationLauncher(*core, without(&OperationSeams::signer)), std::invalid_argument);
    EXPECT_THROW(OperationLauncher(*core, without(&OperationSeams::credentials)), std::invalid_argument);

    const OperationLauncher noRegistry(*core, without(&OperationSeams::depositor));
    auto holder = makeHolder();
    auto deps = noRegistry.depsFor(holder.get(), target, OperationLauncher::ReadIdentity{});
    EXPECT_NE(dynamic_cast<NullCredentialDepositor*>(&deps.depositor), nullptr)
        << "without a registry a renegotiated read deposits nothing, through a well-formed seam";
}

TEST_F(OperationLauncherTest, TheProductionSeamsAreTheMiddlewareOnes)
{
    const OperationSeams production = OperationSeams::production(*core, nullptr);
    EXPECT_NE(dynamic_cast<LmCardReader*>(production.reader.get()), nullptr);
    EXPECT_NE(dynamic_cast<LmCertificateReader*>(production.certReader.get()), nullptr);
    EXPECT_NE(dynamic_cast<LmTrustVerifier*>(production.trustVerifier.get()), nullptr);
    EXPECT_NE(dynamic_cast<LmSigner*>(production.signer.get()), nullptr);
    EXPECT_NE(dynamic_cast<LmCredentialManager*>(production.credentials.get()), nullptr);
    EXPECT_EQ(production.depositor, nullptr) << "no registry, nothing to deposit into";
    EXPECT_NO_THROW(OperationLauncher(*core, production));
}

// --- launch ------------------------------------------------------------------

TEST_F(OperationLauncherTest, ALaunchedReadAnswersThroughTheHostsChannelUnderTheIdItReturned)
{
    // A cached read answers without card I/O: the operation found the card's
    // snapshot under the target's key in the core's own read cache.
    core->cardReadCache().put(kCardKey, CardReadSnapshot{.cardType = "rs-eid", .groups = {GroupSnapshot{}}});

    const auto launched = launcher->launch(target, recordingChannel(), OperationLauncher::ReadIdentity{});
    ASSERT_TRUE(launched.has_value());
    ASSERT_TRUE(waitFor([&] { return record->finishCount() == 1; })) << "the operation never finished";

    ASSERT_EQ(builtIds.size(), 1u);
    EXPECT_EQ(builtIds[0], *launched) << "the channel was built for the id the host was given";
    ASSERT_EQ(builtStates.size(), 1u);
    EXPECT_TRUE(builtStates[0]->completed.load()) << "the channel shares the operation's own state";
    std::lock_guard lk(record->mutex);
    EXPECT_EQ(record->results, 1);
    EXPECT_EQ(record->finishes[0], OperationStatus::Ok);
}

TEST_F(OperationLauncherTest, ALaunchedOperationRunsWithItsWorkersSessionHolder)
{
    // Not cached: the read goes through the holder. An operation built
    // without the worker's holder finishes with "op.internal".
    for (auto launch :
         {+[](OperationLauncher& l, const OperationTarget& t, const OperationLauncher::ChannelFactory& f) {
              return l.launch(t, f, OperationLauncher::ReadIdentity{});
          },
          +[](OperationLauncher& l, const OperationTarget& t, const OperationLauncher::ChannelFactory& f) {
              return l.launch(t, f, OperationLauncher::ListCredentials{});
          }}) {
        ASSERT_TRUE(launch(*launcher, target, recordingChannel()).has_value());
    }
    ASSERT_TRUE(waitFor([&] { return record->finishCount() == 2; })) << "the operations never finished";
    std::lock_guard lk(record->mutex);
    for (const std::string& key : record->finishKeys) {
        EXPECT_NE(key, "op.internal") << "an operation ran without the worker's session holder";
    }
}

TEST_F(OperationLauncherTest, EveryLaunchedOperationCoOwnsTheContextTheSeamsAndTheTransport)
{
    blockWorker();
    const long contextBefore = core->sharedCryptoContext().use_count();
    const long transportBefore = transportShare.use_count();

    const auto f = recordingChannel();
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ReadIdentity{}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::GetPhoto{}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ReadCertificates{}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ReadTokenInfo{}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::Sign{.params = someParams()}).has_value());
    ASSERT_TRUE(
        launcher->launch(target, f, OperationLauncher::SignBatch{.params = someParams(), .documents = {}}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ListCredentials{}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ManagePin{}).has_value());
    ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ActivateSigningKey{}).has_value());
    EXPECT_EQ(channelsBuilt, 9);

    EXPECT_EQ(core->sharedCryptoContext().use_count(), contextBefore + 9)
        << "each queued operation co-owns the crypto-worker context";
    EXPECT_EQ(transportShare.use_count(), transportBefore + 9) << "each queued operation co-owns the host's transport";

    // The launcher and the test let go of every seam; the queued operations
    // still hold them.
    const std::weak_ptr<StubReader> readerAlive = reader;
    const std::weak_ptr<StubSigner> signerAlive = signer;
    const std::weak_ptr<FakeCredentialManager> credentialsAlive = credentials;
    const std::weak_ptr<FakeCredentialDepositor> depositorAlive = depositor;
    reader.reset();
    signer.reset();
    credentials.reset();
    depositor.reset();
    launcher.reset();
    EXPECT_FALSE(readerAlive.expired());
    EXPECT_FALSE(signerAlive.expired());
    EXPECT_FALSE(credentialsAlive.expired());
    EXPECT_FALSE(depositorAlive.expired());

    releaseWorker();
    drainWorker();
}

TEST_F(OperationLauncherTest, AnOperationThatRunsAfterShutdownSkipsItsCompletion)
{
    core->cardReadCache().put(kCardKey, CardReadSnapshot{.cardType = "rs-eid", .groups = {GroupSnapshot{}}});
    blockWorker();
    ASSERT_TRUE(launcher->launch(target, recordingChannel(), OperationLauncher::ReadIdentity{}).has_value());
    core->requestCryptoShutdown();
    releaseWorker();
    drainWorker();

    std::lock_guard lk(record->mutex);
    EXPECT_EQ(record->results, 0) << "the shutdown token is bound: no result into a host being torn down";
    EXPECT_TRUE(record->finishes.empty()) << "the shutdown token is bound: no completion either";
}

TEST_F(OperationLauncherTest, AFullReaderQueueIsRefusedAsRateLimited)
{
    blockWorker();
    const auto f = recordingChannel();
    for (std::size_t i = 0; i < kMaxQueuedOpsPerReader; ++i) {
        ASSERT_TRUE(launcher->launch(target, f, OperationLauncher::ReadTokenInfo{}).has_value()) << "launch " << i;
    }
    const auto refused = launcher->launch(target, f, OperationLauncher::ReadTokenInfo{});
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error(), Wire::SyncError::RateLimited);
    EXPECT_EQ(channelsBuilt, static_cast<int>(kMaxQueuedOpsPerReader)) << "no channel is built for a refused launch";
    releaseWorker();
    drainWorker();
}

TEST_F(OperationLauncherTest, AChannelFactoryThatBuildsNothingQueuesNothing)
{
    const OperationLauncher::ChannelFactory none = [](OperationId, const std::shared_ptr<OperationState>&) {
        return std::unique_ptr<OperationChannel>{};
    };
    blockWorker();
    EXPECT_THROW(static_cast<void>(launcher->launch(target, none, OperationLauncher::ReadIdentity{})),
                 std::logic_error);
    const auto next = launcher->launch(target, recordingChannel(), OperationLauncher::ReadIdentity{});
    ASSERT_TRUE(next.has_value());
    EXPECT_TRUE(core->operationManager().isIdTrackedForTest(*next));
    EXPECT_FALSE(core->operationManager().isIdTrackedForTest(OperationId{next->value() - 1}))
        << "the refused build left no operation behind";
    releaseWorker();
    drainWorker();
}

} // namespace
