// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Construction wiring for the owning neutral-core aggregate: every accessor
// returns the live owned member (or the borrowed collaborator that was injected),
// the members are usable, and the aggregate tears down cleanly in reverse
// construction order. The cross-member interaction (drive the presence model,
// observe the registry) proves the registry is constructed BEFORE the model that
// borrows it; the prompter-refcount check after teardown proves the aggregate
// released its borrowed prompter share on destruction (reverse order, no leak).
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/Identity.h>
#include "fakes/FakeAgentTransport.h"
#include "fakes/FakeAuthorizer.h"
#include "fakes/FakePrompter.h"

#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

using namespace LibreSCRS::Agent;
namespace fs = std::filesystem;

namespace {

// The base CapabilityResolver already models a null (ATR-hint-free, empty
// candidate) resolver via its defaulted virtuals — exactly the neutral double a
// wiring test needs.
class NeutralResolver final : public CapabilityResolver
{};

fs::path uniqueDir()
{
    return fs::temp_directory_path() / "libreagent-agentcore-wiring";
}

} // namespace

TEST(AgentCoreWiring, AccessorsReturnLiveMembersAndBorrowedCollaborators)
{
    const auto dir = uniqueDir();
    fs::remove_all(dir);

    NeutralResolver resolver;
    FakeAgentTransport transport;
    FakeAuthorizer authorizer;
    auto prompter = std::make_shared<Operations::FakePrompter>();

    {
        AgentCore core{resolver,
                       transport,
                       authorizer,
                       prompter,
                       dir / "agent.conf",
                       dir / "cache",
                       [](const std::string&) -> std::optional<ReaderCard> { return std::nullopt; },
                       [](const std::string&) -> std::optional<ObjectId> { return std::nullopt; }};

        // Borrowed collaborators resolve to the exact injected instances.
        EXPECT_EQ(&core.capabilityResolver(), &resolver);
        EXPECT_EQ(&core.transport(), &transport);
        EXPECT_EQ(&core.authorizer(), &authorizer);
        EXPECT_EQ(core.prompter().get(), prompter.get());
        // The aggregate co-owns the prompter for abandoned-worker keep-alive, so
        // the count exceeds the test's single reference.
        EXPECT_GE(prompter.use_count(), 2);

        // Owned-member accessors are stable (same storage across calls).
        EXPECT_EQ(&core.operationManager(), &core.operationManager());
        EXPECT_EQ(&core.leaseManager(), &core.leaseManager());
        EXPECT_EQ(&core.pkcs11(), &core.pkcs11());

        // Cross-member interaction proves the registry was constructed before
        // the presence model that borrows it: driving the model mutates the
        // live registry and mints a stable reader id.
        core.presenceModel().onReaderAdded("reader-A");
        ASSERT_EQ(core.objectRegistry().readers().size(), 1u);
        EXPECT_EQ(core.objectRegistry().readers()[0].name, "reader-A");
        EXPECT_NE(core.presenceModel().readerIdFor("reader-A"), ObjectId{});

        // The signing engine was built from the borrowed config (present even
        // with no TSA configured, so B-B always signs).
        EXPECT_FALSE(core.configStore().defaultLevel().empty());
        EXPECT_NE(core.signingEngineProvider().snapshot().engine, nullptr);

        // The remaining owned members are live and behave.
        EXPECT_TRUE(core.rateLimiter().allow(CallerToken{":1.5"}));

        const Pkcs11::LeaseKey key{.caller = CallerToken{":1.5"}, .card = ObjectId{7}};
        const auto now = std::chrono::steady_clock::now();
        core.leaseManager().grant(key, now);
        EXPECT_TRUE(core.leaseManager().isActive(key, now));

        // The caches accept and return per-card state (proves their storage is
        // the aggregate's own, not a dangling borrow).
        core.credentialCache().putCan("card-1", CredentialCache::Secret{"1234"});
        EXPECT_TRUE(core.credentialCache().hasCan("card-1"));
    }

    // The aggregate is gone: it dropped its prompter share in reverse
    // construction order, leaving only the test's reference. A UAF in the
    // reverse teardown (e.g. a member destroyed before a borrower) would trip
    // the sanitizer here rather than assert.
    EXPECT_EQ(prompter.use_count(), 1);

    fs::remove_all(dir);
}
