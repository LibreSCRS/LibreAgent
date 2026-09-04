// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentClientContract.h — one set of claims, instantiated once per transport.
//
// Two clients behind one interface drift in the refusal mapping first, because
// that is the part no compiler holds: a refusal one transport spells as a name
// and the other as a number reaches the loader as two different reasons for the
// same event, and each transport's own suite stays green throughout. So the
// claims live here, once, and each transport instantiates them.
//
// It sits under include/ and not under tests/ on purpose. The root CMakeLists
// gates BOTH add_subdirectory(tests) and the install/export rules on
// PROJECT_IS_TOP_LEVEL, and no install() rule reaches tests/ -- so a header
// placed there would be neither installed for a find_package consumer nor
// configured for a FetchContent one, which is exactly the two ways the other
// host reaches this project.
//
// What a transport supplies is a Traits type. The claims below never name a
// socket, a bus, an error string or a wire enumerator; the traits type is the
// only place a transport's own spelling appears, and it appears there as the
// FAKE AGENT'S script rather than as the client's mapping. That separation is
// what makes the pair evidence: the double writes the refusal in the wire's own
// words, the production client reads it back, and only the client's answer is
// asserted.
//
//   struct Traits {
//       // An owning harness whose client() is live for the harness's lifetime.
//       struct Harness { AgentClient& client(); };
//
//       // A reader/card the agent serves, and the id of a cert on it.
//       static std::string reader();
//       static std::string certId();
//
//       // An agent that serves that reader and refuses login() with `r`.
//       static std::unique_ptr<Harness> refusingLogin(Refusal r);
//       // An agent that serves that reader and refuses nothing.
//       static std::unique_ptr<Harness> serving();
//       // A client with nothing on the other end at all.
//       static std::unique_ptr<Harness> unreachable();
//
//       // Whether this transport's login reply carries a lease duration.
//       static bool carriesLeaseDuration();
//   };
//
// At most ONE harness is alive at a time, and every claim below is written to
// keep it that way. A transport whose double claims a singleton resource -- a
// well-known bus name, a fixed socket path -- could not supply two, and a suite
// that quietly required two would be un-instantiable there rather than failing
// with something a reader could act on.
//
// Instantiate with:
//   INSTANTIATE_TYPED_TEST_SUITE_P(<TransportName>, AgentClientContract, MyTraits);

#pragma once

#include <LibreSCRS/Agent/pkcs11/AgentClient.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11Agent::Testing {

/// @brief A refusal an agent can answer with, named in the MODULE's terms.
///
/// Deliberately not the wire vocabulary of either transport: each of those is
/// larger, and the members that are missing from the other are exactly what a
/// shared claim cannot be made about. This is the intersection that both wires
/// can name, which is the set on which "the two transports agree" is even a
/// question.
enum class Refusal : std::uint8_t {
    UserNotLoggedIn,
    NotAuthorized,
    AuthFailed,
    Cancelled,
    KeyNotFound,
    UnknownCard,
    NotSupported,
    RateLimited,
    Communication,
};

/// @brief A refusal and the single Status every transport must answer with.
struct RefusalRow
{
    Refusal refusal;
    Status status;
    const char* label;
};

/// @brief Every refusal both wires name, with the one answer the module owes.
///
/// The Status column is the module's own contract (AgentClient.h names the
/// CKR_* each one becomes), so this table is what stops a transport from
/// quietly answering a cancelled prompt with a device error -- the failure this
/// suite exists for, and one that each transport's own suite reports as green.
inline constexpr std::array<RefusalRow, 9> kEveryRefusal{{
    {Refusal::UserNotLoggedIn, Status::UserNotLoggedIn, "UserNotLoggedIn"},
    {Refusal::NotAuthorized, Status::NotAuthorized, "NotAuthorized"},
    {Refusal::AuthFailed, Status::AuthFailed, "AuthFailed"},
    {Refusal::Cancelled, Status::Cancelled, "Cancelled"},
    {Refusal::KeyNotFound, Status::KeyNotFound, "KeyNotFound"},
    {Refusal::UnknownCard, Status::UnknownCard, "UnknownCard"},
    {Refusal::NotSupported, Status::NotSupported, "NotSupported"},
    {Refusal::RateLimited, Status::RateLimited, "RateLimited"},
    {Refusal::Communication, Status::Communication, "CommunicationError"},
}};

template <typename Traits>
class AgentClientContract : public ::testing::Test
{};

TYPED_TEST_SUITE_P(AgentClientContract);

// Each row, driven end to end: the double answers login() with the refusal in
// its own transport's words, and the client's Status is compared against the
// one column both transports share. A transport that maps two rows onto one
// Status passes this loop and fails the next one, which is why they are two.
TYPED_TEST_P(AgentClientContract, EveryRefusalReachesItsOwnStatus)
{
    for (const auto& row : kEveryRefusal) {
        auto harness = TypeParam::refusingLogin(row.refusal);
        ASSERT_NE(harness, nullptr) << row.label;
        EXPECT_EQ(harness->client().login(TypeParam::reader()).status, row.status) << row.label;
    }
}

// The table's Status column has no repeats, so the loop above is a claim about
// nine distinguishable outcomes rather than about nine names for one. Asserted
// here rather than assumed: a later edit that folds two rows together would
// otherwise leave the loop above passing with less coverage than it reads as
// having.
TYPED_TEST_P(AgentClientContract, TheRefusalsStayDistinguishableFromEachOther)
{
    std::vector<Status> seen;
    seen.reserve(kEveryRefusal.size());
    for (const auto& row : kEveryRefusal) {
        seen.push_back(row.status);
    }
    const std::size_t before = seen.size();
    std::sort(seen.begin(), seen.end());
    seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
    EXPECT_EQ(seen.size(), before) << "two refusals collapsed onto one Status";
}

// The claim this suite was blocked on. A user who dismisses the prompt has not
// hit a broken device, and the loader is told which of the two it was: the
// module answers CKR_FUNCTION_CANCELED rather than CKR_DEVICE_ERROR, on both
// transports. Spelled out separately from the loop because the loop would still
// pass if this row and the communication row swapped answers with each other.
TYPED_TEST_P(AgentClientContract, ACancelledPromptIsNotAFailedOne)
{
    // One harness at a time, per the traits contract above.
    Status cancelledStatus = Status::GeneralError;
    {
        auto harness = TypeParam::refusingLogin(Refusal::Cancelled);
        ASSERT_NE(harness, nullptr);
        cancelledStatus = harness->client().login(TypeParam::reader()).status;
    }
    Status brokenStatus = Status::GeneralError;
    {
        auto harness = TypeParam::refusingLogin(Refusal::Communication);
        ASSERT_NE(harness, nullptr);
        brokenStatus = harness->client().login(TypeParam::reader()).status;
    }

    EXPECT_EQ(cancelledStatus, Status::Cancelled);
    EXPECT_EQ(brokenStatus, Status::Communication);
    EXPECT_NE(cancelledStatus, brokenStatus) << "a cancelled prompt is reported as a device failure";
}

// Nothing on the other end at all. Every call answers DeviceRemoved -- not the
// generic error, and not a hang.
//
// connected() is deliberately NOT asserted here. One transport can tell before
// the first call (a socket that will not connect) and the other cannot (a bus
// proxy is constructible against a name nobody owns), and that difference is a
// property of the transports rather than a defect in either. What both owe is
// the same ANSWER once a call is made.
TYPED_TEST_P(AgentClientContract, WithNoAgentEveryCallIsDeviceRemoved)
{
    auto harness = TypeParam::unreachable();
    ASSERT_NE(harness, nullptr);
    AgentClient& c = harness->client();
    const std::string reader = TypeParam::reader();
    const std::string certId = TypeParam::certId();
    const std::vector<std::uint8_t> payload{0x01, 0x02, 0x03};

    EXPECT_EQ(c.login(reader).status, Status::DeviceRemoved);
    EXPECT_EQ(c.logout(reader), Status::DeviceRemoved);
    EXPECT_EQ(c.certDer(reader, certId).status, Status::DeviceRemoved);
    EXPECT_EQ(c.publicKey(reader, certId).status, Status::DeviceRemoved);
    EXPECT_EQ(c.signRaw(reader, certId, payload).status, Status::DeviceRemoved);
    EXPECT_EQ(c.decrypt(reader, certId, payload).status, Status::DeviceRemoved);
    EXPECT_TRUE(c.snapshot().readers.empty());
}

// The control for every case above: against an agent that refuses nothing, the
// same call succeeds. Without it a transport whose login() answered
// DeviceRemoved unconditionally would pass the unreachable case, and a
// transport whose double never started would pass the refusal loop by failing
// every row for the wrong reason.
//
// The lease DURATION is the one answer the two wires do not both carry -- the
// bus reply has an idle-timeout field, the socket reply is a bare ack -- so the
// claim is made per transport rather than weakened to what both happen to
// satisfy. A claim narrowed until everything passes it has stopped being one,
// and the transport that does carry the field would then be unwatched. Zero on
// the transport that carries no field means "the agent did not say"; anything
// else there would be a number this client invented.
TYPED_TEST_P(AgentClientContract, AServingAgentAnswersALease)
{
    auto harness = TypeParam::serving();
    ASSERT_NE(harness, nullptr);
    const LoginResult lease = harness->client().login(TypeParam::reader());
    EXPECT_EQ(lease.status, Status::Ok);
    if (TypeParam::carriesLeaseDuration()) {
        EXPECT_GT(lease.idleTimeoutSecs, 0U) << "this transport carries a lease duration and answered none";
    } else {
        EXPECT_EQ(lease.idleTimeoutSecs, 0U) << "this transport carries no lease duration to report";
    }
}

// ...and it really is the agent being talked to, not an empty answer that
// happens to satisfy the shapes above: the reader and its signing cert arrive.
TYPED_TEST_P(AgentClientContract, AServingAgentEnumeratesItsCard)
{
    auto harness = TypeParam::serving();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();
    ASSERT_FALSE(snap.readers.empty());

    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end()) << "the served reader is missing from the snapshot";
    EXPECT_TRUE(reader->hasCard);
    ASSERT_FALSE(reader->certs.empty()) << "the served card carries no certificate";
    EXPECT_EQ(reader->certs.front().certId, TypeParam::certId());
}

REGISTER_TYPED_TEST_SUITE_P(AgentClientContract, EveryRefusalReachesItsOwnStatus,
                            TheRefusalsStayDistinguishableFromEachOther, ACancelledPromptIsNotAFailedOne,
                            WithNoAgentEveryCallIsDeviceRemoved, AServingAgentAnswersALease,
                            AServingAgentEnumeratesItsCard);

} // namespace LibreSCRS::Pkcs11Agent::Testing
