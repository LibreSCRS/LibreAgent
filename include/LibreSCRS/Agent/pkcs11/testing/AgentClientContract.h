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
//       // That reader's display name, the subject CN of that cert, and the
//       // token serial the card's handle yields (tokenSerialFor() over the
//       // handle the double mints).
//       static std::string readerName();
//       static std::string holderName();
//       static std::string tokenSerial();
//
//       // An agent that serves that reader and refuses login() with `r`.
//       static std::unique_ptr<Harness> refusingLogin(Refusal r);
//       // An agent that serves that reader and refuses signRaw() with r.
//       static std::unique_ptr<Harness> refusingSign(Refusal r);
//       // An agent that serves that reader, its cert the EC key of servingEcCert(),
//       // and refuses derive() with r.
//       static std::unique_ptr<Harness> refusingDerive(Refusal r);
//       // An agent that serves that reader and refuses decrypt() with r.
//       static std::unique_ptr<Harness> refusingDecrypt(Refusal r);
//       // An agent that serves that reader and refuses nothing.
//       static std::unique_ptr<Harness> serving();
//       // The same reader and card, with no certificate on the card.
//       static std::unique_ptr<Harness> servingCardWithoutCertificate();
//       // The same, with the signing cert's subject carrying no CN.
//       static std::unique_ptr<Harness> servingCertWithoutCommonName();
//       // The same reader and card, its cert's key marked by the card for consent per operation.
//       static std::unique_ptr<Harness> servingAlwaysAuthenticateCert();
//       // The same reader and card, its cert an EC P-384 key with ID ecKeyId() that derives.
//       static std::unique_ptr<Harness> servingEcCert();
//       static std::vector<std::uint8_t> ecKeyId();
//       // The same EC key for key agreement only: its certificate's keyUsage
//       // is keyAgreement, so the agent reports it as not signing-capable.
//       static std::unique_ptr<Harness> servingDeriveOnlyEcCert();
//       // The secret Z servingEcCert()'s agent answers every derive() with.
//       static std::vector<std::uint8_t> cannedSecret();
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
#include <optional>
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
    InvalidRequest,
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
inline constexpr std::array<RefusalRow, 10> kEveryRefusal{{
    {Refusal::UserNotLoggedIn, Status::UserNotLoggedIn, "UserNotLoggedIn"},
    {Refusal::NotAuthorized, Status::NotAuthorized, "NotAuthorized"},
    {Refusal::AuthFailed, Status::AuthFailed, "AuthFailed"},
    {Refusal::Cancelled, Status::Cancelled, "Cancelled"},
    {Refusal::KeyNotFound, Status::KeyNotFound, "KeyNotFound"},
    {Refusal::UnknownCard, Status::UnknownCard, "UnknownCard"},
    {Refusal::NotSupported, Status::NotSupported, "NotSupported"},
    {Refusal::RateLimited, Status::RateLimited, "RateLimited"},
    {Refusal::Communication, Status::Communication, "CommunicationError"},
    {Refusal::InvalidRequest, Status::InvalidInput, "InvalidRequest"},
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
// ten distinguishable outcomes rather than about ten names for one. Asserted
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
    EXPECT_EQ(c.publicKey(reader, certId, LibreSCRS::Agent::KeyType::Rsa).status, Status::DeviceRemoved);
    EXPECT_EQ(c.signRaw(reader, certId, LibreSCRS::Agent::Mechanism::RsaPkcs1Sign, payload).status,
              Status::DeviceRemoved);
    EXPECT_EQ(c.decrypt(reader, certId, payload).status, Status::DeviceRemoved);
    EXPECT_EQ(c.derive(reader, certId, payload).status, Status::DeviceRemoved);
    EXPECT_EQ(c.loginActive(reader), std::nullopt) << "no agent, no answer -- not \"logged out\"";
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

// A loader tells two seated cards apart by their token's label and serial, so
// both transports owe the same two answers from what their agent already sends:
// the holder named by the card's signing certificate, and the tail of the
// card's handle as the serial. Without these, two cards both read "LibreSCRS
// Token" with no serial, and a loader such as NSS cannot keep them apart.
TYPED_TEST_P(AgentClientContract, ACardIsNamedAfterItsCertificateHolder)
{
    auto harness = TypeParam::serving();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();

    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end()) << "the served reader is missing from the snapshot";
    EXPECT_EQ(reader->tokenLabel, TypeParam::holderName());
    EXPECT_EQ(reader->tokenSerial, TypeParam::tokenSerial());
    EXPECT_FALSE(reader->tokenSerial.empty()) << "a seated card with no serial is indistinguishable from another";
}

// ...and a card with no certificate to name it after is named after the reader
// it sits in, on both transports alike. The serial does not depend on the
// certificates.
TYPED_TEST_P(AgentClientContract, ACardWithoutACertificateIsNamedAfterItsReader)
{
    auto harness = TypeParam::servingCardWithoutCertificate();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();

    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end()) << "the served reader is missing from the snapshot";
    EXPECT_TRUE(reader->certs.empty());
    EXPECT_EQ(reader->tokenLabel, TypeParam::readerName());
    EXPECT_EQ(reader->tokenSerial, TypeParam::tokenSerial());
}

// A signing certificate whose subject has no CN names nobody: its CKA_LABEL
// falls back to the certificate's hex id, and that is not a name to show a
// user. The token is named after its reader, as if there were no certificate,
// while the certificate itself still arrives.
TYPED_TEST_P(AgentClientContract, ACertWithoutACommonNameDoesNotNameTheToken)
{
    auto harness = TypeParam::servingCertWithoutCommonName();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();

    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end()) << "the served reader is missing from the snapshot";
    ASSERT_FALSE(reader->certs.empty()) << "the served card carries no certificate";
    EXPECT_TRUE(reader->certs.front().holderName.empty());
    EXPECT_EQ(reader->tokenLabel, TypeParam::readerName());
}

// The reader's own name reaches the snapshot for display, beside the handle
// every call is addressed by, on both transports alike.
TYPED_TEST_P(AgentClientContract, AReaderCarriesItsName)
{
    auto harness = TypeParam::serving();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();

    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end()) << "the served reader is missing from the snapshot";
    EXPECT_EQ(reader->readerName, TypeParam::readerName());
}

// The card's per-operation consent rule reaches the module the same way on
// both transports: a key it marks arrives marked, one it does not arrives
// unmarked. The PKCS#11 attribute a loader reads is built from this one bit.
TYPED_TEST_P(AgentClientContract, TheCardsConsentRuleReachesTheEntry)
{
    const std::string want = TypeParam::reader();
    const auto firstCertFlag = [&want](const AgentSnapshot& snap) -> std::optional<bool> {
        const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                         [&want](const ReaderState& r) { return r.readerPath == want; });
        if (reader == snap.readers.end() || reader->certs.empty())
            return std::nullopt;
        return reader->certs.front().alwaysAuthenticate;
    };
    {
        auto harness = TypeParam::serving();
        ASSERT_NE(harness, nullptr);
        EXPECT_EQ(firstCertFlag(harness->client().snapshot()), std::optional<bool>{false});
    }
    {
        auto harness = TypeParam::servingAlwaysAuthenticateCert();
        ASSERT_NE(harness, nullptr);
        EXPECT_EQ(firstCertFlag(harness->client().snapshot()), std::optional<bool>{true});
    }
}

// An agent whose lease has lapsed refuses the next signature as "not logged
// in". Both transports owe the module that one Status for it -- the answer it
// turns back into a public session -- not the generic error a transport that
// mapped only login() refusals would give.
TYPED_TEST_P(AgentClientContract, ASignWithoutALeaseIsNotLoggedIn)
{
    auto harness = TypeParam::refusingSign(Refusal::UserNotLoggedIn);
    ASSERT_NE(harness, nullptr);
    const std::vector<std::uint8_t> payload{0x30, 0x31};
    EXPECT_EQ(harness->client()
                  .signRaw(TypeParam::reader(), TypeParam::certId(), LibreSCRS::Agent::Mechanism::RsaPkcs1Sign, payload)
                  .status,
              Status::UserNotLoggedIn);
}

// The facts a module builds a key object from arrive the same way on both
// transports: the card's own CKA_ID, the key's family and size, and whether the
// agent derives with it. A transport that dropped one would hand a loader an
// RSA key with a made-up ID where the card holds an EC key.
TYPED_TEST_P(AgentClientContract, TheKeyFactsReachTheEntry)
{
    auto harness = TypeParam::servingEcCert();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();
    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end());
    ASSERT_FALSE(reader->certs.empty());
    const CertEntry& e = reader->certs.front();
    EXPECT_EQ(e.ckaId, TypeParam::ecKeyId());
    EXPECT_EQ(e.keyType, LibreSCRS::Agent::KeyType::Ec);
    EXPECT_EQ(e.keyBits, 384u);
    EXPECT_TRUE(e.canDerive);
    EXPECT_FALSE(e.canDecrypt) << "an EC key never decrypts";
    EXPECT_TRUE(e.signingCapable);
    EXPECT_TRUE(e.canSign) << "a signing-capable key on a card the agent signs with";
}

// A key the agent derives with but whose certificate does not sign still
// arrives -- as a key that derives and does not sign, on both transports.
TYPED_TEST_P(AgentClientContract, ADeriveOnlyKeyArrivesAsOneThatDoesNotSign)
{
    auto harness = TypeParam::servingDeriveOnlyEcCert();
    ASSERT_NE(harness, nullptr);
    const AgentSnapshot snap = harness->client().snapshot();
    const std::string want = TypeParam::reader();
    const auto reader = std::find_if(snap.readers.begin(), snap.readers.end(),
                                     [&want](const ReaderState& r) { return r.readerPath == want; });
    ASSERT_NE(reader, snap.readers.end());
    ASSERT_FALSE(reader->certs.empty()) << "a key that derives is dropped for not signing";
    const CertEntry& e = reader->certs.front();
    EXPECT_EQ(e.keyType, LibreSCRS::Agent::KeyType::Ec);
    EXPECT_TRUE(e.canDerive);
    EXPECT_FALSE(e.signingCapable);
    EXPECT_FALSE(e.canSign);
}

// An EC key's public point arrives at fixed width on both transports.
TYPED_TEST_P(AgentClientContract, AnEcKeyServesItsPoint)
{
    auto harness = TypeParam::servingEcCert();
    ASSERT_NE(harness, nullptr);
    const PublicKeyResult pk =
        harness->client().publicKey(TypeParam::reader(), TypeParam::certId(), LibreSCRS::Agent::KeyType::Ec);
    EXPECT_EQ(pk.status, Status::Ok);
    EXPECT_EQ(pk.crv, "P-384");
    EXPECT_EQ(pk.x.size(), 48u);
    EXPECT_EQ(pk.y.size(), 48u);
    EXPECT_TRUE(pk.modulus.empty());
}

// An input the agent refuses before any prompt is the caller's mistake on both
// transports -- InvalidInput, never a device error the loader would act on.
TYPED_TEST_P(AgentClientContract, ASignTheAgentRefusesAsInvalidIsInvalidInput)
{
    auto harness = TypeParam::refusingSign(Refusal::InvalidRequest);
    ASSERT_NE(harness, nullptr);
    const std::vector<std::uint8_t> digest(20, 0x01);
    EXPECT_EQ(harness->client()
                  .signRaw(TypeParam::reader(), TypeParam::certId(), LibreSCRS::Agent::Mechanism::EcdsaSign, digest)
                  .status,
              Status::InvalidInput);
}

// ...and a decryption refused the same way is InvalidInput as well.
TYPED_TEST_P(AgentClientContract, ADecryptTheAgentRefusesAsInvalidIsInvalidInput)
{
    auto harness = TypeParam::refusingDecrypt(Refusal::InvalidRequest);
    ASSERT_NE(harness, nullptr);
    const std::vector<std::uint8_t> ciphertext(255, 0x01);
    EXPECT_EQ(harness->client().decrypt(TypeParam::reader(), TypeParam::certId(), ciphertext).status,
              Status::InvalidInput);
}

// Only a signing mechanism is ever sent as a signature. A decryption mechanism
// shares its wire token with an RSA signature, and a mechanism with no signing
// token at all has nothing to send; both answer NotSupported without reaching
// the agent -- which here would refuse any signature as "not logged in", so a
// transport that sent one is caught by the answer it got back.
TYPED_TEST_P(AgentClientContract, OnlyASigningMechanismIsSentAsASignature)
{
    using LibreSCRS::Agent::Mechanism;
    auto harness = TypeParam::refusingSign(Refusal::UserNotLoggedIn);
    ASSERT_NE(harness, nullptr);
    const std::vector<std::uint8_t> payload(48, 0x01);
    for (const Mechanism m : {Mechanism::RsaPkcs1Sign, Mechanism::RsaPssSign, Mechanism::EcdsaSign,
                              Mechanism::RsaPkcs1Decrypt, Mechanism::RsaOaepDecrypt, Mechanism::EcdhDerive,
                              Mechanism::RsaPkcs1Encrypt, Mechanism::RsaOaepEncrypt, Mechanism::Sha256RsaPkcs1Sign}) {
        const bool signs = LibreSCRS::Agent::signMechanismFromToken(LibreSCRS::Agent::mechanismToken(m)) == m;
        const Status got = harness->client().signRaw(TypeParam::reader(), TypeParam::certId(), m, payload).status;
        EXPECT_EQ(got, signs ? Status::UserNotLoggedIn : Status::NotSupported)
            << "mechanism " << static_cast<int>(m)
            << (signs ? " is a signature and was not sent" : " is not a signature and reached the agent");
    }
}

// A key agreement answers the agent's secret, or its refusal, the same on both
// wires: an off-curve point the agent refuses before any prompt is the
// caller's mistake (InvalidInput), not a device error.
TYPED_TEST_P(AgentClientContract, ADeriveAnswersTheSecretOrItsRefusal)
{
    std::vector<std::uint8_t> point(97, 0x33);
    point[0] = 0x04;
    {
        auto harness = TypeParam::servingEcCert();
        ASSERT_NE(harness, nullptr);
        const BytesResult z = harness->client().derive(TypeParam::reader(), TypeParam::certId(), point);
        EXPECT_EQ(z.status, Status::Ok);
        EXPECT_EQ(z.bytes, TypeParam::cannedSecret());
    }
    {
        auto harness = TypeParam::refusingDerive(Refusal::InvalidRequest);
        ASSERT_NE(harness, nullptr);
        EXPECT_EQ(harness->client().derive(TypeParam::reader(), TypeParam::certId(), point).status,
                  Status::InvalidInput);
    }
    {
        // Lease-gated like a signature: without one it is not logged in.
        auto harness = TypeParam::refusingDerive(Refusal::UserNotLoggedIn);
        ASSERT_NE(harness, nullptr);
        EXPECT_EQ(harness->client().derive(TypeParam::reader(), TypeParam::certId(), point).status,
                  Status::UserNotLoggedIn);
    }
}

// What a loader is told about its login is what the agent holds: none before
// C_Login, one after it, none after C_Logout. Both wires, the same three
// answers -- a transport that answered "held" from its own memory would keep a
// login the agent had already dropped.
TYPED_TEST_P(AgentClientContract, ALoginHoldsUntilItEnds)
{
    auto harness = TypeParam::serving();
    ASSERT_NE(harness, nullptr);
    AgentClient& c = harness->client();
    const std::string reader = TypeParam::reader();
    EXPECT_EQ(c.loginActive(reader), std::optional<bool>{false}) << "before the login";
    ASSERT_EQ(c.login(reader).status, Status::Ok);
    EXPECT_EQ(c.loginActive(reader), std::optional<bool>{true}) << "after the login";
    ASSERT_EQ(c.logout(reader), Status::Ok);
    EXPECT_EQ(c.loginActive(reader), std::optional<bool>{false}) << "after the logout";
}

// An agent that does not offer the question leaves it unanswered, which the
// module reads as "keep what you knew" -- never as "logged out", which would
// ask for the PIN every second against an older agent.
TYPED_TEST_P(AgentClientContract, AnAgentThatDoesNotOfferTheQuestionLeavesItUnanswered)
{
    auto harness = TypeParam::servingWithoutLoginState();
    ASSERT_NE(harness, nullptr);
    AgentClient& c = harness->client();
    const std::string reader = TypeParam::reader();
    ASSERT_EQ(c.login(reader).status, Status::Ok);
    EXPECT_EQ(c.loginActive(reader), std::nullopt);
    EXPECT_EQ(c.login(reader).status, Status::Ok) << "and the connection is still there";
}

REGISTER_TYPED_TEST_SUITE_P(AgentClientContract, EveryRefusalReachesItsOwnStatus,
                            TheRefusalsStayDistinguishableFromEachOther, ACancelledPromptIsNotAFailedOne,
                            WithNoAgentEveryCallIsDeviceRemoved, AServingAgentAnswersALease,
                            AServingAgentEnumeratesItsCard, ACardIsNamedAfterItsCertificateHolder,
                            ACardWithoutACertificateIsNamedAfterItsReader, ACertWithoutACommonNameDoesNotNameTheToken,
                            AReaderCarriesItsName, TheCardsConsentRuleReachesTheEntry, ASignWithoutALeaseIsNotLoggedIn,
                            TheKeyFactsReachTheEntry, ADeriveOnlyKeyArrivesAsOneThatDoesNotSign, AnEcKeyServesItsPoint,
                            ASignTheAgentRefusesAsInvalidIsInvalidInput, ADecryptTheAgentRefusesAsInvalidIsInvalidInput,
                            OnlyASigningMechanismIsSentAsASignature, ADeriveAnswersTheSecretOrItsRefusal,
                            ALoginHoldsUntilItEnds, AnAgentThatDoesNotOfferTheQuestionLeavesItUnanswered);

} // namespace LibreSCRS::Pkcs11Agent::Testing
