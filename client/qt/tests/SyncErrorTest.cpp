// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The sync-error DIMENSION of the error-name classification table: which
// failures carry a named wire error back to the caller, which carry none, and
// that the name survives the collapse onto CallError/ErrorCode instead of being
// dropped there.
//
// Deliberately a separate suite from ErrorNameMapTest.cpp, which stays exactly
// as it was: this work adds an axis and re-maps nothing, so that file's
// assertions are the proof the existing two axes did not move, and mixing the
// new cases into it would blur what is old and what is new.
//
// The other half of this coverage — the same value reaching the PUBLIC
// AgentOperation::syncError() getter, over a transport fake, including the
// certificateDer path that never touches failEntry — lives with the rest of the
// public-API-over-a-fake-seam corpus in SeamMappingTest.cpp (the SeamSyncError
// cases).
//
// Compiles src/dbus/ErrorNameMap.cpp directly (internal, hidden-visibility TU)
// and links the wire library, whose decoder the table now calls. Pure string
// classification: no bus, no event loop.

#include "ErrorNameMap.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <vector>

using namespace LibreSCRS::AgentClient;

namespace {

SeamError mapFull(const char* name)
{
    return mapDBusErrorName(QString::fromLatin1(name), QStringLiteral("msg"));
}

SeamError mapShort(const char* shortName)
{
    return mapAgentErrorShortName(QString::fromLatin1(shortName), QStringLiteral("msg"));
}

} // namespace

// ---- every token in the vocabulary is reachable ---------------------------------

// The whole vocabulary, spelled out rather than derived from syncErrorName():
// the point of this case is that the classification site really parses the
// token and lands on the right enumerator, so driving the expectation from the
// same function the implementation uses would assert nothing. A token appended
// to the wire vocabulary without a row here is caught on the wire side, where
// the CDDL and the enum are compared as sets.
TEST(SyncErrorClassification, EveryWireNameReachesItsOwnEnumerator)
{
    struct Row
    {
        const char* name;
        SyncError expected;
    };
    const Row rows[] = {
        {"UnknownCard", SyncError::UnknownCard},
        {"KeyNotFound", SyncError::KeyNotFound},
        {"NotAuthorized", SyncError::NotAuthorized},
        {"UserNotLoggedIn", SyncError::UserNotLoggedIn},
        {"UnknownConfigKey", SyncError::UnknownConfigKey},
        {"ReadOnlyConfig", SyncError::ReadOnlyConfig},
        {"InvalidConfigValue", SyncError::InvalidConfigValue},
        {"UnsupportedProtocol", SyncError::UnsupportedProtocol},
        {"AuthFailed", SyncError::AuthFailed},
        {"CommunicationError", SyncError::CommunicationError},
        {"NotSupported", SyncError::NotSupported},
        {"UnsupportedOnThisCard", SyncError::UnsupportedOnThisCard},
        {"UnsupportedSignatureParameter", SyncError::UnsupportedSignatureParameter},
        {"InputTooLarge", SyncError::InputTooLarge},
        {"RateLimited", SyncError::RateLimited},
        {"UnknownCredential", SyncError::UnknownCredential},
        {"InvalidRequest", SyncError::InvalidRequest},
        {"NoResult", SyncError::NoResult},
    };
    for (const Row& row : rows) {
        const SeamError viaShort = mapShort(row.name);
        ASSERT_TRUE(viaShort.syncError.has_value()) << "no named error carried for " << row.name;
        EXPECT_EQ(*viaShort.syncError, row.expected) << row.name;

        // Both entry points must agree: the socket wire carries the short
        // spelling, the bus wire the prefixed one.
        const SeamError viaFull = mapDBusErrorName(
            QStringLiteral("org.librescrs.Agent.Error.") + QString::fromLatin1(row.name), QStringLiteral("msg"));
        ASSERT_TRUE(viaFull.syncError.has_value()) << "no named error carried for the prefixed " << row.name;
        EXPECT_EQ(*viaFull.syncError, *viaShort.syncError) << row.name;
    }
}

// ---- the collapse this axis exists to survive -----------------------------------

// Six names share CallError::InvalidArguments and report ErrorCode::None, so
// before this axis existed a caller could not tell them apart at all. The two
// that matter most to a credential surface are the first two rows: one means
// "your ids went stale, re-list and the user can retry" and the other means "a
// persistent condition of this card, re-listing cannot clear it".
TEST(SyncErrorClassification, NamesSharingOneCallErrorBucketStayDistinguishable)
{
    const char* names[] = {
        "InvalidRequest",   "UnknownCredential", "UnsupportedSignatureParameter",
        "UnknownConfigKey", "ReadOnlyConfig",    "InvalidConfigValue",
    };
    std::vector<SyncError> seen;
    for (const char* name : names) {
        const SeamError e = mapShort(name);
        // The bucket itself is unchanged — that is the invariant this work keeps.
        EXPECT_EQ(e.callError, CallError::InvalidArguments) << name;
        EXPECT_EQ(e.errorCode, ErrorCode::None) << name;
        ASSERT_TRUE(e.syncError.has_value()) << name;
        seen.push_back(*e.syncError);
    }
    // All six distinct: no two of them collapse onto one another on this axis.
    const std::size_t before = seen.size();
    std::sort(seen.begin(), seen.end());
    seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
    EXPECT_EQ(seen.size(), before) << "two names sharing a CallError bucket also collapsed on the sync-error axis";
}

// The three-way split a public-data fetch needs: two names that mean "this
// certificate/card does not exist" (distinguishable from each other), versus an
// unreachable agent, which is NOT a wire token at all and is discriminated by
// callError instead.
TEST(SyncErrorClassification, MissingObjectNamesAreNamedAndUnavailabilityIsNot)
{
    const SeamError keyNotFound = mapShort("KeyNotFound");
    ASSERT_TRUE(keyNotFound.syncError.has_value());
    EXPECT_EQ(*keyNotFound.syncError, SyncError::KeyNotFound);
    EXPECT_EQ(keyNotFound.errorCode, ErrorCode::KeyNotFound);

    const SeamError unknownCard = mapShort("UnknownCard");
    ASSERT_TRUE(unknownCard.syncError.has_value());
    EXPECT_EQ(*unknownCard.syncError, SyncError::UnknownCard);
    EXPECT_EQ(unknownCard.errorCode, ErrorCode::UnsupportedCard);

    // Unavailability has never been a wire name — nothing on the wire says it,
    // the client observes it. Its discriminator is the CallError.
    const SeamError unavailable = mapFull("org.freedesktop.DBus.Error.ServiceUnknown");
    EXPECT_EQ(unavailable.callError, CallError::AgentUnavailable);
    EXPECT_FALSE(unavailable.syncError.has_value())
        << "an unreachable agent must not be reported as a named wire refusal";
}

// ---- the degrade, pinned so nobody mistakes it for identification -------------

TEST(SyncErrorClassification, UnrecognisedAgentNameDegradesRatherThanDisengaging)
{
    // A name from a newer agent, and the agent's own catch-all name. Both land
    // on the generic bucket on BOTH axes: the vocabulary is a text-token enum
    // with nowhere to carry an unrecognised token forward, and the socket wire
    // already degrades identically at decode time, so the two transports
    // converge.
    for (const char* name : {"SomethingFromTheFuture", "Internal"}) {
        const SeamError e = mapShort(name);
        EXPECT_EQ(e.callError, CallError::None) << name;
        EXPECT_EQ(e.errorCode, ErrorCode::CommunicationError) << name;
        ASSERT_TRUE(e.syncError.has_value()) << name;
        EXPECT_EQ(*e.syncError, SyncError::CommunicationError) << name;
    }
    // ...and it is therefore INDISTINGUISHABLE from the peer genuinely naming
    // CommunicationError. Pinned deliberately: a consumer must not read this
    // value as a positive identification.
    const SeamError genuine = mapShort("CommunicationError");
    ASSERT_TRUE(genuine.syncError.has_value());
    EXPECT_EQ(*genuine.syncError, *mapShort("SomethingFromTheFuture").syncError);
}

// ---- everything outside the agent namespace carries no name ---------------------

TEST(SyncErrorClassification, BusDaemonFailuresCarryNoName)
{
    const char* names[] = {
        "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner",
        "org.freedesktop.DBus.Error.NoReply",        "org.freedesktop.DBus.Error.Timeout",
        "org.freedesktop.DBus.Error.TimedOut",       "org.freedesktop.DBus.Error.AccessDenied",
        "org.freedesktop.DBus.Error.InvalidArgs",    "org.freedesktop.DBus.Error.UnknownMethod",
        "org.freedesktop.DBus.Error.Disconnected",   "org.freedesktop.DBus.Error.NoMemory",
    };
    for (const char* name : names) {
        const SeamError e = mapFull(name);
        EXPECT_FALSE(e.syncError.has_value()) << name;
    }
}

TEST(SyncErrorClassification, ForeignErrorDomainCarriesNoName)
{
    const SeamError e = mapFull("com.example.SomeService.Error.Whatever");
    EXPECT_EQ(e.callError, CallError::ProtocolError);
    EXPECT_FALSE(e.syncError.has_value());
}

// The sharp case for WHERE the token is parsed. Two freedesktop names end in
// spellings that are also sync-error tokens ("AuthFailed", and "Timeout" is not
// but "AccessDenied" pairs with the agent's NotAuthorized bucket). A consumer —
// or an implementation — that derived the named error from the tail of
// `wireName` would read the bus daemon's own AuthFailed as the CARD's
// AuthFailed, which is a completely different failure with a completely
// different recovery. Parsing at the classification site, which knows which
// namespace it is in, is what makes that impossible.
TEST(SyncErrorClassification, TheNameIsParsedAtTheClassificationSiteNotFromWireName)
{
    const SeamError busAuth = mapFull("org.freedesktop.DBus.Error.AuthFailed");
    EXPECT_EQ(busAuth.callError, CallError::AccessDenied);
    // wireName holds the FULL name on this branch — its tail is a red herring.
    EXPECT_EQ(busAuth.wireName, QStringLiteral("org.freedesktop.DBus.Error.AuthFailed"));
    EXPECT_FALSE(busAuth.syncError.has_value()) << "the bus daemon's AuthFailed is not the card's AuthFailed";

    // The agent's own AuthFailed, by contrast, IS named — same tail, different
    // namespace, different answer.
    const SeamError cardAuth = mapFull("org.librescrs.Agent.Error.AuthFailed");
    ASSERT_TRUE(cardAuth.syncError.has_value());
    EXPECT_EQ(*cardAuth.syncError, SyncError::AuthFailed);
    EXPECT_EQ(cardAuth.errorCode, ErrorCode::AuthFailed);
}

// ---- a failure the client diagnosed, not one the peer named ---------------------

// The distinction that motivates localExchangeFailure(): a reply that is not a
// reply, an empty body, a reply arm that does not answer the request. These used
// to be routed through mapAgentErrorShortName("CommunicationError"), which gave
// the right two axes but — once the third axis existed — also claimed the peer
// had named CommunicationError. It had named nothing.
TEST(SyncErrorClassification, AClientDiagnosedExchangeFailureCarriesNoName)
{
    const SeamError e = localExchangeFailure(QStringLiteral("empty reply"));
    EXPECT_FALSE(e.syncError.has_value()) << "the peer named nothing, so the named-error axis must stay disengaged";

    // ...while the two pre-existing axes are byte-identical to what the old
    // spelling produced, because this work re-maps nothing. Compared against
    // that exact spelling so the equivalence is asserted, not assumed.
    const SeamError legacy = mapShort("CommunicationError");
    EXPECT_EQ(e.callError, legacy.callError);
    EXPECT_EQ(e.errorCode, legacy.errorCode);
    EXPECT_EQ(e.wireName, legacy.wireName);
    EXPECT_EQ(e.message, QStringLiteral("empty reply"));
    EXPECT_TRUE(e.isError());

    // And the two differ on exactly one axis — the new one.
    ASSERT_TRUE(legacy.syncError.has_value());
    EXPECT_EQ(*legacy.syncError, SyncError::CommunicationError);
}

// ---- the default ----------------------------------------------------------------

TEST(SyncErrorClassification, ASeamErrorNobodyClassifiedCarriesNoName)
{
    const SeamError none;
    EXPECT_FALSE(none.isError());
    EXPECT_FALSE(none.syncError.has_value());
}
