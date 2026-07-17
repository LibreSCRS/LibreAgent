// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum (wire-stable integers)
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <gtest/gtest.h>
#include <type_traits>

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::errorCodeFor;
using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::SecureChannel::ChannelActivationError;
using ReadStatus = LibreSCRS::Plugin::ReadResult::Status;

TEST(ErrorTaxonomy, StableNumericValues)
{
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::None), 0u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::CardRemoved), 1u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::CredentialWrong), 2u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::CredentialBlocked), 3u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::CommunicationError), 4u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::ParseError), 5u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::UnsupportedCard), 6u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::AuthFailed), 7u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::PrompterError), 8u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::CapabilityMissing), 9u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::WatchdogTimeout), 10u);
    // Signing codes — append-only, frozen on the wire (Operation1.xml doc block).
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::KeyNotFound), 11u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::KeyAmbiguous), 12u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::CertExpiredBlocked), 13u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::ChainIncomplete), 14u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::TsaUnreachable), 15u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::SigningEngineError), 16u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::RateLimited), 17u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::EngineUnavailable), 18u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::InvalidDocument), 19u);
}

// Exhaustiveness guard. The StableNumericValues test above pins every ErrorCode
// integer 0..N individually; this pins N itself (the highest wire value). A new
// code appended to the enum bumps this maximum and trips this assertion, which
// is the reminder to (a) add its numeric pin above and (b) update the three
// out-of-repo mirrors of this taxonomy (see the ErrorTaxonomy.h wire-freeze
// note): the Linux agent CDDL/taxonomy, the KDE client, and the fail-closed
// macOS Swift AgentTypes mirror. Bump this value only when all of that is done.
TEST(ErrorTaxonomy, HighestWireValueIsPinned)
{
    // The enum is append-only, so the last enumerator is the maximum value.
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::InvalidDocument), 19u)
        << "ErrorCode enum grew: pin the new value in StableNumericValues, bump "
           "this guard, and update the CDDL / KDE / macOS Swift mirrors.";
}

TEST(ErrorTaxonomy, PhaseWireValuesAreFrozen)
{
    // Phase integers are a frozen wire contract (Operation1.xml doc block). Pin
    // Timestamping at 6 — the b-t/b-lt/b-lta declarative timestamping phase.
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Created), 0u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Connecting), 1u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent), 2u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Authenticating), 3u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Reading), 4u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Signing), 5u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Timestamping), 6u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Done), 7u);
}

TEST(ErrorTaxonomy, MapsChannelActivationErrors)
{
    EXPECT_EQ(errorCodeFor(ChannelActivationError::None), ErrorCode::None);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::SelectAppletFailed), ErrorCode::UnsupportedCard);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::PaceWrongSecret), ErrorCode::CredentialWrong);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::PacePinBlocked), ErrorCode::CredentialBlocked);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::PaceProtocolFailure), ErrorCode::AuthFailed);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::PaceUnsupported), ErrorCode::UnsupportedCard);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::UserCancelled), ErrorCode::None);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::Cancelled), ErrorCode::None);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::CardRemoved), ErrorCode::CardRemoved);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::ReaderError), ErrorCode::CommunicationError);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::CredentialsRequired), ErrorCode::AuthFailed);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::Internal), ErrorCode::CommunicationError);
    EXPECT_EQ(errorCodeFor(ChannelActivationError::ReentrantAccess), ErrorCode::CommunicationError);
}

TEST(ErrorTaxonomy, MapsReadResultStatuses)
{
    EXPECT_EQ(errorCodeFor(ReadStatus::Ok), ErrorCode::None);
    EXPECT_EQ(errorCodeFor(ReadStatus::CommunicationError), ErrorCode::CommunicationError);
    EXPECT_EQ(errorCodeFor(ReadStatus::ParseError), ErrorCode::ParseError);
    EXPECT_EQ(errorCodeFor(ReadStatus::UnsupportedCard), ErrorCode::UnsupportedCard);
    EXPECT_EQ(errorCodeFor(ReadStatus::AuthenticationFailed), ErrorCode::AuthFailed);
    EXPECT_EQ(errorCodeFor(ReadStatus::Cancelled), ErrorCode::None);
}

TEST(ErrorTaxonomy, MappersAreNoexcept)
{
    static_assert(noexcept(errorCodeFor(ChannelActivationError::None)));
    static_assert(noexcept(errorCodeFor(ReadStatus::Ok)));
    SUCCEED();
}
