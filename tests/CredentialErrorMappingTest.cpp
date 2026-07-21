// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/OperationPhase.h>         // OperationStatus (the finish status)
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialOutcome
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>    // ErrorCode, CredentialFinish, errorCodeFor
#include <gtest/gtest.h>

#include <array>
#include <stdexcept>

using LibreSCRS::Agent::CredentialFinish;
using LibreSCRS::Agent::CredentialOutcome;
using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::errorCodeFor;
using OperationStatus = LibreSCRS::Agent::Operations::OperationStatus;

namespace {

// Independent oracle for the normative outcome -> (finish status, wire code)
// map. Exhaustive over CredentialOutcome with NO default case; the pragma
// promotes -Wswitch to an ERROR in THIS translation unit regardless of the test
// target's warning flags, so appending a member to CredentialOutcome that this
// table does not cover is a hard COMPILE failure here. It is a local mirror of
// the production mapper's own exhaustive switch and the reminder to extend the
// verbatim assertions below in lockstep.
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
CredentialFinish oracle(CredentialOutcome outcome)
{
    switch (outcome) {
    case CredentialOutcome::Ok:
        return {OperationStatus::Ok, ErrorCode::None};
    case CredentialOutcome::UserCancelled:
        return {OperationStatus::Cancelled, ErrorCode::None};
    case CredentialOutcome::Unspecified:
        return {OperationStatus::Error, ErrorCode::CommunicationError};
    case CredentialOutcome::MissingFields:
        return {OperationStatus::Error, ErrorCode::PrompterError};
    case CredentialOutcome::InvalidPin:
        return {OperationStatus::Error, ErrorCode::CredentialWrong};
    case CredentialOutcome::Blocked:
        return {OperationStatus::Error, ErrorCode::CredentialBlocked};
    case CredentialOutcome::PluginError:
        return {OperationStatus::Error, ErrorCode::CommunicationError};
    case CredentialOutcome::Unsupported:
        return {OperationStatus::Error, ErrorCode::CapabilityMissing};
    case CredentialOutcome::KeyActivationFailed:
        return {OperationStatus::Error, ErrorCode::CommunicationError};
    case CredentialOutcome::CardRemoved:
        return {OperationStatus::Error, ErrorCode::CardRemoved};
    }
    throw std::logic_error("oracle: unmapped CredentialOutcome (switch is exhaustive)");
}
#pragma GCC diagnostic pop

constexpr std::array<CredentialOutcome, 10> kAllOutcomes{
    CredentialOutcome::Unspecified,   CredentialOutcome::Ok,          CredentialOutcome::UserCancelled,
    CredentialOutcome::MissingFields, CredentialOutcome::InvalidPin,  CredentialOutcome::Blocked,
    CredentialOutcome::PluginError,   CredentialOutcome::Unsupported, CredentialOutcome::KeyActivationFailed,
    CredentialOutcome::CardRemoved,
};

// Assert the whole PAIR, not the code alone: the Cancelled-status / None-code
// row is only meaningful when the finish status is checked too.
void expectPair(CredentialOutcome outcome, OperationStatus status, ErrorCode code)
{
    const CredentialFinish got = errorCodeFor(outcome);
    EXPECT_EQ(got.status, status) << "outcome index " << static_cast<int>(outcome);
    EXPECT_EQ(got.code, code) << "outcome index " << static_cast<int>(outcome);
}

} // namespace

// The normative table, verbatim (one row per CredentialOutcome member).
TEST(CredentialErrorMapping, MapsEachOutcomeToContractPair)
{
    expectPair(CredentialOutcome::Ok, OperationStatus::Ok, ErrorCode::None);
    expectPair(CredentialOutcome::UserCancelled, OperationStatus::Cancelled, ErrorCode::None);
    expectPair(CredentialOutcome::Unspecified, OperationStatus::Error, ErrorCode::CommunicationError);
    expectPair(CredentialOutcome::MissingFields, OperationStatus::Error, ErrorCode::PrompterError);
    expectPair(CredentialOutcome::InvalidPin, OperationStatus::Error, ErrorCode::CredentialWrong);
    expectPair(CredentialOutcome::Blocked, OperationStatus::Error, ErrorCode::CredentialBlocked);
    expectPair(CredentialOutcome::PluginError, OperationStatus::Error, ErrorCode::CommunicationError);
    expectPair(CredentialOutcome::Unsupported, OperationStatus::Error, ErrorCode::CapabilityMissing);
    expectPair(CredentialOutcome::KeyActivationFailed, OperationStatus::Error, ErrorCode::CommunicationError);
    expectPair(CredentialOutcome::CardRemoved, OperationStatus::Error, ErrorCode::CardRemoved);
}

// Cancellation is expressed as an OperationStatus, never an ErrorCode: the
// UserCancelled row is the sole one that finishes non-Ok yet carries code None,
// mirroring the channel/read mappers' treatment of a user cancel.
TEST(CredentialErrorMapping, CancellationIsAStatusNotAnErrorCode)
{
    const CredentialFinish cancelled = errorCodeFor(CredentialOutcome::UserCancelled);
    EXPECT_EQ(cancelled.status, OperationStatus::Cancelled);
    EXPECT_EQ(cancelled.code, ErrorCode::None);
}

// KeyActivationFailed rides the coarse CommunicationError class on the wire; the
// verify-succeeded / activate-failed distinction crosses in the Result payload,
// not in this numeric code — so it must NOT map to a credential/auth code that
// would invite a client to re-prompt the (correct) PIN.
TEST(CredentialErrorMapping, KeyActivationFailedIsCommunicationErrorNotAuthClass)
{
    const CredentialFinish r = errorCodeFor(CredentialOutcome::KeyActivationFailed);
    EXPECT_EQ(r.status, OperationStatus::Error);
    EXPECT_EQ(r.code, ErrorCode::CommunicationError);
    EXPECT_NE(r.code, ErrorCode::CredentialWrong);
    EXPECT_NE(r.code, ErrorCode::AuthFailed);
}

// Ties the production mapper to the exhaustive compile-guarded oracle above: any
// member enumerated here must produce the same pair, and the oracle's no-default
// switch forces both to grow together.
TEST(CredentialErrorMapping, ProductionMapperMatchesExhaustiveOracle)
{
    for (const CredentialOutcome outcome : kAllOutcomes) {
        EXPECT_EQ(errorCodeFor(outcome), oracle(outcome)) << "outcome index " << static_cast<int>(outcome);
    }
}

TEST(CredentialErrorMapping, MapperIsNoexcept)
{
    static_assert(noexcept(errorCodeFor(CredentialOutcome::Ok)));
    SUCCEED();
}

// A default-constructed CredentialFinish must fail closed: an accidentally
// unassigned pair reads as an Error / CommunicationError, never a spurious
// Ok / None. Its members carry default initializers so value init is safe.
TEST(CredentialErrorMapping, DefaultConstructedFailsClosed)
{
    const CredentialFinish f{};
    EXPECT_EQ(f.status, OperationStatus::Error);
    EXPECT_EQ(f.code, ErrorCode::CommunicationError);
}
