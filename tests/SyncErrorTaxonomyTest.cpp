// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one table both hosts use to name the wire error a refusal goes out as.
// Each table below lists EVERY enumerator, in declaration order, and the test
// checks that it does: an outcome appended upstream fails here until somebody
// decides what it means on the wire, instead of falling silently to the
// generic error.
#include <LibreSCRS/Agent/value/SyncErrorTaxonomy.h>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <utility>

namespace {

using LibreSCRS::Agent::EntryError;
using LibreSCRS::Agent::Pkcs11Broker;
using LibreSCRS::Agent::toSyncError;
using LibreSCRS::Agent::Wire::SyncError;

template <typename E, std::size_t N>
void expectEveryEnumeratorInOrder(const std::array<std::pair<E, SyncError>, N>& table, E last)
{
    ASSERT_EQ(N, static_cast<std::size_t>(last) + 1) << "an enumerator is missing from the table";
    for (std::size_t i = 0; i < N; ++i) {
        EXPECT_EQ(static_cast<std::size_t>(table[i].first), i) << "row " << i << " is out of order";
        EXPECT_EQ(static_cast<int>(toSyncError(table[i].first)), static_cast<int>(table[i].second)) << "row " << i;
    }
}

TEST(SyncErrorTaxonomy, EveryCryptoOutcomeHasItsWireError)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    constexpr std::array table{
        std::pair{CO::Ok, SyncError::CommunicationError}, // not an error: fails closed
        std::pair{CO::Cancelled, SyncError::Cancelled},
        std::pair{CO::KeyNotFound, SyncError::KeyNotFound},
        std::pair{CO::AuthFailed, SyncError::AuthFailed},
        std::pair{CO::NotSupported, SyncError::NotSupported},
        std::pair{CO::CardError, SyncError::CommunicationError},
        std::pair{CO::UnknownCard, SyncError::UnknownCard},
        std::pair{CO::UserNotLoggedIn, SyncError::UserNotLoggedIn},
        std::pair{CO::RateLimited, SyncError::RateLimited},
        std::pair{CO::InvalidInput, SyncError::InvalidRequest},
    };
    expectEveryEnumeratorInOrder(table, CO::InvalidInput);
}

TEST(SyncErrorTaxonomy, EveryLoginOutcomeHasItsWireError)
{
    using LO = Pkcs11Broker::LoginOutcome;
    constexpr std::array table{
        std::pair{LO::Ok, SyncError::CommunicationError}, // not an error: fails closed
        std::pair{LO::Cancelled, SyncError::Cancelled},
        std::pair{LO::NotAuthorizedByCard, SyncError::AuthFailed},
        std::pair{LO::CardError, SyncError::CommunicationError},
        std::pair{LO::UnknownCard, SyncError::UnknownCard},
        std::pair{LO::NotAuthorized, SyncError::NotAuthorized},
    };
    expectEveryEnumeratorInOrder(table, LO::NotAuthorized);
}

TEST(SyncErrorTaxonomy, OnlyAnUnknownCredentialIsNotAMalformedRequest)
{
    constexpr std::array table{
        std::pair{EntryError::UnknownVerb, SyncError::InvalidRequest},
        std::pair{EntryError::UnknownOption, SyncError::InvalidRequest},
        std::pair{EntryError::UnknownCredential, SyncError::UnknownCredential},
        std::pair{EntryError::InvalidCombination, SyncError::InvalidRequest},
        std::pair{EntryError::AmbiguousCredential, SyncError::InvalidRequest},
    };
    expectEveryEnumeratorInOrder(table, EntryError::AmbiguousCredential);
}

} // namespace
