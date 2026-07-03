// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/OperationPhase.h>
#include <cstdint>
#include <gtest/gtest.h>

using namespace LibreSCRS::Agent::Operations;

TEST(OperationPhase, WireValuesAreFrozen)
{
    // Must match org.librescrs.Agent.Operation1.xml — append-only.
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Created), 0u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Connecting), 1u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent), 2u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Authenticating), 3u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Reading), 4u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Signing), 5u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Timestamping), 6u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationPhase::Done), 7u);
}

TEST(OperationPhase, StatusWireValuesAreFrozen)
{
    EXPECT_EQ(static_cast<std::uint32_t>(OperationStatus::Ok), 0u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationStatus::Cancelled), 1u);
    EXPECT_EQ(static_cast<std::uint32_t>(OperationStatus::Error), 2u);
}
