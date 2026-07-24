// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/wire/ErrorCode.h>
#include <LibreSCRS/Agent/OperationPhase.h>
#include <gtest/gtest.h>
TEST(WireHeaders, WireFrozenPins)
{
    using LibreSCRS::Agent::ErrorCode;
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::None), 0u);
    EXPECT_EQ(static_cast<std::uint32_t>(ErrorCode::InvalidDocument), 19u);
}
