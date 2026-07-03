// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-level check: every seam name resolves, every signature compiles,
// every method has exactly one virtual. Body of the test is a no-op.

#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>

#include <gtest/gtest.h>
#include <type_traits>

namespace {
using namespace LibreSCRS::Agent::Operations;
static_assert(std::is_abstract_v<CardReader>);
static_assert(std::is_abstract_v<PrompterClientBase>);
} // namespace

TEST(Seams, AllAbstractBasesCompile)
{
    SUCCEED();
}
