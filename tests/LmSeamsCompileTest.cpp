// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only smoke: every Lm seam derives from the matching abstract
// base. Behaviour exercised against a real card by the E2E task.

#include <LibreSCRS/Agent/operations/LmSeams.h>

#include <gtest/gtest.h>
#include <type_traits>

namespace {
using namespace LibreSCRS::Agent::Operations;
static_assert(std::is_base_of_v<CardReader, LmCardReader>);
static_assert(std::is_base_of_v<CertificateReader, LmCertificateReader>);
} // namespace

TEST(LmSeams, AllConcretesCompileAndDerive)
{
    SUCCEED();
}
