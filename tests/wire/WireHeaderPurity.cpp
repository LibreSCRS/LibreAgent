// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Isolation proof for tests/wire/CMakeLists.txt's WireHeaderPurityCheck
// target: this TU is compiled with an include path of ONLY this repo's
// include/ dir (see that file) and links nothing at all, so a passing build
// is direct evidence these two headers pull in zero external dependencies —
// not even GTest's INTERFACE include dirs, which is what let a prior version
// of this proof (WireHeadersTest alone) go unnoticed when GTest::gtest's
// resolved package happened to add an LM install prefix to the compile line.
#include <LibreSCRS/Agent/wire/ErrorCode.h>
#include <LibreSCRS/Agent/OperationPhase.h>

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationStatus;

static_assert(static_cast<std::uint32_t>(ErrorCode::None) == 0u);
static_assert(static_cast<std::uint32_t>(ErrorCode::InvalidDocument) == 19u);
static_assert(static_cast<std::uint32_t>(OperationStatus::Cancelled) == 1u);
