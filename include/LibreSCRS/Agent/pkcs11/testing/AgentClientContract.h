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
// STATUS: declared, not yet populated. The body is blocked on a wire question
// that is not this header's to answer: the socket transport has no name for
// "the user cancelled the prompt", so the two transports cannot yet be held to
// one claim about it. Until that is settled the suite would have to encode a
// guess about whether the difference is a defect or a contract.

#pragma once

#include <LibreSCRS/Agent/pkcs11/AgentClient.h>
