// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-time proof, built with every build: the public LmSeams.h does not
// pull in the middleware's certificate definitions, which the core links
// privately. A host including it must not inherit that dependency.

#include <LibreSCRS/Agent/operations/LmSeams.h>

namespace {
template <typename T>
concept Complete = requires { sizeof(T); };
} // namespace

static_assert(!Complete<LibreSCRS::Certificate::ParsedCertificate>,
              "LmSeams.h must declare ParsedCertificate, not include its definition");
