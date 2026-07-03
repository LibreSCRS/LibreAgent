// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Minimal downstream consumer: includes a public core header via its installed
// path and exercises a frozen value type. Success proves the installed CONFIG
// package's include and link interfaces are self-consistent.
#include <LibreSCRS/Agent/Identity.h>

int main()
{
    const LibreSCRS::Agent::ObjectId id{42};
    return id == LibreSCRS::Agent::ObjectId{42} ? 0 : 1;
}
