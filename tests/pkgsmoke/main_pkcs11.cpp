// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Does an installed LibreAgent CONFIG package resolve COMPONENTS Pkcs11Facade,
// and are its public headers actually in the install tree? Both are answered by
// this file compiling and linking; it runs so a broken archive shows up as a
// failure rather than as a file nobody opened.

#include <LibreSCRS/Agent/pkcs11/ObjectModel.h>

int main()
{
    // An empty snapshot is a legitimate one: no readers, therefore no slots.
    const auto model = LibreSCRS::Pkcs11Agent::ObjectModel::build({});
    return model.slots.empty() ? 0 : 1;
}
