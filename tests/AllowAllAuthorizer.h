// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <string_view>

namespace LibreSCRS::Agent {

// Grants every action to every caller. A TEST double, shipped with the test
// support component and never with the agent API: no host runs without a
// policy gate, so an authority that approves everything has no place in the
// headers a host is built from.
class AllowAllAuthorizer final : public Authorizer
{
public:
    [[nodiscard]] AuthorizationOutcome authorize(std::string_view /*actionId*/, const CallerToken& /*caller*/) override
    {
        return AuthorizationOutcome::Granted;
    }
};

} // namespace LibreSCRS::Agent
