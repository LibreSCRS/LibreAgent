// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

// Programmable recording double over the frozen Authorizer policy gate. By
// default allows everything (allowAll = true); a test can flip allowAll off and
// list the exact action ids to permit via allow(). Every authorize() call is
// recorded as an (actionId, caller) pair for assertion.
struct FakeAuthorizer final : Authorizer
{
    bool allowAll{true};
    std::set<std::string> allowed;
    std::vector<std::pair<std::string, CallerToken>> calls;

    void allow(std::string_view actionId)
    {
        allowed.emplace(actionId);
    }

    [[nodiscard]] bool authorize(std::string_view actionId, const CallerToken& caller) override
    {
        calls.emplace_back(std::string(actionId), caller);
        if (allowAll) {
            return true;
        }
        return allowed.contains(std::string(actionId));
    }
};

} // namespace LibreSCRS::Agent
