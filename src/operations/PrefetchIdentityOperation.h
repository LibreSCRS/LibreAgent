// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <functional>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

// The background read of a freshly published card's identity. Nobody asked for
// it and nobody waits on it: its channel drops every emission, it sets no phase
// (so no watchdog is armed on it) and its only effect is a put into the card's
// read cache. Never prompts, never touches the secret cache.
class PrefetchIdentityOperation final : public OperationBase
{
public:
    struct Deps
    {
        CardSessionHolder* holder{nullptr};
        CardReader& reader;
        CardReadCache& readCache;
        std::string cardKey;
        std::string readerName;
        std::function<void(const std::string&)> onCardType;
    };

    explicit PrefetchIdentityOperation(Deps deps);

protected:
    void doWork() override;

private:
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
