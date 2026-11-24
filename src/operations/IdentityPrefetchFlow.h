// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/FlowOutcome.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/CancelToken.h>
#include <functional>
#include <optional>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

// Deliberately has no prompter, no prompt gate and no credential cache: the
// background read must never raise a window, wait behind another reader's
// prompt, or record a refusal against a secret it never asked for.
struct IdentityPrefetchFlowDeps
{
    CardSessionHolder& holder;
    CardReader& reader;
    std::string cardKey;
    // Only for the audit line.
    std::string readerName;
    LibreSCRS::CancelToken token;
    // Fired with the read's card type on success, as IdentityReadFlowDeps does.
    std::function<void(const std::string&)> onCardType;
};

// Reads a card's identity on the held session with a provider that always
// refuses a secret. It never reuses IdentityReadFlow: that flow installs an
// interactive provider and, on AuthFailed, evicts the cached secret and clears
// the session's PACE state -- both would destroy what a user's own operation
// left in the same held session.
class IdentityPrefetchFlow
{
public:
    struct Result
    {
        FlowOutcome outcome{FlowOutcome::Error};
        ErrorCode code{ErrorCode::CommunicationError};
        std::optional<CardReadSnapshot> snapshot;
    };

    explicit IdentityPrefetchFlow(IdentityPrefetchFlowDeps deps);
    [[nodiscard]] Result run();

private:
    IdentityPrefetchFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
