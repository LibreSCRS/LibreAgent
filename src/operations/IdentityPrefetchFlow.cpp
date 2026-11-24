// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/IdentityPrefetchFlow.h"
#include "operations/FlowPrelude.h"
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // identityCandidates
#include <LibreSCRS/Logging.h>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

IdentityPrefetchFlow::Result failed(ErrorCode code)
{
    return {.outcome = FlowOutcome::Error, .code = code, .snapshot = std::nullopt};
}

IdentityPrefetchFlow::Result cancelled()
{
    return {.outcome = FlowOutcome::Cancelled, .code = ErrorCode::None, .snapshot = std::nullopt};
}

} // namespace

IdentityPrefetchFlow::IdentityPrefetchFlow(IdentityPrefetchFlowDeps deps) : m_deps(std::move(deps)) {}

IdentityPrefetchFlow::Result IdentityPrefetchFlow::run()
{
    // Metadata only, never a field of the snapshot.
    log::infof("identity prefetch: reader=\"{}\" card={}", m_deps.readerName, m_deps.cardKey);

    auto opened = FlowPrelude::openSession(m_deps.holder, m_deps.token);
    if (opened.status == FlowPrelude::OpenStatus::Cancelled) {
        return cancelled();
    }
    if (opened.status != FlowPrelude::OpenStatus::Ok) {
        return failed(opened.code);
    }
    const auto idCands = identityCandidates(opened.candidates);

    // Always refuses a secret: LM asks the provider only on a PACE-cache miss,
    // so a secret a user's operation already left in this session is still
    // used, while nothing is ever prompted for or cached here.
    const auto providerGuard =
        FlowPrelude::installScopedReadProvider(opened.session, &FlowPrelude::noCredentialsProvider);

    auto read = m_deps.reader.read(*opened.session, idCands, m_deps.token, {});

    // A cancelled prefetch (reader removed, agent stopping) must hand nothing
    // to its caller, whatever the read returned.
    if (read.status == ReadOutcome::Status::Cancelled || m_deps.token.isCancelled()) {
        return cancelled();
    }
    if (read.status != ReadOutcome::Status::Ok || !read.snapshot) {
        // No clearCachedPaceCredentials here: this flow handed over no secret,
        // and the session may hold one a user's own operation established.
        return failed(FlowPrelude::mapReadStatus(read.status));
    }
    if (m_deps.onCardType && !read.snapshot->cardType.empty()) {
        m_deps.onCardType(read.snapshot->cardType);
    }
    return {.outcome = FlowOutcome::Ok, .code = ErrorCode::None, .snapshot = std::move(read.snapshot)};
}

} // namespace LibreSCRS::Agent::Operations
