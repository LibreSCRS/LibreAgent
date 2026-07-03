// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <LibreSCRS/CancelToken.h>
#include <memory>

namespace LibreSCRS::Agent {

// Held only as shared_ptr-to-forward-declared: a zombie worker co-owns these two
// for keep-alive but never dereferences them (the signing engine is reached
// through the LM-signer seam, the config through that engine), so this header
// stays free of the config / signing-engine includes. The full headers are pulled
// in only where the shares are populated (the AgentCore ctor).
namespace Config {
class ConfigStore;
}
namespace Operations {
class SigningEngineProvider;
}

// One owning bundle of everything a crypto worker that outlives the AgentCore
// aggregate may touch as a core member on unblock. A private-key / read op runs
// on a per-reader worker that can BLOCK in an uncancellable call (the consent
// prompt, the held-session acquire, the on-card terminal op); if the backend is
// torn down while that worker is parked, the worker is abandoned to the
// process-lifetime zombie list and outlives the composition that owned its
// collaborators. Every worker closure that can outlive the aggregate
// value-captures a shared_ptr to THIS context, so on unblock it touches only
// memory it co-owns — never a freed member.
//
// Collapsing the four separately co-owned handles into one context makes the
// invariant "everything a zombie may touch lives here" structural: one capture
// per closure instead of four, no transitive-capture reasoning, and a future
// worker path is safe by construction (it captures the same whole context). The
// members:
//   * prompter    — the blocking consent/CAN/MRZ call itself (and, through the
//                   prompter client, its backing bus connection);
//   * serializer  — the single-live-prompt gate; its SlotGuard unwind locks +
//                   notifies unconditionally on any live-process unblock;
//   * credentials — a nested CAN/MRZ prompt writes putCan/putMrz, and a raw
//                   AuthFailed unwind invalidates it, both past the flow gate;
//   * lease       — the login grant + the PIN-verified-state marks reached past
//                   the flow gate (the broker's PIN-state callbacks and the
//                   login continuation co-own this same share);
//   * shutdown    — the agent-wide shutdown-cancel token; a worker that unblocks
//                   after teardown began returns Cancelled at its flow's
//                   post-prompt gate and skips its wire completion where it can,
//                   so it never drives a torn-down reply channel / broker.
//   * config      — the signing-config SSOT; an abandoned qualified-timestamped
//                   sign worker unblocks into recordLastTsaUrl on it (below the
//                   flow's post-return token gate), so it must outlive the zombie;
//   * signingEngine — the immutable engine provider the LM-signer seam holds by
//                   reference; the abandoned sign worker unblocks into snapshot()
//                   at entry and recordLastTsaUrlUsed at success-exit through it,
//                   so it too must outlive the zombie. Its own ConfigStore& is the
//                   `config` share above, so recordLastTsaUrl is safe. Declared
//                   after `config` so it is destroyed BEFORE the config it borrows.
struct CryptoWorkerContext
{
    std::shared_ptr<Operations::PrompterClientBase> prompter;
    std::shared_ptr<Operations::PromptSerializer> serializer;
    std::shared_ptr<CredentialCache> credentials;
    std::shared_ptr<Pkcs11::LeaseManager> lease;
    LibreSCRS::CancelToken shutdown;
    std::shared_ptr<Config::ConfigStore> config;
    std::shared_ptr<Operations::SigningEngineProvider> signingEngine;
};

} // namespace LibreSCRS::Agent
