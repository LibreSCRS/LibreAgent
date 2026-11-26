// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <functional>
#include <memory>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;
class GroupRelay;
class IdentityGroupFeed;

class ReadIdentityOperation final : public OperationBase
{
public:
    struct Deps
    {
        // Per-reader shared-session holder, injected by OperationManager from the
        // worker that serialises this reader's ops (single-threaded; no locking).
        CardSessionHolder* holder{nullptr};
        CardReader& reader;
        // Deposits a holder-chosen passport MRZ into the candidate plugins when
        // the flow renegotiates a CAN prompt into an MRZ read (see
        // IdentityReadFlowDeps::depositor). Bound by CardObject from the
        // per-card seam bundle.
        CredentialDepositor& depositor;
        PrompterClientBase& prompter;
        // Agent-wide single-live-prompt gate (see IdentityReadFlowDeps).
        PromptSerializer& serializer;
        CredentialCache& credentials;
        CardReadCache& readCache;
        std::string cardKey;
        // Human reader name (e.g. "Yubico YubiKey ..."), used by the
        // OperationManager to lazily build this reader's CardSessionHolder, and
        // forwarded into IdentityReadFlowDeps::readerName for the flow's
        // per-request audit line (the flow never uses it to open anything --
        // the holder owns the open).
        std::string readerName;
        // Caller-identity chrome for the consent prompt: the requesting
        // client's best-effort label and the artifact being read ("identity").
        // Resolved at the host's method entry; client-supplied, may be empty.
        std::string requester;
        std::string artifact;
        // Fired with a completed read's CardData::cardType (via
        // IdentityReadFlowDeps::onCardType) so the caller can push the
        // host's authoritative card-type update through its property-update
        // path. Default (unset): a no-op, for tests with no such path.
        std::function<void(const std::string&)> onCardType;
    };

    ReadIdentityOperation(std::unique_ptr<OperationChannel> channel, Deps deps, std::shared_ptr<OperationState> state);
    ~ReadIdentityOperation() override;

    // Queued behind the background read of THIS card: follow its groups. Returns
    // the parked relay it attached through (and writes the audit line for that
    // source), or null for another card, a feed that is not open, or an op that
    // already follows one. Emits nothing; the manager releases the relay once the
    // client can receive. See OperationBase::followIdentityGroupFeed.
    [[nodiscard]] std::shared_ptr<GroupRelay> followIdentityGroupFeed(IdentityGroupFeed& feed) override;
    [[nodiscard]] std::shared_ptr<GroupRelay> groupRelay() const noexcept override;

protected:
    void doWork() override;

private:
    Deps m_deps;
    // Set once, under the worker's mutex, before the op is visible to any other
    // thread; the paths that end a queued op read it after taking the op out under
    // that same mutex.
    std::shared_ptr<GroupRelay> m_relay;
};

} // namespace LibreSCRS::Agent::Operations
