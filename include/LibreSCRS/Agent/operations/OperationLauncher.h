// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/AgentCore.h> // ReaderCard
#include <LibreSCRS/Agent/Identity.h>  // CallerToken, OperationId
#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include <LibreSCRS/Agent/operations/ActivateSigningKeyOperation.h>
#include <LibreSCRS/Agent/operations/GetPhotoOperation.h>
#include <LibreSCRS/Agent/operations/ListCredentialsOperation.h>
#include <LibreSCRS/Agent/operations/ManagePinOperation.h>
#include <LibreSCRS/Agent/operations/ReadCertificatesOperation.h>
#include <LibreSCRS/Agent/operations/ReadIdentityOperation.h>
#include <LibreSCRS/Agent/operations/ReadTokenInfoOperation.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/operations/SignBatchOperation.h>
#include <LibreSCRS/Agent/operations/SignOperation.h>
#include <LibreSCRS/Agent/wire/SyncError.h>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>

/// @file
/// @brief One place where a card operation is assembled and queued, for every
///        host.
///
/// A host's request handler checks what only it can check (the card handle,
/// the capability bit, authorization, its own argument decoding), then hands
/// the launcher three things: where the operation runs and who asked
/// (`OperationTarget`), how to build the operation's result channel on its own
/// transport (`ChannelFactory`), and the arguments that belong to that one
/// operation (`OperationLauncher::Sign{params}` and so on). Everything else an
/// operation needs -- the prompter, the prompt gate, the caches, the seams, the
/// worker's session holder, the consent-prompt category, the keep-alives and
/// the shutdown binding -- comes from the core here, so a dependency added to
/// an operation is filled in one place, not once per host and operation.

namespace LibreSCRS::Plugin {
class CardPluginService;
}

namespace LibreSCRS::Agent::Operations {

/// The card-facing seams every operation drives. One bundle per launcher; each
/// launched operation co-owns the whole bundle, so an operation abandoned while
/// blocked (and detached past the host's teardown) never reaches a freed seam.
/// The production seams hold no per-card state, so one bundle serves every card.
struct OperationSeams
{
    std::shared_ptr<CardReader> reader;
    std::shared_ptr<CertificateReader> certReader;
    std::shared_ptr<TrustVerifier> trustVerifier;
    std::shared_ptr<Signer> signer;
    std::shared_ptr<CredentialManager> credentials;
    /// Optional: without a plugin registry there is nothing to deposit a
    /// passport MRZ into, and the launcher substitutes NullCredentialDepositor.
    std::shared_ptr<CredentialDepositor> depositor;

    /// The production seams over the middleware: the signer and the trust
    /// verifier share @p core's signing engine; the depositor is engaged only
    /// when @p plugins is given.
    [[nodiscard]] static OperationSeams production(AgentCore& core, LibreSCRS::Plugin::CardPluginService* plugins);
};

/// Where an operation runs and who asked for it, resolved by the host at its
/// method entry.
struct OperationTarget
{
    /// The reader worker, the PC/SC name its session opens, the card's cache
    /// key.
    ReaderCard card;
    /// The requesting client, registered for disconnect-cancel before the
    /// operation enters the queue. Empty: no auto-cancel.
    CallerToken caller;
    /// The client's best-effort label for the consent prompt.
    std::string requester;
};

class OperationLauncher
{
public:
    /// Builds the operation's result channel on the host's transport, for the
    /// minted id and over the state the operation shares with it. Called once
    /// per accepted launch, on the calling thread; never for a refused one. Must
    /// not return null.
    using ChannelFactory =
        std::function<std::unique_ptr<OperationChannel>(OperationId id, const std::shared_ptr<OperationState>& state)>;
    /// The new operation's id, or why it was refused: `RateLimited` when the
    /// reader's queue is full (retry later).
    using Launched = std::expected<OperationId, Wire::SyncError>;
    /// Receives the card type a completed identity read resolved, so the host
    /// can publish it. Empty: nobody listens.
    using CardTypeSink = std::function<void(const std::string& cardType)>;

    // The arguments that belong to one operation; everything else is the
    // launcher's. `Operation` names the operation each one launches.
    struct ReadIdentity
    {
        using Operation = ReadIdentityOperation;
        CardTypeSink onCardType;
    };
    struct GetPhoto
    {
        using Operation = GetPhotoOperation;
        CardTypeSink onCardType;
    };
    struct ReadCertificates
    {
        using Operation = ReadCertificatesOperation;
    };
    struct ReadTokenInfo
    {
        using Operation = ReadTokenInfoOperation;
    };
    struct Sign
    {
        using Operation = SignOperation;
        SignParams params;
    };
    struct SignBatch
    {
        using Operation = SignBatchOperation;
        SignParams params;
        std::vector<BatchDocumentInput> documents;
    };
    struct ListCredentials
    {
        using Operation = ListCredentialsOperation;
    };
    struct ManagePin
    {
        using Operation = ManagePinOperation;
        PinManageRequest request;
        CredentialSnapshot snapshot;
    };
    struct ActivateSigningKey
    {
        using Operation = ActivateSigningKeyOperation;
    };

    /// @p core outlives the launcher. @p seams must engage every seam but the
    /// depositor (std::invalid_argument otherwise). @p transportKeepAlive, when
    /// set, is co-owned by every launched operation: a host whose channels
    /// borrow a transport object (a bus connection) keeps it alive for an
    /// operation that outlives the host.
    OperationLauncher(AgentCore& core, OperationSeams seams, std::shared_ptr<void> transportKeepAlive = {});

    OperationLauncher(const OperationLauncher&) = delete;
    OperationLauncher& operator=(const OperationLauncher&) = delete;

    /// Build the operation on the reader's worker slot and queue it. The
    /// channel factory throwing propagates, and nothing is queued.
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, ReadIdentity args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, GetPhoto args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, ReadCertificates args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, ReadTokenInfo args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, Sign args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, SignBatch args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, ListCredentials args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel, ManagePin args);
    [[nodiscard]] Launched launch(const OperationTarget& target, const ChannelFactory& channel,
                                  ActivateSigningKey args);

    /// The dependencies launch() gives each operation, for the worker's
    /// @p holder. The one place they are assembled.
    [[nodiscard]] ReadIdentityOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                      ReadIdentity args) const;
    [[nodiscard]] GetPhotoOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                  GetPhoto args) const;
    [[nodiscard]] ReadCertificatesOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                          ReadCertificates args) const;
    [[nodiscard]] ReadTokenInfoOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                       ReadTokenInfo args) const;
    [[nodiscard]] SignOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                              Sign args) const;
    [[nodiscard]] SignBatchOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                   SignBatch args) const;
    [[nodiscard]] ListCredentialsOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                         ListCredentials args) const;
    [[nodiscard]] ManagePinOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                   ManagePin args) const;
    [[nodiscard]] ActivateSigningKeyOperation::Deps depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                            ActivateSigningKey args) const;

private:
    template <class Args>
    Launched launchOperation(const OperationTarget& target, const ChannelFactory& channel, Args args);

    AgentCore& m_core;
    std::shared_ptr<OperationSeams> m_seams;
    std::shared_ptr<void> m_transportKeepAlive;
};

} // namespace LibreSCRS::Agent::Operations
