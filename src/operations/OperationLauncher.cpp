// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/OperationArtifact.h>
#include <LibreSCRS/Agent/operations/OperationManager.h> // QueueFull
#include <stdexcept>
#include <utility>

namespace LibreSCRS::Agent::Operations {

OperationSeams OperationSeams::production(AgentCore& core, LibreSCRS::Plugin::CardPluginService* plugins)
{
    OperationSeams seams{
        .reader = std::make_shared<LmCardReader>(),
        .certReader = std::make_shared<LmCertificateReader>(),
        // Reuses the signing engine's own trust store rather than building a
        // second one.
        .trustVerifier = std::make_shared<LmTrustVerifier>(core.signingEngineProvider()),
        .signer = std::make_shared<LmSigner>(core.signingEngineProvider()),
        .credentials = std::make_shared<LmCredentialManager>(),
        .depositor = {},
    };
    // The deposit seam is the one read-path seam that needs the registry: only
    // the registry holds mutable handles to the plugins a renegotiated read
    // deposits the passport MRZ into.
    if (plugins != nullptr) {
        seams.depositor = std::make_shared<LmCredentialDepositor>(*plugins);
    }
    return seams;
}

namespace {

std::shared_ptr<OperationSeams> completeSeams(OperationSeams seams)
{
    if (!seams.reader || !seams.certReader || !seams.trustVerifier || !seams.signer || !seams.credentials) {
        throw std::invalid_argument{"OperationLauncher: every operation seam but the depositor is required"};
    }
    if (!seams.depositor) {
        seams.depositor = std::make_shared<NullCredentialDepositor>();
    }
    return std::make_shared<OperationSeams>(std::move(seams));
}

} // namespace

OperationLauncher::OperationLauncher(AgentCore& core, OperationSeams seams, std::shared_ptr<void> transportKeepAlive)
    : m_core(core), m_seams(completeSeams(std::move(seams))), m_transportKeepAlive(std::move(transportKeepAlive))
{}

template <class Args>
OperationLauncher::Launched OperationLauncher::launchOperation(const OperationTarget& target,
                                                               const ChannelFactory& channel, Args args)
{
    using Op = typename Args::Operation;
    // publish() moves the closure; the name it opens the worker's session with
    // is read into its own argument first.
    const std::string readerName = target.card.readerName;
    try {
        return m_core.operationManager().publish(
            target.card.readerId, readerName, target.caller,
            [this, &target, &channel, args = std::move(args)](
                CardSessionHolder* holder, OperationId id) mutable -> std::unique_ptr<OperationBase> {
                // The state exists before the channel, and the same share goes
                // to both, so a Cancel arriving before the operation is built
                // is never dropped.
                auto state = std::make_shared<OperationState>();
                auto opChannel = channel(id, state);
                if (!opChannel) {
                    throw std::logic_error{"OperationLauncher: the channel factory built no channel"};
                }
                auto op = std::make_unique<Op>(std::move(opChannel), depsFor(holder, target, std::move(args)), state);
                // An operation abandoned while blocked in a prompt outlives the
                // host's composition. It co-owns everything its unwind may
                // touch -- the core members (through the crypto-worker
                // context), the seams it drives, and the host's transport --
                // and on shutdown it bails at its flow's gate and skips its
                // wire completion.
                op->keepAlive(m_core.sharedCryptoContext());
                op->keepAlive(m_seams);
                op->keepAlive(m_transportKeepAlive);
                op->bindShutdownToken(m_core.shutdownToken());
                return op;
            });
    } catch (const QueueFull&) {
        return std::unexpected{Wire::SyncError::RateLimited};
    }
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      ReadIdentity args)
{
    return launchOperation(target, channel, std::move(args));
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      GetPhoto args)
{
    return launchOperation(target, channel, std::move(args));
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      ReadCertificates args)
{
    return launchOperation(target, channel, args);
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      ReadTokenInfo args)
{
    return launchOperation(target, channel, args);
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      Sign args)
{
    return launchOperation(target, channel, std::move(args));
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      SignBatch args)
{
    return launchOperation(target, channel, std::move(args));
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      ListCredentials args)
{
    return launchOperation(target, channel, args);
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      ManagePin args)
{
    return launchOperation(target, channel, std::move(args));
}

OperationLauncher::Launched OperationLauncher::launch(const OperationTarget& target, const ChannelFactory& channel,
                                                      ActivateSigningKey args)
{
    return launchOperation(target, channel, args);
}

ReadIdentityOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                       ReadIdentity args) const
{
    return {
        .holder = holder,
        .reader = *m_seams->reader,
        .depositor = *m_seams->depositor,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credentials = m_core.credentialCache(),
        .readCache = m_core.cardReadCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kIdentity},
        .onCardType = std::move(args.onCardType),
    };
}

GetPhotoOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                   GetPhoto args) const
{
    return {
        .holder = holder,
        .reader = *m_seams->reader,
        .depositor = *m_seams->depositor,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credentials = m_core.credentialCache(),
        .readCache = m_core.cardReadCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kPhoto},
        .onCardType = std::move(args.onCardType),
    };
}

ReadCertificatesOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                           ReadCertificates /*args*/) const
{
    return {
        .holder = holder,
        .certReader = *m_seams->certReader,
        .trustVerifier = *m_seams->trustVerifier,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credentials = m_core.credentialCache(),
        .readCache = m_core.cardReadCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kCertificates},
    };
}

ReadTokenInfoOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                        ReadTokenInfo /*args*/) const
{
    return {
        .holder = holder,
        .reader = *m_seams->reader,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credentials = m_core.credentialCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kTokenInfo},
    };
}

SignOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                               Sign args) const
{
    return {
        .holder = holder,
        .signer = *m_seams->signer,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credentials = m_core.credentialCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .params = std::move(args.params),
    };
}

SignBatchOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                    SignBatch args) const
{
    return {
        .holder = holder,
        .signer = *m_seams->signer,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credentials = m_core.credentialCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .params = std::move(args.params),
        .documents = std::move(args.documents),
    };
}

ListCredentialsOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                          ListCredentials /*args*/) const
{
    return {
        .holder = holder,
        .credentials = *m_seams->credentials,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credCache = m_core.credentialCache(),
        .snapshotCache = m_core.credentialSnapshotCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kCredentials},
    };
}

ManagePinOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                    ManagePin args) const
{
    return {
        .holder = holder,
        .credentials = *m_seams->credentials,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credCache = m_core.credentialCache(),
        .snapshotCache = m_core.credentialSnapshotCache(),
        .readCache = m_core.cardReadCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kCredentials},
        .request = std::move(args.request),
        .snapshot = std::move(args.snapshot),
    };
}

ActivateSigningKeyOperation::Deps OperationLauncher::depsFor(CardSessionHolder* holder, const OperationTarget& target,
                                                             ActivateSigningKey /*args*/) const
{
    return {
        .holder = holder,
        .credentials = *m_seams->credentials,
        .prompter = *m_core.prompter(),
        .serializer = m_core.promptSerializer(),
        .credCache = m_core.credentialCache(),
        .snapshotCache = m_core.credentialSnapshotCache(),
        .readCache = m_core.cardReadCache(),
        .cardKey = target.card.cardKey,
        .readerName = target.card.readerName,
        .requester = target.requester,
        .artifact = std::string{Artifact::kCredentials},
    };
}

} // namespace LibreSCRS::Agent::Operations
