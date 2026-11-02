// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/ReaderInterface.h>
#include <LibreSCRS/AgentClient/Export.h>

#include <QObject>
#include <QString>
#include <QVariantMap>

#include <memory>

/// @file
/// @brief Typed live proxy for one agent-exported reader.

namespace LibreSCRS::AgentClient {

class AgentCard;
class AgentClient;
class TransportSeam;

/// @brief Which physical interface a reader is -- the agent's own wire
///        vocabulary, shared rather than re-declared here.
using LibreSCRS::Agent::Wire::ReaderInterface;

/// @brief Live proxy for one reader the agent exports. Tracks name / card
///        presence live; emits `changed` on any update.
class LIBRESCRS_AGENTCLIENT_EXPORT AgentReader : public QObject
{
    Q_OBJECT
public:
    ~AgentReader() override;

    AgentReader(const AgentReader&) = delete;
    AgentReader& operator=(const AgentReader&) = delete;

    /// @brief Opaque reader id — a cross-wire token; compare and pass back
    ///        as-is (e.g. to `AgentClient::certificateDer()`), never parse.
    [[nodiscard]] QString id() const;
    /// @brief The reader's raw PC/SC name. Shown to nobody as is: model()
    ///        and interface() are its label.
    [[nodiscard]] QString name() const;
    /// @brief The reader's short model as the agent labels it ("OMNIKEY
    ///        5422"), carrying no interface wording; name() when the agent
    ///        sent no label. Two readers that would read alike carry a short
    ///        serial suffix, so a label built from model() and interface()
    ///        tells every reader apart. May change while the reader stays
    ///        (another reader arrived or left): `changed` fires.
    [[nodiscard]] QString model() const;
    /// @brief Which physical interface the reader is, for the client to say
    ///        in the holder's language; ReaderInterface::Unknown when the
    ///        agent sent none or one this build does not know.
    [[nodiscard]] ReaderInterface interface() const;
    /// @brief Whether the agent reports a card seated in this reader.
    [[nodiscard]] bool hasCard() const;
    /// @brief Opaque id of the seated card, or empty.
    [[nodiscard]] QString cardId() const;
    /// @brief The seated card's live proxy, resolved through the owning
    ///        client's registry — nullptr while no card is present or before
    ///        the card object has been discovered.
    [[nodiscard]] AgentCard* card() const;

Q_SIGNALS:
    /// @brief A tracked reader property changed (name, label, card presence).
    void changed();

private:
    friend class AgentClient; // constructs/primes registry entries

    AgentReader(TransportSeam* transport, AgentClient* client, const QString& id, QObject* parent);

    /// @brief Seed properties from a discovery snapshot map (avoids a
    ///        round-trip when discovery already carried them).
    void primeFrom(const QVariantMap& reader1Props);

    struct LIBRESCRS_AGENTCLIENT_NO_EXPORT Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
