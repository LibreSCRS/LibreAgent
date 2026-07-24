// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
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
    /// @brief The reader's friendly name.
    [[nodiscard]] QString name() const;
    /// @brief Whether the agent reports a card seated in this reader.
    [[nodiscard]] bool hasCard() const;
    /// @brief Opaque id of the seated card, or empty.
    [[nodiscard]] QString cardId() const;
    /// @brief The seated card's live proxy, resolved through the owning
    ///        client's registry — nullptr while no card is present or before
    ///        the card object has been discovered.
    [[nodiscard]] AgentCard* card() const;

Q_SIGNALS:
    /// @brief A tracked reader property changed (name, card presence).
    void changed();

private:
    friend class AgentClient; // constructs/primes registry entries

    AgentReader(TransportSeam* transport, AgentClient* client, const QString& id, QObject* parent);

    /// @brief Seed properties from a discovery snapshot map (avoids a
    ///        round-trip when discovery already carried them).
    void primeFrom(const QVariantMap& reader1Props);

    struct Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
