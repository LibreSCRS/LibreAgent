// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/AgentClient/AgentReader.h>

#include <LibreSCRS/AgentClient/AgentClient.h>

#include "TransportSeam.h"

namespace LibreSCRS::AgentClient {

// The lifted live-proxy property discipline, verbatim behind the seam:
//   - NO ctor full fetch: AgentClient::addReader always calls primeFrom()
//     right after construction with the full property map from discovery, so
//     a cold-start fetch would be a redundant round-trip.
//   - The transport ships full new values in the `changed` map, so they apply
//     directly — no per-property round-trips. Only a property the transport
//     declared stale WITHOUT a value (`invalidated`) triggers the single
//     asynchronous full refresh.
//   - The generation counter keeps a stale in-flight fetch from clobbering
//     newer state, and a fetch superseded by a direct apply re-issues itself
//     so the invalidated property still converges.
struct AgentReader::Private final : public PropertyListener
{
    AgentReader* q;
    TransportSeam* transport;
    AgentClient* client;
    QString id;

    /// Version counter for the cached properties. Every direct apply
    /// (primeFrom / a changed map) and every new refresh request bumps it; a
    /// fetched reply whose captured generation no longer matches is stale
    /// (newer state landed while it was in flight) and is discarded.
    quint64 propsGeneration = 0;
    /// The single in-flight refresh token, or 0.
    quint64 fetchToken = 0;
    quint64 fetchGeneration = 0;

    QString name;
    bool hasCard = false;
    QString cardId;

    Private(AgentReader* owner, TransportSeam* t, AgentClient* c, QString objectId)
        : q(owner), transport(t), client(c), id(std::move(objectId))
    {}

    /// Apply a property subset (from `changed`, a full fetch, or discovery)
    /// onto the cached fields. Keys are the canonical seam vocabulary.
    void applyProps(const QVariantMap& props)
    {
        if (props.contains(QStringLiteral("Name"))) {
            name = props.value(QStringLiteral("Name")).toString();
        }
        if (props.contains(QStringLiteral("HasCard"))) {
            hasCard = props.value(QStringLiteral("HasCard")).toBool();
        }
        if (props.contains(QStringLiteral("Card"))) {
            cardId = props.value(QStringLiteral("Card")).toString();
        }
    }

    /// Non-blocking full-property refresh (the `invalidated` fallback).
    /// Supersedes any refresh still in flight (only the newest snapshot
    /// request may apply); the reply lands on this object's thread.
    void refreshAll()
    {
        fetchGeneration = ++propsGeneration;
        fetchToken = transport->requestProperties(id, ObjectKind::Reader, this);
    }

    void onPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated) override
    {
        // Direct apply is the newest known state: bump the generation so a
        // fetch still in flight cannot clobber it when its older reply lands.
        ++propsGeneration;
        applyProps(changed);
        if (!invalidated.isEmpty()) {
            refreshAll();
        }
        Q_EMIT q->changed();
    }

    void onPropertiesFetched(quint64 token, const std::optional<QVariantMap>& properties) override
    {
        if (token != fetchToken) {
            return; // superseded by a newer refresh — its reply drives us
        }
        fetchToken = 0;
        if (fetchGeneration != propsGeneration) {
            // Stale: a DIRECT apply raced this refresh with no successor fetch
            // behind it — the invalidated property that motivated this fetch
            // has not converged. Re-issue under the newest generation so it
            // does; otherwise it would keep its pre-invalidation value until
            // the next unrelated signal.
            refreshAll();
            return;
        }
        if (!properties) {
            return; // fetch failed or timed out — leave cached values
        }
        applyProps(*properties);
        Q_EMIT q->changed();
    }
};

AgentReader::AgentReader(TransportSeam* transport, AgentClient* client, const QString& id, QObject* parent)
    : QObject(parent), d(std::make_unique<Private>(this, transport, client, id))
{
    transport->subscribeProperties(id, ObjectKind::Reader, d.get());
}

AgentReader::~AgentReader()
{
    d->transport->unsubscribeProperties(d->id, d.get());
}

QString AgentReader::id() const
{
    return d->id;
}

QString AgentReader::name() const
{
    return d->name;
}

bool AgentReader::hasCard() const
{
    return d->hasCard;
}

QString AgentReader::cardId() const
{
    return d->cardId;
}

AgentCard* AgentReader::card() const
{
    return d->cardId.isEmpty() ? nullptr : d->client->card(d->cardId);
}

void AgentReader::primeFrom(const QVariantMap& reader1Props)
{
    // Discovery-fresh data: bump the generation so a fetch still in flight
    // cannot overwrite this newer state when its older reply lands.
    ++d->propsGeneration;
    d->applyProps(reader1Props);
}

} // namespace LibreSCRS::AgentClient
