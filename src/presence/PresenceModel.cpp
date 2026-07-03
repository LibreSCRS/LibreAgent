// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

PresenceModel::PresenceModel(ObjectRegistry& registry, CapabilityResolver& resolver)
    : m_registry(registry), m_resolver(resolver)
{}

ObjectId PresenceModel::readerIdFor(const std::string& name) const
{
    auto it = m_readerIds.find(name);
    return it == m_readerIds.end() ? ObjectId{} : it->second;
}

ObjectId PresenceModel::cardIdFor(const std::string& readerName) const
{
    auto it = m_cardIds.find(readerName);
    return it == m_cardIds.end() ? ObjectId{} : it->second;
}

void PresenceModel::onReaderAdded(const std::string& readerName)
{
    if (m_readerIds.contains(readerName)) {
        return;
    }
    const ObjectId id{++m_nextId};
    m_readerIds[readerName] = id;
    m_registry.addReader(ReaderState{.id = id, .name = readerName, .hasCard = false, .card = {}});
}

void PresenceModel::onReaderRemoved(const std::string& readerName)
{
    // Drop any card on the reader first so observers see consistent ordering.
    onCardRemoved(readerName);
    auto it = m_readerIds.find(readerName);
    if (it == m_readerIds.end()) {
        return;
    }
    m_registry.remove(it->second);
    m_readerIds.erase(it);
}

void PresenceModel::onCardInserted(const std::string& readerName, const std::vector<std::uint8_t>& atr)
{
    if (!m_readerIds.contains(readerName)) {
        onReaderAdded(readerName);
    }
    if (m_cardIds.contains(readerName)) {
        onCardRemoved(readerName);
    }
    const ObjectId cardId{++m_nextId};
    m_cardIds[readerName] = cardId;

    // Resolve capabilities from the ATR alone — no CardSession is opened on the
    // monitor thread. The per-reader worker-held session is the sole opener; the
    // union of the ATR-matched candidate plugin(s)' declared capabilities is
    // enough to publish a correct, fail-closed Card1.Capabilities synchronously.
    std::uint32_t caps = 0;
    if (auto plugin = m_resolver.resolvePlugin(atr)) {
        const Operations::CandidateList candidates{std::move(plugin)};
        caps = Operations::unionCapabilities(candidates);
    } else {
        log::infof("no plugin matched for reader {} (ATR fast-path miss)", readerName);
    }
    // Pre-read auth requires a live session (CardPlugin::preReadAuth(session)), so
    // it cannot be resolved here without opening one. Publish the pending None
    // token; the per-reader worker resolves and republishes it on the held
    // session.
    const auto preReadAuth = LibreSCRS::Auth::PreReadAuthMethod::None;

    const ObjectId readerId = m_readerIds.at(readerName);
    m_registry.addCard(CardState{.id = cardId, .reader = readerId, .capabilities = caps, .preReadAuth = preReadAuth});

    // Make the parent reader's HasCard/Card live: the transport backend emits
    // a properties-changed notification so clients observing Reader1 see the
    // insert without re-walking the object tree.
    m_registry.update(readerId, PropertyDelta{.hasCard = true, .card = cardId});
}

void PresenceModel::onCardRemoved(const std::string& readerName)
{
    auto it = m_cardIds.find(readerName);
    if (it == m_cardIds.end()) {
        return;
    }
    m_registry.remove(it->second);
    m_cardIds.erase(it);

    // Reset the parent reader's HasCard/Card so a client observing Reader1 sees
    // the removal. No-op when the reader is no longer registered (onReaderRemoved
    // drops the card first, then the reader → the update lands on an invalid id).
    auto rit = m_readerIds.find(readerName);
    m_registry.update(rit == m_readerIds.end() ? ObjectId{} : rit->second, PropertyDelta{.hasCard = false, .card = {}});
}

} // namespace LibreSCRS::Agent
