// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/SyncError.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QList>
#include <QObject>
#include <QRectF>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVariantMap>

#include <memory>
#include <optional>

/// @file
/// @brief Top-level agent client: owns the transport, watches agent
///        availability, and maintains the reader/card registry from the
///        agent's discovery surface.

namespace LibreSCRS::AgentClient {

class AgentOperation;
class TransportSeam;
struct ClientTestAccess;

/// @brief Connection + discovery for the card agent.
///
/// Single responsibility: own the transport, track agent availability,
/// populate the `AgentReader`/`AgentCard` registries from the agent's
/// discovery snapshot + live add/remove notifications, and emit
/// `readersChanged` / `cardChanged` / `availabilityChanged`. The transport
/// (D-Bus on Linux) is an internal detail — nothing transport-specific
/// appears on this surface.
class LIBRESCRS_AGENTCLIENT_EXPORT AgentClient : public QObject
{
    Q_OBJECT
public:
    /// @brief Constructs a client, runs a bounded synchronous probe of agent
    ///        availability, and — if reachable — populates the initial
    ///        reader/card registry before returning; both are already valid
    ///        via `isAvailable()` / `readers()` on the very next line. Live
    ///        subscriptions are also armed here, so a later appear/vanish or
    ///        registry change is observed via `availabilityChanged` /
    ///        `readersChanged` / `cardChanged` without polling. Most
    ///        consumers should prefer `sharedAgentClient()` over
    ///        constructing directly, so the process establishes one
    ///        connection.
    /// @param parent Standard QObject ownership parent, or nullptr.
    explicit AgentClient(QObject* parent = nullptr);
    ~AgentClient() override;

    AgentClient(const AgentClient&) = delete;
    AgentClient& operator=(const AgentClient&) = delete;

    /// @brief Whether the agent is currently reachable.
    [[nodiscard]] bool isAvailable() const;

    /// @brief Whether an agent is INSTALLED on this system (reachable now, or
    ///        startable on demand), even if not currently running — the
    ///        "install the agent" vs "start a card operation" empty-state
    ///        split. A bounded probe; never hangs.
    [[nodiscard]] bool agentInstalled() const;

    /// @brief Manually re-run discovery: re-probe agent availability (in case
    ///        a liveness notification was missed) and re-populate the
    ///        reader/card registry from a fresh snapshot. This is the client
    ///        path behind a GUI refresh affordance: it recovers from a dropped
    ///        card-added notification (a card the agent exported but this
    ///        client never saw) and reconciles availability if the agent
    ///        reappeared silently. Fires `availabilityChanged` only on an
    ///        actual flip and always ends with `readersChanged` so consumers
    ///        recompute.
    void refreshDiscovery();

    /// @brief All tracked readers in DETERMINISTIC id-sorted order (never
    ///        hash iteration order) — the shared ordering primitive for
    ///        every roster a consumer renders.
    [[nodiscard]] QList<AgentReader*> readers() const;
    /// @brief The tracked reader with @p readerId, or nullptr.
    [[nodiscard]] AgentReader* reader(const QString& readerId) const;
    /// @brief The tracked card with @p cardId, or nullptr.
    [[nodiscard]] AgentCard* card(const QString& cardId) const;

    /// @brief Fetch a certificate's raw DER — the agent's public-data
    ///        primitive (no consent, no lease). Addressed by the reader
    ///        holding the card (@p readerId) plus @p certId (from
    ///        `CertificateInfo::id`). Asynchronous: returns a non-null
    ///        operation (parented to this client) whose
    ///        `certificateDerResult()` is valid after `finished()`.
    [[nodiscard]] AgentOperation* certificateDer(const QString& readerId, const QString& certId);

    /// @brief The optional request/property families the CURRENTLY connected
    ///        agent advertises (empty before the agent is reachable, and for
    ///        an agent that predates this discovery surface — never an
    ///        error; see `hasFeature()` for the common membership check).
    [[nodiscard]] QStringList features() const;
    /// @brief Whether the agent advertises @p token (`features().contains(token)`).
    [[nodiscard]] bool hasFeature(const QString& token) const;

    /// @brief The connected agent's version string (`Manager1.Version` on
    ///        D-Bus; the socket handshake's `HelloAck.agentVer`). Cached per
    ///        connection. Empty while no agent is reachable or against an
    ///        agent predating the surface — never an error.
    ///
    ///        "Per connection" is the whole lifetime rule: the string is
    ///        forgotten when the connection is lost and re-read from the
    ///        next one, so it always describes the agent answering NOW.
    ///        Treat it as a DISPLAY datum only (an About box, a support
    ///        report). It is a free-form string the agent chooses — never
    ///        parse it to decide what the agent can do; that is what
    ///        `hasFeature()` is for.
    [[nodiscard]] QString agentVersion() const;

    /// @brief Snapshot of the agent's `Config1` property set, key → value —
    ///        the agent-owned, operation-affecting settings (signature level,
    ///        TSA, trusted lists, cache dirs, plugin dir). All NON-secret:
    ///        a PIN/CAN/MRZ is never configuration and never appears here.
    ///
    ///        Keys use the wire spellings: `"DefaultLevel"`, `"TsaUrls"`,
    ///        `"LastTsaUrl"`, `"TslSources"`, `"TslCacheDir"`,
    ///        `"AiaCacheDir"`, `"DefaultReason"`, `"DefaultLocation"`,
    ///        `"PluginDir"`. Values are `QString` except `"TsaUrls"`
    ///        (`QStringList`) and `"TslSources"`, which is a `QVariantList`
    ///        of three-entry `QVariantList`s —
    ///        `[QString url, bool isLotl, bool eager]`. That one shape is a
    ///        CLIENT guarantee, identical on every transport, even though the
    ///        wires carry it differently.
    ///
    ///        Cached per connection and refreshed before `configChanged()`
    ///        announces a key, so reading this from that signal's slot always
    ///        sees the new value. EMPTY while no agent is reachable — a dead
    ///        agent's settings are never served as if they were live — and
    ///        empty against an agent that does not expose the interface.
    ///        Never an error.
    [[nodiscard]] QVariantMap configSnapshot() const;

    /// @brief Write one agent setting (`Config1.SetValue` / socket
    ///        `SetConfig`). Synchronous and bounded; disengaged on success.
    ///
    ///        Only five keys are writable — `"DefaultLevel"`,
    ///        `"DefaultReason"`, `"DefaultLocation"`, `"TsaUrls"`,
    ///        `"TslSources"`. The rest are read-only by design (a
    ///        wire-settable `"PluginDir"` would be a code-execution vector,
    ///        and `"LastTsaUrl"` is agent-internal state), and writing one
    ///        answers `SyncError::ReadOnlyConfig`.
    ///
    ///        A returned error is always NAMED, so a caller can act on WHICH
    ///        refusal it was:
    ///          - `UnknownConfigKey`   no such setting;
    ///          - `ReadOnlyConfig`     the setting is not client-writable;
    ///          - `InvalidConfigValue` the agent rejected @p value;
    ///          - `NotAuthorized`      the user declined, or policy denied,
    ///                                 the authorization this key needs (the
    ///                                 trust-tier keys `"TsaUrls"` and
    ///                                 `"TslSources"` prompt for it);
    ///          - `CommunicationError` the write never REACHED the agent
    ///                                 (unreachable, timed out, no reply) —
    ///                                 the one case worth retrying, and the
    ///                                 reason this is a named enumerator
    ///                                 rather than a bool.
    ///        Both transports report the identical enumerator for the
    ///        identical key, though they may decide it in different places.
    ///
    /// @param value Must match the key's type as documented on
    ///        `configSnapshot()` above; a `"TslSources"` row that is not a
    ///        three-entry list is dropped from the write.
    [[nodiscard]] std::optional<SyncError> setConfigValue(const QString& key, const QVariant& value);

    /// @brief Restore one setting to the agent's built-in default
    ///        (`Config1.Reset` / socket `ResetConfig`). Same synchronous,
    ///        named-refusal contract as `setConfigValue()` above, including
    ///        the read-only gate — a setting a client may not write is not
    ///        one it may reset either.
    [[nodiscard]] std::optional<SyncError> resetConfigValue(const QString& key);

    /// @brief Card-independent, synchronous visible-signature layout preview
    ///        (`Manager1.LayoutVisualSignature` / socket `"LayoutVisual"`) —
    ///        no card, no `AgentOperation`, just a bounded round-trip. This
    ///        is the PIXEL-PARITY primitive a preview renderer must use:
    ///        a GUI client's preview text layout is defined to equal exactly
    ///        this call's result, which in turn is exactly what a subsequent
    ///        `AgentCard::sign()` with the same @p text / @p box would stamp
    ///        (both sides call through the same agent-side computation).
    ///
    ///        Gated on the `"layout-preview"` feature token: when the
    ///        connected agent does not advertise it (including "no agent
    ///        connected at all"), this returns `std::nullopt` WITHOUT ever
    ///        dialing the wire — the same local-refusal posture
    ///        `AgentCard::sign()` applies to `tsaUrl`/`visualSignature`, only
    ///        without an `AgentOperation` to fail (there is none here to
    ///        mint). A `nullopt` therefore covers three distinct causes
    ///        (capability absent, no agent, or a genuine call
    ///        failure/entry rejection) — callers that need to tell them
    ///        apart should check `hasFeature("layout-preview")` first.
    /// @param text UTF-8 text to lay out (the same text a subsequent `sign()`
    ///        call's `SignOptions::visualSignature` would carry).
    /// @param box The placement rectangle, PDF user units (the same
    ///        coordinate space as `SignOptions::visualSignature`'s box). A
    ///        box too small to fit even the floor font size is still a VALID
    ///        call — the result's `clipped` becomes `true`.
    [[nodiscard]] std::optional<LayoutResult> layoutVisualSignature(const QString& text, QRectF box) const;

    /// @brief The embedded appearance font (Liberation Sans Regular TTF)
    ///        every agent-rendered visible signature uses
    ///        (`Manager1.GetAppearanceFont` / socket `"GetAppearanceFont"`),
    ///        cached per connection. A preview renderer loads this SAME font
    ///        so its glyph metrics agree with `layoutVisualSignature()`'s
    ///        line breaks and with the font PAdES actually embeds.
    ///
    ///        Same `"layout-preview"` gate as `layoutVisualSignature()`
    ///        above: an invalid handle (`FdHandle::valid() == false`) means
    ///        either the gate refused locally or the fetch itself failed —
    ///        never a thrown error.
    [[nodiscard]] FdHandle appearanceFont() const;

Q_SIGNALS:
    /// @brief The agent appeared/vanished.
    ///
    /// Consumers MUST treat `availabilityChanged(false)` as "all cards and
    /// readers are gone": on agent loss the registry is cleared and only
    /// `readersChanged()` + `availabilityChanged(false)` fire — there is NO
    /// per-card `cardChanged()` for each dropped card (the whole tree vanishes
    /// at once, so per-id notifications would be redundant). UI that tracks
    /// individual card ids must drop them all on this signal.
    void availabilityChanged(bool available);
    /// @brief The reader/card roster ITSELF changed — a reader or card was
    ///        added or removed, including as the reconcile outcome of
    ///        `refreshDiscovery()` (fired even when a re-scan finds nothing
    ///        new, so consumers always recompute after asking). Contrast
    ///        `cardChanged()`, which fires for a property change on an
    ///        object already in the roster. Re-fetch `readers()` on this
    ///        signal rather than diffing incrementally.
    void readersChanged();
    /// @brief The card situation behind one registry object changed: a card
    ///        appeared/vanished (@p objectId is the card id) or a reader's
    ///        tracked properties changed (@p objectId is the reader id).
    void cardChanged(const QString& objectId);
    /// @brief One agent setting changed — from THIS client's own
    ///        `setConfigValue()`/`resetConfigValue()`, from another client's,
    ///        or from the agent itself (it records `"LastTsaUrl"` after a
    ///        timestamped signature).
    ///
    /// Carries only @p key: read the value from `configSnapshot()`, which is
    /// already refreshed when this fires. Declared LAST on purpose — a signal
    /// appended after the existing ones keeps every earlier signal's moc
    /// index stable, so an already-compiled consumer keeps working.
    void configChanged(const QString& key);

private:
    friend struct ClientTestAccess; // internal: inject a TransportSeam in tests

    AgentClient(std::unique_ptr<TransportSeam> transport, QObject* parent);

    void onServiceRegistered();
    void onServiceUnregistered();
    void repopulate();
    void clearRegistry();
    void addReader(const QString& readerId, const QVariantMap& props);
    void addCard(const QString& cardId, const QVariantMap& props);
    /// Terminalize any in-flight op on the card @p cardId (loud finished),
    /// then delete it and emit cardChanged. Shared by a live removal
    /// notification and repopulate's reconcile (a card a fresh snapshot no
    /// longer reports), so a going-away card never leaks a hung operation.
    void removeCard(const QString& cardId);
    /// Delete the reader @p readerId. Emits nothing — the caller batches a
    /// single readersChanged (a live removal fires one; a reconcile fires one
    /// at the end).
    void removeReader(const QString& readerId);

    struct Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
