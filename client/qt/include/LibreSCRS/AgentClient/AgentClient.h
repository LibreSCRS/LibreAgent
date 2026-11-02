// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/QuiesceReason.h>
#include <LibreSCRS/AgentClient/AgentCard.h>
#include <LibreSCRS/AgentClient/AgentReader.h>
#include <LibreSCRS/AgentClient/Export.h>
#include <LibreSCRS/AgentClient/FdHandle.h>
#include <LibreSCRS/AgentClient/SyncError.h>
#include <LibreSCRS/AgentClient/Types.h>

#include <QList>
#include <QLocale>
#include <QObject>
#include <QRectF>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVariantMap>

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>

/// @file
/// @brief Top-level agent client: owns the transport, watches agent
///        availability, and maintains the reader/card registry from the
///        agent's discovery surface.

namespace LibreSCRS::AgentClient {

class AgentOperation;

/// @brief Why the agent quiesced card access -- the agent's own wire
///        vocabulary, re-exported so a client names it without reaching into
///        the agent's headers. See `AgentClient::quiesced()`.
///
/// @since 5.0
using LibreSCRS::Agent::QuiesceReason;

/// @brief What asking for the agent to be started achieved
///        (`AgentClient::requestAgentStart()`).
enum class AgentStartResult : std::uint8_t {
    Running,           ///< The agent is reachable now (it already was, or it was started and answered).
    Requested,         ///< The platform was asked to start it; `refreshDiscovery()` picks it up once it is up.
    NotInstalled,      ///< Nothing on this system can start an agent: it has to be installed first.
    NotInApplications, ///< macOS only: the agent's host app exists only outside an Applications
                       ///< folder (a mounted disk image, Downloads), where it cannot register the agent.
    Failed,            ///< An agent is installed, but starting it did not succeed.
};

/// @brief Whether there is an agent, and whether it runs
///        (`AgentClient::agentState()`).
enum class AgentState : std::uint8_t {
    Ready,   ///< The agent is reachable.
    Stopped, ///< An agent is installed but not running; `requestAgentStart()` can start it.
    Missing, ///< No agent is installed: point the user at `AgentClient::installHelpUrl()`.
};

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
    ///        split. `agentState() != AgentState::Missing`; no I/O.
    [[nodiscard]] bool agentInstalled() const;

    /// @brief The agent's state as this client last learned it, without asking
    ///        anyone: it is safe to call from any signal handler, as often as a
    ///        view repaints. Learned at construction, kept current by the
    ///        agent appearing and vanishing, and re-learned by
    ///        `refreshDiscovery()` and by every call that starts the agent — so
    ///        an agent installed while the client runs reads as `Missing`
    ///        until the user's next "try again".
    [[nodiscard]] AgentState agentState() const;

    /// @brief Where a user learns how to install the agent on this platform,
    ///        in @p locale's language when the guide has it (Serbian, either
    ///        script, gets the Serbian page; everything else English).
    [[nodiscard]] static QString installHelpUrl(const QLocale& locale = QLocale());

    /// @brief Manually re-run discovery: re-probe agent availability (in case
    ///        a liveness notification was missed) and re-populate the
    ///        reader/card registry from a fresh snapshot. This is the client
    ///        path behind a GUI refresh affordance: it recovers from a dropped
    ///        card-added notification (a card the agent exported but this
    ///        client never saw) and reconciles availability if the agent
    ///        reappeared silently. Fires `availabilityChanged` only on an
    ///        actual flip and ends with `readersChanged` so consumers
    ///        recompute. Called while a start is already in flight, it adds
    ///        nothing and returns at once: that start reports the outcome.
    ///
    ///        This is also the one place a GUI's "try again" gesture starts
    ///        the agent: an agent that is installed but not running is started
    ///        first (see `requestAgentStart()`), exactly like a configuration
    ///        call or a certificate fetch does. Construction never starts it —
    ///        merely creating a client, as a panel does at login, must not
    ///        bring up a service nobody asked for.
    ///
    ///        It waits on the agent in local event loops, and whatever those
    ///        loops deliver -- the agent coming up, a card inserted -- reaches
    ///        this client's signals before it returns. A control whose view
    ///        those signals can replace (a QML item behind a Loader) must call
    ///        `refreshDiscoveryLater()` instead.
    void refreshDiscovery();

    /// @brief `refreshDiscovery()`, run from the event loop once the caller
    ///        has returned — the form for the handler of a control that the
    ///        outcome may destroy.
    ///
    ///        A deferred delete posted while a local event loop delivers an
    ///        event runs in the next local loop of the same call stack, so a
    ///        view swapped while the refresh waits would be deleted under the
    ///        handler that asked for it. Run from the event loop, the refresh
    ///        has no caller frame beneath its waits. The outcome arrives as
    ///        `refreshDiscovery()` reports it: `availabilityChanged`,
    ///        `configChanged` and `readersChanged`, or, when a start was
    ///        already in flight, whatever that start reports. Asking again
    ///        before that refresh has ended asks for nothing more.
    ///
    /// @since 5.0
    void refreshDiscoveryLater();

    /// @brief Start the agent if it is installed but not running.
    ///
    ///        Linux: the agent is a D-Bus-activatable session service; this
    ///        asks the bus to start it and waits (bounded) for it to answer,
    ///        so `Running` means it is reachable on return and the registry is
    ///        already populated. macOS: the agent is a launchd job the LibreMac
    ///        host app registers; this launches that app in the background and
    ///        kicks the job, and answers `Requested` — call
    ///        `refreshDiscovery()` once the agent has had time to come up.
    ///
    ///        Every other agent-addressed call in this class (configuration,
    ///        certificate fetch, layout preview, and `refreshDiscovery()`)
    ///        runs the same start first, so a consumer needs this only for an
    ///        explicit "start the service" control.
    ///
    ///        One start at a time: the wait runs a local event loop, and a
    ///        call that arrives from it (a second click, a timer) starts
    ///        nothing and answers `Requested`; the start in flight reports
    ///        the outcome through the usual signals. A control whose view the
    ///        agent's arrival can replace must call `requestAgentStartLater()`
    ///        instead (see `refreshDiscoveryLater()` for why).
    AgentStartResult requestAgentStart();

    /// @brief `requestAgentStart()`, run from the event loop once the caller
    ///        has returned — the form for a "start the service" control that
    ///        the agent's arrival may destroy. Its result arrives as
    ///        `agentStartFinished()`; asking again before then asks for
    ///        nothing more, and that one signal answers both.
    ///
    /// @since 5.0
    void requestAgentStartLater();

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
    ///        `"LastTsaUrl"`, `"TslSources"`, `"CscaSources"`,
    ///        `"CscaAnchorState"`, `"TslCacheDir"`, `"AiaCacheDir"`,
    ///        `"DefaultReason"`, `"DefaultLocation"`, `"PluginDir"`. Values
    ///        are `QString` except `"TsaUrls"` (`QStringList`), the two source
    ///        lists (each a `QVariantList` of fixed-width `QVariantList`
    ///        rows) and `"CscaAnchorState"` (a `QVariantMap`):
    ///          - `"TslSources"`  three entries,
    ///            `[QString url, bool isLotl, bool eager]`;
    ///          - `"CscaSources"` TWO entries, `[QString uri, bool eager]` —
    ///            no `isLotl` twin, because a country-signing source names
    ///            anchors and never further sources;
    ///          - `"CscaAnchorState"` what the agent currently HOLDS in
    ///            country-signing trust anchors — the same report
    ///            `importCscaMasterList()` returns, readable without having
    ///            performed an import, which is what lets a just-started
    ///            client say what is installed instead of that it cannot be
    ///            known. Members, all optional and ABSENT (never zeroed) when
    ///            the agent did not send them:
    ///              * `"anchors"`             `quint32` — anchors held,
    ///                INCLUDING CSCA link certificates, so not a root count;
    ///              * `"issuers"`             `quint32` — distinct issuing
    ///                countries among them;
    ///              * `"replayRefusalActive"` `bool` — whether a rollback can
    ///                be refused at all. Its FALSE is the value worth showing:
    ///                it means the accepted list carried no signing time, so
    ///                "is this older than what I have" cannot be answered;
    ///              * `"signer"`              `QString` — lowercase hex
    ///                SHA-256 over the publisher's SubjectPublicKeyInfo;
    ///              * `"signerPinned"`        `bool` — the publisher was
    ///                ESTABLISHED, not merely observed. Rendering
    ///                "authenticity verified" over a false claims more than
    ///                was measured;
    ///              * `"acceptedAt"`          `qint64` epoch seconds — when
    ///                the AGENT accepted the list;
    ///              * `"signedAt"`            `qint64` epoch seconds — when
    ///                the list says it was signed. ABSENT when it carried no
    ///                CMS signingTime; there is no epoch sentinel, so an
    ///                undated list never reads as one signed in 1970;
    ///              * `"origin"`              `QString` — where the anchors
    ///                came from (`"import"`).
    ///            An EMPTY map means nothing has been imported. A member this
    ///            build does not name is passed through verbatim.
    ///        Those shapes are a CLIENT guarantee, identical on every
    ///        transport, even though the wires carry them differently.
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
    ///        Only six keys are writable — `"DefaultLevel"`,
    ///        `"DefaultReason"`, `"DefaultLocation"`, `"TsaUrls"`,
    ///        `"TslSources"`, `"CscaSources"`. The rest are read-only by
    ///        design (a wire-settable `"PluginDir"` would be a code-execution
    ///        vector, `"LastTsaUrl"` is agent-internal state, and a writable
    ///        `"CscaAnchorState"` would let a client CLAIM what passports are
    ///        checked against without installing an anchor), and writing one
    ///        answers `SyncError::ReadOnlyConfig`.
    ///
    ///        A returned error is always NAMED, so a caller can act on WHICH
    ///        refusal it was:
    ///          - `UnknownConfigKey`   no such setting;
    ///          - `ReadOnlyConfig`     the setting is not client-writable;
    ///          - `InvalidConfigValue` the agent rejected @p value;
    ///          - `NotAuthorized`      the user declined, or policy denied,
    ///                                 the authorization this key needs (the
    ///                                 trust-tier keys `"TsaUrls"`,
    ///                                 `"TslSources"` and `"CscaSources"`
    ///                                 prompt for it);
    ///          - `CommunicationError` the write never REACHED the agent
    ///                                 (unreachable, timed out, no reply) —
    ///                                 the one case worth retrying, and the
    ///                                 reason this is a named enumerator
    ///                                 rather than a bool.
    ///        Both transports report the identical enumerator for the
    ///        identical key, though they may decide it in different places.
    ///
    /// @param key Wire spelling of the setting, exactly as `configSnapshot()`
    ///        above lists it. A key outside that vocabulary answers
    ///        `UnknownConfigKey` and one outside the six writable ones
    ///        answers `ReadOnlyConfig`; neither writes anything.
    /// @param value Must match the key's type as documented on
    ///        `configSnapshot()` above; a row of the wrong width is dropped
    ///        from the write (a `"TslSources"` row that is not three entries,
    ///        a `"CscaSources"` row that is not two).
    [[nodiscard]] std::optional<SyncError> setConfigValue(const QString& key, const QVariant& value);

    /// @brief Restore one setting to the agent's built-in default
    ///        (`Config1.Reset` / socket `ResetConfig`). Same synchronous,
    ///        named-refusal contract as `setConfigValue()` above, including
    ///        the read-only gate — a setting a client may not write is not
    ///        one it may reset either.
    [[nodiscard]] std::optional<SyncError> resetConfigValue(const QString& key);

    /// @brief Install country-signing (CSCA) trust anchors from a signed ICAO
    ///        master list (`Config1.ImportCscaMasterList` / socket
    ///        `ImportCscaMasterList`). Synchronous and bounded; the accepted
    ///        anchor state on success, else the NAMED refusal.
    ///
    ///        The agent needs the trust-tier authorization for this — the same
    ///        one the `"TsaUrls"` / `"TslSources"` / `"CscaSources"` writes
    ///        need, and for a stronger version of the same reason: an import
    ///        does not name a place anchors may come from, it INSTALLS the
    ///        concrete anchors passports will be accepted or refused against.
    ///        A user who declines, or a policy that denies, is
    ///        `SyncError::NotAuthorized`.
    ///
    ///        The accepted anchors REPLACE the cached set rather than merging
    ///        into it: a master list is a complete statement of what its
    ///        publisher vouches for, so merging would keep anchors it has
    ///        withdrawn. Nothing about the file is remembered as a SOURCE to
    ///        fetch from later — that is what the `"CscaSources"` setting is
    ///        for; this is a one-shot input.
    ///
    ///        Refusals worth branching on:
    ///          - `MasterListReplayed`   the list is authentic and NOT newer
    ///                                   than the one installed (older, dated
    ///                                   the same, or undated while the
    ///                                   installed one is dated). Nothing was
    ///                                   installed and nothing already held was
    ///                                   given up — the case a person can act
    ///                                   on ("you already have this one");
    ///          - `NotAuthorized`        declined or denied;
    ///          - `RateLimited`          this caller is over budget;
    ///          - `InvalidRequest`       not a regular file, or unreadable;
    ///          - `InputTooLarge`        past the agent's size bound;
    ///          - `CommunicationError`   the import never REACHED the agent
    ///                                   (unreachable, timed out, no reply) —
    ///                                   the one case worth retrying.
    ///        The agent also names several "this file is not a usable master
    ///        list" refusals (not a master list, empty, malformed, bad
    ///        signature, a publisher it does not follow, an unwritable anchor
    ///        cache). Those are outside the closed `SyncError` vocabulary and
    ///        arrive as `CommunicationError`, the same degrade an unrecognised
    ///        name gets on either wire; a caller renders them as "this file
    ///        could not be installed" and offers a different file.
    ///
    /// @param masterListFd An OPEN descriptor for the master list, BORROWED —
    ///        this call duplicates it for the wire and never closes yours, so
    ///        closing it stays your job. A descriptor and not a path because
    ///        the agent is a separate, possibly sandboxed process: a name it
    ///        would have to re-open is a name it may not be able to open, and
    ///        would resolve a second time what you already resolved once.
    ///
    ///        One consequence follows from what a descriptor IS and is worth
    ///        knowing before you reuse yours: what crosses the wire refers to
    ///        the SAME open file description as yours, so the agent's read
    ///        ADVANCES YOUR FILE POSITION. Rewind (or re-open) before reading
    ///        the same descriptor yourself afterwards.
    [[nodiscard]] std::expected<CscaAnchorState, SyncError> importCscaMasterList(int masterListFd);

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
    /// already refreshed when this fires. An EMPTY @p key means every setting
    /// may have changed: the agent has just become reachable, so a snapshot
    /// taken while it was not (an empty one) must be read again. Appended
    /// after the existing signals on purpose — that keeps every earlier
    /// signal's moc index stable, so an already-compiled consumer keeps
    /// working.
    void configChanged(const QString& key);
    /// @brief The agent quiesced card access: the holder's session went away
    ///        (the machine sleeps, the user switched away, the screen locked)
    ///        or the agent is stopping.
    ///
    /// By then the agent has forgotten what @p reason calls for: on
    /// `SystemSleep`, `SessionInactive` and `Shutdown` every cached CAN/MRZ,
    /// every card session and every PKCS#11 login; on `ScreenLocked` the
    /// PKCS#11 logins only. The next operation asks again. A reason this
    /// build does not name arrives verbatim.
    ///
    /// Over the socket the agent also counts as unavailable from here until
    /// `refreshDiscovery()` finds it answering again (`availabilityChanged`
    /// follows this signal); over D-Bus the agent stays available. Appended
    /// after the signals declared before it, like `configChanged()`, to keep
    /// their indices.
    ///
    /// @since 5.0
    void quiesced(LibreSCRS::AgentClient::QuiesceReason reason);
    /// @brief What the start `requestAgentStartLater()` asked for answered,
    ///        exactly as `requestAgentStart()` would have returned it.
    ///
    /// `Requested` does not end the start: on macOS the agent comes up later
    /// (see `requestAgentStart()`), and when another start was already in
    /// flight, that start reports its outcome through the usual signals
    /// (`availabilityChanged` once the agent is up). Appended after the
    /// signals declared before it, like `configChanged()`, to keep their
    /// indices.
    ///
    /// @since 5.0
    void agentStartFinished(LibreSCRS::AgentClient::AgentStartResult result);

private:
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

    struct LIBRESCRS_AGENTCLIENT_NO_EXPORT Private;
    std::unique_ptr<Private> d;
};

} // namespace LibreSCRS::AgentClient
