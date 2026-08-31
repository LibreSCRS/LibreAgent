# LibreAgent Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 4.3.0

A never-configured installation now seeds a working timestamp-authority
and trusted-list configuration on first start. Startup stays
network-free (no seeded list is fetched eagerly), but the first DEFAULT
signature on a fresh installation changes shape: with timestamp
authorities configured, an auto-level sign resolves to B-T, so it is
timestamped and contacts a seeded TSA at signing time.

First public release of LibreAgent: the platform-neutral, Qt-free core
of the LibreSCRS smart-card agent, the shared wire vocabulary both of
its transports speak, and the Qt client library desktop frontends use to
talk to it. Platform hosts (LibreLinux today, a macOS host to follow)
build on the core to provide the per-user card broker without
re-implementing the neutral state machine; GUI clients build on the Qt
client library instead of re-implementing an agent protocol per desktop.

Three targets ship, each independently usable:

| Target | Links | For |
| --- | --- | --- |
| `LibreAgent::Core` | LibreMiddleware, OpenSSL | platform hosts |
| `LibreAgent::Wire` | nothing first-party | anything speaking the agent wire |
| `LibreAgent::ClientQt` | Qt6 | Qt/KDE desktop clients |

### Added

- **Platform-neutral agent core.** A single static library
  (`LibreAgent::Core`) owning the backend-agnostic agent logic every
  host needs: reader/card presence tracking, a bounded operation
  scheduler, read and credential caches, the PKCS#11 lease/broker
  model, and the LibreMiddleware-backed card flows (identity, photo and
  certificate reads plus AdES / raw-crypto signing). The core links no
  D-Bus, systemd, polkit or Qt.
- **Five backend interfaces** through which a host plugs in its IPC and
  desktop stack: `Prompter` (PIN / CAN / MRZ collection, returning a
  cleansing secret rather than a raw fd), `Authorizer` (per-operation
  gate, with a fail-closed default shipped in-tree), `AgentTransport`,
  `OperationChannel`, and `LogSink`.
- **Stable error taxonomy** carried on each finished operation. Codes
  are wire-frozen and append-only so clients can branch on the numeric
  value across releases. This release adds two signing-related codes:
  `EngineUnavailable` (the signing engine or security module could not
  be loaded — a deployment problem) and `InvalidDocument` (the document
  submitted for signing is invalid or unreadable — a client-input
  problem), each distinct from a generic engine failure so clients can
  give the user an accurate, actionable message.
- **Certificate read caching per card insertion**, so repeated
  certificate reads within a single card session avoid redundant card
  I/O; the cache is bound to the card's presence.
- **Card credential management.** Beyond reading and signing, the core
  can enumerate a card's PINs and keys together with their current state
  — retry counts, whether a PIN is still in transport state or has been
  blocked, and whether a signing key is awaiting activation — and can
  change a card PIN. The same surface additionally exposes unblocking a
  blocked PIN and activating a dormant signing key for cards and plugins
  that support them; on the hardware supported in this release those
  requests return an unsupported result. Each operation collects the
  PIN(s) it needs through the prompter and never caches them. When a card
  reports that a blocked PIN or a dormant key can only be recovered
  through the card issuer, that guidance is forwarded to the client so
  the user learns the correct next step.
- **Shared wire vocabulary** (`LibreAgent::Wire`): the message types,
  canonical CBOR codec and framing both agent transports carry, plus the
  frozen error vocabularies — the numeric operation taxonomy and the
  named synchronous-method vocabulary — so a host and a client cannot
  drift apart on what a message or a refusal means. It links nothing
  first-party, so a consumer that only needs to speak the protocol takes
  on neither LibreMiddleware nor Qt.
- **A sign request may defer the conformance level to the agent**, and
  that is what `SignOptions` does by default (`SignatureLevel::Auto`).
  The agent then applies the level it is configured with, including that
  value's upgrade to a timestamped one when a timestamp authority is
  set. Naming a level overrides the deployment's own policy, which is
  occasionally right and easy to do by accident: a client that always
  asked for the baseline produced baseline signatures everywhere,
  successfully and silently, no matter how the site was configured. To
  ask for a specific level anyway, set it: `options.level =
  SignatureLevel::BB`. `Auto` is request-only — a result always reports
  the level actually produced and never reports `Auto`.
- **Qt client library** (`LibreAgent::ClientQt`): a transport-neutral,
  typed client for Qt/KDE desktop frontends. It exposes the agent as
  live `AgentClient` / `AgentReader` / `AgentCard` / `AgentOperation`
  objects — reader and card discovery with live add/remove, the card
  read/sign/credential operations with typed results, and the
  no-consent public-data fetches. It is written against an internal
  transport seam with two implementations, D-Bus and the AF_UNIX socket
  wire, so no transport type appears anywhere in the public API.
  **This release's public API picks the transport per platform and
  offers no way to override it** — `AgentClient` has a single
  constructor, which builds the D-Bus transport on Linux and the
  App-Group socket transport on macOS; a platform with neither yet gets
  an inert client that is never available. Every call that reaches the
  agent is bounded by a call-timeout budget, so a slow or wedged agent
  cannot hang a caller indefinitely; the budget is 3 s by default, so a
  synchronous call is bounded rather than instant. Public value types
  are plain Qt/std aggregates, and file descriptors cross the boundary
  as a move-only owning handle rather than a raw `int`.
- **The Qt client can now reach the agent on macOS.** Building for
  macOS previously left `AgentClient` with no transport at all, so a
  Qt application reported itself permanently unavailable and read no
  cards. It now opens the same App-Group socket connection the macOS
  agent host listens on, the same way the Linux build already opens a
  D-Bus connection — no application code changes to pick it up.
- **Country-signing (CSCA) trust-anchor import is platform-neutral.**
  Turning a signed ICAO master list into trust anchors — and the
  trust-on-first-use, signer-pinning and rotation judgement that
  decides whether a later list should be believed — now lives in the
  shared agent core instead of a single platform host, so every host
  applies the same policy against a travel document's issuing country
  rather than each carrying its own copy that could quietly disagree.
- **Best-effort certificate cache warm** (`AgentCard::warmCertificates()`):
  asks the agent to pre-read a card's certificates so a later real read
  finds them warm, for frontends that can predict a read shortly before
  it happens. It returns immediately whatever state the agent is in,
  mints nothing to observe or cancel, debounces itself, and reports no
  outcome — a warm that did not happen simply leaves the next read to
  pay the cold cost it would have paid anyway. On a transport that
  cannot express it without stranding agent-side state it is a no-op,
  which no consumer needs to handle: correctness never depends on a warm
  having happened.

### Changed

- **Minimum CMake is now 3.28** (was 3.24), for
  `FetchContent_Declare(... EXCLUDE_FROM_ALL)` — which is what keeps the
  vendored QCBOR dependency's own install rules out of the installed
  tree. Consumers building against an older CMake must upgrade.

### Security

- **Secrets never outlive the card.** The credential cache holds no
  PIN by construction, and both the read cache and credential cache are
  scrubbed the moment the card is removed. Collected secrets use
  cleansing storage that zeroizes on drop, and cached read data is
  zeroized on drop as well.
- **Bounded, rate-limited operation scheduling** with watchdog-driven
  cancellation and a per-reader backlog cap, so a misbehaving or
  hostile client cannot exhaust the agent.
- **Exclusive card-access arbitration** between the agent's own flows
  and external PKCS#11 clients via the lease/broker model, with the
  first PKCS#11 cold-lease PIN prompt rate-limited.

### Packaging

- **Installed CONFIG package** with three components — `Core`, `Wire`
  and `ClientQt`. Ask for what you need and nothing else:

  ```cmake
  find_package(LibreAgent 4.2 REQUIRED CONFIG COMPONENTS ClientQt)
  target_link_libraries(my_gui PRIVATE LibreAgent::ClientQt)
  ```

  Each component re-exposes only its own dependencies — `Core` brings
  LibreMiddleware and OpenSSL, `ClientQt` brings Qt6::Core, `Wire`
  brings nothing — so a Qt client never has to discover LibreMiddleware
  and a platform host never has to discover Qt. Naming components is the
  supported spelling; a componentless `find_package` still resolves, but
  it probes for every component that happens to be installed and so
  drags in dependencies the caller may not want.
- **Public-ABI snapshot gate** in CI freezing the exported surface;
  minor-version additions are tracked, while removals or signature drift
  are rejected. It gates the exported symbols of **all three** shipped
  components, AND the memory layout of the Qt client's public value
  types — size, alignment, member count and per-member offsets —
  because those types are copied by value into consumers, so a member
  added, removed or reordered breaks an already-built consumer without
  moving a single symbol name.

  Two limits are worth knowing rather than discovering. Demangling
  collapses the constructor/destructor ABI variants, so the symbol
  sections record fewer lines than the linker emits and a change
  affecting only one variant would not move them.

  And the Qt client's shared library exports a good deal that is not
  its API. Of 279 exported symbols, 113 are the API; the remaining
  **166 are not API**, and of those **164 are not gated** — the two
  that are, are the error-vocabulary functions a public header
  re-exports. The ungated 164 are the statically folded wire library
  (47) and its vendored CBOR dependency (117), left out because gating
  them would be pure churn. The vendored 117 are the ones to know
  about: they are unversioned C symbols, so a consumer that also links
  that CBOR library can end up with symbols bound across two copies of
  it. Giving them hidden visibility is tracked as follow-up work.
