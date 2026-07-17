# LibreAgent Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 4.3.0

First public release of `LibreAgent::Core`, the platform-neutral,
Qt-free core of the LibreSCRS smart-card agent. Platform hosts
(LibreLinux today, a macOS host to follow) build on it to provide the
per-user card broker without re-implementing the neutral state machine.

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

- **Installed CONFIG package** (`find_package(LibreAgent CONFIG)`
  exposing `LibreAgent::Core`) that re-exposes the LibreMiddleware and
  OpenSSL dependencies, so downstream hosts do not re-discover them.
- **Public-ABI snapshot gate** in CI freezing the exported symbol
  surface; minor-version additions are tracked, while removals or
  signature drift are rejected.
