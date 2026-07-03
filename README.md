# LibreAgent

The platform-neutral core of the LibreSCRS smart-card agent. This
library (`LibreAgent::Core`) holds the Qt-free, backend-agnostic brain
of the per-user card broker — reader/card presence tracking, operation
scheduling, read and credential caches, the PKCS#11 lease/broker model, and
the LibreMiddleware-backed card flows — behind a small set of backend
interfaces (prompting, authorization, transport, operation channel, logging).
Platform hosts provide the interface implementations and the inbound frontend:
LibreLinux ships the Linux D-Bus daemon today, with a macOS host to follow.
Built on LibreMiddleware.

## What it owns

The core is the single owner of the neutral agent state and logic that every
platform host needs, regardless of its IPC or desktop stack:

- **Presence tracking** — a reader/card presence model driven by
  LibreMiddleware's `MonitorService`, with card-key tracking and a plugin
  capability resolver that classifies each seated card.
- **Operation scheduling** — a bounded worker pool that runs card read/sign
  operations, with rate limiting, watchdog-driven cancellation, and a
  property-emission throttler for downstream status updates.
- **Caches** — a card-read cache and a credential cache, both scrubbed on card
  removal so secrets never outlive the card.
- **PKCS#11 lease/broker** — the lease manager and broker that arbitrate
  exclusive card access between the agent's own flows and external PKCS#11
  clients.
- **LibreMiddleware-backed card flows** — identity, photo and certificate
  reads plus AdES / raw-crypto signing, expressed as seam-isolated flows over
  the LibreMiddleware SDK.

## Backend interfaces

The core stays free of any IPC, desktop or OS integration by talking to its
host through five small interfaces. The platform host implements them; the
core never links D-Bus, systemd, polkit or Qt:

- **Prompter** (`Operations::PrompterClientBase`) — collects PIN / CAN / MRZ
  secrets; the secret returns as a cleansing `Secure::String`, never a raw fd.
- **Authorizer** (`Authorizer`) — gates each client operation (the Linux host
  backs this with polkit; a fail-closed default gate ships in-tree).
- **AgentTransport** (`AgentTransport`) — the outbound channel back to the
  requesting client.
- **OperationChannel** (`Operations::OperationChannel`) — per-operation
  progress, result and error emission.
- **LogSink** (`log::LogSink`) — an injected sink so the host owns the
  platform logging surface.

## Building

Requirements:

- CMake ≥ 3.24
- A C++23 toolchain (GCC 13+ / Clang 16+)
- `find_package(LibreMiddleware 4.2 CONFIG)` — the sole first-party dependency
- OpenSSL ≥ 3.0 (`Crypto`)
- GoogleTest (for the test suite)

```bash
cmake -B build
cmake --build build
(cd build && ctest --output-on-failure)
```

If LibreMiddleware is installed to a non-standard prefix, point CMake at it
with `-DCMAKE_PREFIX_PATH=<lm-install-prefix>`. The installed CONFIG package,
the unit tests and the export rules only build when LibreAgent is the top-level
project; when it is pulled in as a subproject only the `LibreAgent::Core`
library is produced.

## Consuming

Downstream projects consume the installed CONFIG package:

```cmake
find_package(LibreAgent CONFIG REQUIRED)
target_link_libraries(my_host PRIVATE LibreAgent::Core)
```

Public headers are then reachable under `<LibreSCRS/Agent/...>`. The config
package re-exposes the LibreMiddleware and OpenSSL dependencies the static
archive carries, so consumers do not re-discover them.

For local development against a sibling checkout, the platform host can build
the core from source via FetchContent and re-point it at the working tree with
`-DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=/path/to/LibreAgent` — this is how
LibreLinux's `cmake/FindOrUseLibreAgent.cmake` hybrid consumes the core,
switching to `find_package(LibreAgent CONFIG)` for installed builds.

## Repository layout

```
include/LibreSCRS/Agent/   public C++ headers (namespace LibreSCRS::Agent)
src/                       library implementation
tests/                     unit tests + the five backend fakes, pkgsmoke consumer
cmake/                     CONFIG package template + install/export rules
```

## LibreSCRS

LibreAgent is one component of the LibreSCRS smart-card stack:

- **LibreMiddleware** — the Qt-free C++23 card-reading core
- **LibreAgent** — this platform-neutral agent core
- **LibreLinux** — the Linux D-Bus agent host
- **LibreCelik** — the Qt6 desktop GUI

A macOS host is to follow.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code-formatting expectations
(clang-format-21 pin), build/test steps, and commit conventions.

## License

LGPL-2.1-or-later — see [LICENSE](LICENSE) for details. The repository is
[REUSE](https://reuse.software/)-oriented: source files carry SPDX headers and
the license text lives in `LICENSES/LGPL-2.1-or-later.txt`.
