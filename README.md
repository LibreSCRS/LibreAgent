# LibreAgent

The platform-neutral core of the LibreSCRS smart-card agent, the wire
vocabulary its transports speak, and the Qt client library desktop frontends
use to talk to it. Three independently usable libraries ship from this
repository:

| Target | Links | Who consumes it |
| --- | --- | --- |
| `LibreAgent::Core` | LibreMiddleware, OpenSSL | platform hosts (LibreLinux today, a macOS host to follow) |
| `LibreAgent::Wire` | nothing first-party | anything speaking the agent protocol |
| `LibreAgent::ClientQt` | Qt6 | Qt/KDE desktop clients |

`LibreAgent::Core` holds the Qt-free, backend-agnostic brain of the per-user
card broker — reader/card presence tracking, operation scheduling, read and
credential caches, the PKCS#11 lease/broker model, and the
LibreMiddleware-backed card flows — behind a small set of backend interfaces
(prompting, authorization, transport, operation channel, logging). Platform
hosts provide the interface implementations and the inbound frontend.

`LibreAgent::Wire` is the shared message vocabulary: the message types,
canonical CBOR codec and framing both transports carry, plus the frozen error
vocabularies, so a host and a client cannot drift apart on what a message or a
refusal means.

`LibreAgent::ClientQt` is the other side of the conversation — a
transport-neutral, typed Qt client exposing the agent as live `AgentClient` /
`AgentReader` / `AgentCard` / `AgentOperation` objects. It is written against
an internal transport seam with two implementations — D-Bus and the AF_UNIX
socket wire — so no transport type appears anywhere in the public API. **In
this release the public API selects D-Bus and offers no way to ask for the
socket transport**: `AgentClient` has a single constructor, and it builds the
D-Bus transport on Linux and none elsewhere. The socket implementation is
complete and tested, but reaching it needs a constructor this release does not
export. Every call the client makes is bounded by a timeout budget, so a slow
or wedged agent cannot hang a caller indefinitely — note *bounded*, not
instant: a synchronous call may still block for its budget (3 s by default),
which is why the operation-entry calls are the ones a GUI should not make from
its paint path.

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

- CMake ≥ 3.28 (needed for `FetchContent_Declare(... EXCLUDE_FROM_ALL)`, which
  keeps the vendored QCBOR dependency's own install rules out of the
  installed tree)
- A C++23 toolchain (GCC 13+ / Clang 16+)
- `find_package(LibreMiddleware 4.2 CONFIG)` — the sole first-party dependency,
  needed by `LibreAgent::Core` only
- OpenSSL ≥ 3.0 (`Crypto`) — `LibreAgent::Core` only
- Qt6 (`Core`, plus `DBus` on Linux) — `LibreAgent::ClientQt` only
- GoogleTest (for the test suite)

```bash
cmake -B build
cmake --build build
(cd build && ctest --output-on-failure)
```

`LIBREAGENT_BUILD_CORE` and `LIBREAGENT_BUILD_WIRE` default to `ON`;
`LIBREAGENT_BUILD_CLIENT_QT` defaults to `OFF`, so the Qt client library and
its test suite are opt-in via `-DLIBREAGENT_BUILD_CLIENT_QT=ON` (which
requires `LIBREAGENT_BUILD_WIRE`, since the client links the wire library).
Turning `LIBREAGENT_BUILD_CORE=OFF` alongside it gives a client-only build
that needs neither LibreMiddleware nor OpenSSL present.

If LibreMiddleware is installed to a non-standard prefix, point CMake at it
with `-DCMAKE_PREFIX_PATH=<lm-install-prefix>`. The installed CONFIG package,
the unit tests and the export rules only build when LibreAgent is the
top-level project; when it is pulled in as a subproject the enabled libraries
are produced without any of that surrounding machinery.

## Consuming

Downstream projects consume the installed CONFIG package, naming the
components they need:

```cmake
# A platform host:
find_package(LibreAgent 4.2 REQUIRED CONFIG COMPONENTS Core)
target_link_libraries(my_host PRIVATE LibreAgent::Core)

# A Qt/KDE desktop client:
find_package(LibreAgent 4.2 REQUIRED CONFIG COMPONENTS ClientQt)
target_link_libraries(my_gui PRIVATE LibreAgent::ClientQt)
```

Naming components is the supported spelling, and it is what keeps the
dependency sets apart: each component re-exposes only its own dependencies —
`Core` brings LibreMiddleware and OpenSSL, `ClientQt` brings `Qt6::Core`,
`Wire` brings nothing — so a Qt client never has to discover LibreMiddleware
and a platform host never has to discover Qt. A componentless
`find_package(LibreAgent CONFIG)` still resolves, but it probes for every
component that happens to be installed and therefore drags in dependencies the
caller may not want.

Public headers are then reachable under `<LibreSCRS/Agent/...>` for the core
and the wire, and `<LibreSCRS/AgentClient/...>` for the Qt client.

For local development against a sibling checkout, the platform host can build
the core from source via FetchContent and re-point it at the working tree with
`-DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=/path/to/LibreAgent` — this is how
LibreLinux's `cmake/FindOrUseLibreAgent.cmake` hybrid consumes the core,
switching to `find_package(LibreAgent CONFIG)` for installed builds.

## Repository layout

```
include/LibreSCRS/Agent/   public C++ headers for Core and Wire
                             (namespace LibreSCRS::Agent)
src/                       Core implementation
src/wire/                  Wire implementation (codec, framing, messages)
wire/                      the wire contract itself (CDDL schema)
client/qt/                 LibreAgent::ClientQt — public headers under
                             include/LibreSCRS/AgentClient/, the transport
                             seam and both transports under src/, its own
                             test suite under tests/
tests/                     Core/Wire unit tests + the five backend fakes,
                             pkgsmoke consumer
cmake/                     CONFIG package template + install/export rules
ci/                        the public-ABI snapshot gate and its baseline
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
