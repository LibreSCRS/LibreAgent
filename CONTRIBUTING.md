# Contributing to LibreAgent

Thank you for your interest in contributing to LibreAgent. This document
captures the conventions a contributor must follow before opening a pull
request. LibreAgent is the platform-neutral core of the LibreSCRS smart-card
agent; keep changes free of any IPC, desktop or OS integration (no D-Bus,
systemd, polkit or Qt) — those belong in a platform host such as LibreLinux.

## Code formatting

LibreAgent uses **`clang-format` version 21** as the canonical formatter.
CI lints `include/`, `src/` and `tests/` against this exact version (see
`.github/workflows/ci.yml`, `format-check` job). Newer versions of
`clang-format` may emit slightly different layout decisions and produce false
positives or false negatives against CI.

To match CI locally:

- **Debian/Ubuntu**: `apt-get install clang-format-21`
  (use the LLVM nightly apt repo if 21 is not in your distribution)
- **Arch / Manjaro**: `pacman -S clang21`
- **macOS (Homebrew)**: `brew install llvm@21`, then use
  `$(brew --prefix llvm@21)/bin/clang-format`
- **Other distros / fallback**: download the prebuilt LLVM 21 release from
  <https://github.com/llvm/llvm-project/releases> and put the binary on
  `$PATH` as `clang-format-21`.

Run before every commit:

```bash
find include src tests -name "*.cpp" -o -name "*.h" \
  | xargs clang-format-21 -i
```

If your local `clang-format` is a different major version, please install
version 21 specifically; do not commit a layout produced by another version
of the tool. CI will reject diverging layouts.

## Build and test

See the top-level `README.md` for the build instructions. LibreAgent depends on
LibreMiddleware (consumed via `find_package(LibreMiddleware 4.2 CONFIG)`); make
sure it is installed and discoverable, or point CMake at its prefix with
`-DCMAKE_PREFIX_PATH=<lm-install-prefix>`. Platform hosts that pull the core in
as a subproject build it from source with FetchContent — see
`FindOrUseLibreAgent.cmake` in LibreLinux and the
`FETCHCONTENT_SOURCE_DIR_LIBREAGENT` dev override.

Cap parallel jobs to a sensible value (`-j4` is a known-good cap on most
workstations); some contributors have observed full-CPU saturation freezing
their machine.

Always run the test suite before opening a pull request:

```bash
cmake -B build
cmake --build build -j4
(cd build && ctest --output-on-failure -j4)
```

The tests run against the five backend fakes and need no reader, D-Bus session
or live card; there are no PIN or live-card suites in the neutral core. CI also
runs the concurrency core (scheduler + throttler and the abandoned-worker
drain proofs) under ThreadSanitizer — keep that surface race-free.

## Commit conventions

- One logical change per commit. Use Conventional-Commit-style subjects
  (e.g. `agent: ...`, `presence: ...`, `pkcs11: ...`, `docs: ...`).
- Do not include `Co-Authored-By:` lines unless explicitly requested.
- Describe the rationale ("why") in the body, not just the surface diff.

## Public surface

LibreAgent follows the conventions documented in the
[LibreSCRS API Policy](https://LibreSCRS.github.io/developer-guide/sdk-reference/api-policy/).
The public headers under `include/LibreSCRS/Agent/` are the supported surface;
changes there must comply with the documented thread-safety, exception-policy
and append-only-enum rules. Keep the seam-boundary invariant intact: public
headers must not expose LibreMiddleware's Certificate / Signing / Trust types
(those stay a private link dependency of the seam translation units).

## License

Source files carry SPDX headers. LibreAgent is LGPL-2.1-or-later; new files
must preserve this license unless explicitly carved out.
