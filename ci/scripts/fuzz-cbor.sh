#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# fuzz-cbor.sh — build and run the libFuzzer target for the canonical-CBOR
# decoder (tests/wire/CborFuzzTest.cpp over src/wire/Cbor.cpp).
#
# The CBOR decoder parses input from any local caller over the socket wire
# (and, on macOS, the browser-extension facade) — an untrusted-input surface
# that must never crash / invoke UB. This script mirrors the fuzz job this
# repo's CI will run: same technique (raw clang -fsanitize=fuzzer,address over
# the decoder + QCBOR, standalone — NOT the project's own CMake/compiler
# configuration, since -fsanitize=fuzzer needs a fuzzer-capable clang and this
# repo's default build compiler is whatever CMAKE_CXX_COMPILER resolves to,
# typically GCC), same pinned QCBOR revision (parsed straight out of
# cmake/FetchQCBOR.cmake, single source of truth), same corpus
# (tests/corpus/cbor/). Wiring this into LibreAgent's own CI workflow is a
# separate, later task; this script is what that job will eventually shell
# out to, and is meanwhile how a dev runs the fuzzer locally.
#
# Requires: a clang++ with the libFuzzer + ASan runtimes (libclang_rt.fuzzer*,
# libclang_rt.asan*) — e.g. Arch's `clang`+`compiler-rt` packages, or Debian/
# Ubuntu's `clang-21`+`libclang-rt-21-dev` (matching the CI job). AppleClang
# ships neither runtime, so this does not run on macOS.
#
# Usage:
#   ci/scripts/fuzz-cbor.sh [--time SECONDS] [--clang CLANGXX_BINARY] [--keep]
#
# Default --time: 120 (matches the CI job). Default --clang: clang++ on PATH.
# --keep preserves the scratch build dir (QCBOR checkout + objects + the
# cbor-fuzz binary + the corpus copy, see below) instead of deleting it on
# exit; the path is printed.
#
# IMPORTANT: libFuzzer writes every new "interesting" input it discovers
# straight into the corpus directory given on its command line. The CI job
# can point it at the checked-out tests/corpus/cbor/ directly because that
# whole checkout is thrown away after the job; this script runs against a
# real, persistent git working tree, so it fuzzes a scratch COPY of
# tests/corpus/cbor/ instead — the tracked seed corpus is read-only input
# here, never a write target.

set -euo pipefail

TIME_BUDGET=120
CLANGXX="clang++"
CLANG="clang"
KEEP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --time) TIME_BUDGET="$2"; shift 2 ;;
        --clang) CLANGXX="$2"; CLANG="${2%++}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "ERROR: unrecognized argument '$1'" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FETCH_QCBOR="${REPO_ROOT}/cmake/FetchQCBOR.cmake"
TRACKED_CORPUS="${REPO_ROOT}/tests/corpus/cbor"

QCBOR_SHA="$(sed -n 's/^[[:space:]]*GIT_TAG[[:space:]]*\([0-9a-f]\{40\}\).*/\1/p' "$FETCH_QCBOR")"
if [[ -z "$QCBOR_SHA" ]]; then
    echo "ERROR: could not parse the pinned QCBOR GIT_TAG SHA out of $FETCH_QCBOR" >&2
    exit 2
fi

SCRATCH="$(mktemp -d)"
if [[ "$KEEP" -eq 0 ]]; then
    trap 'rm -rf "$SCRATCH"' EXIT
else
    trap 'echo "Scratch build dir kept at: $SCRATCH"' EXIT
fi

# Fuzz a scratch copy of the tracked seed corpus — see the IMPORTANT note
# above; the tracked tests/corpus/cbor/ itself is never passed to cbor-fuzz.
CORPUS="${SCRATCH}/corpus"
mkdir -p "$CORPUS"
cp "${TRACKED_CORPUS}"/*.bin "$CORPUS/"

echo "Fetching QCBOR @ ${QCBOR_SHA} ..."
git clone --quiet https://github.com/laurencelundblade/QCBOR.git "${SCRATCH}/qcbor-src"
git -C "${SCRATCH}/qcbor-src" checkout --quiet "$QCBOR_SHA"

echo "Compiling QCBOR (ASan-instrumented) ..."
(
    cd "${SCRATCH}"
    "$CLANG" -c -g -O1 -fsanitize=address -I"${SCRATCH}/qcbor-src/inc" "${SCRATCH}"/qcbor-src/src/*.c
)

echo "Building the fuzzer (decoder + QCBOR, -fsanitize=fuzzer,address) ..."
"$CLANGXX" -std=c++23 -g -O1 -fsanitize=fuzzer,address \
    -I"${REPO_ROOT}/include" -I"${SCRATCH}/qcbor-src/inc" \
    "${REPO_ROOT}/tests/wire/CborFuzzTest.cpp" "${REPO_ROOT}/src/wire/Cbor.cpp" \
    "${SCRATCH}"/*.o -o "${SCRATCH}/cbor-fuzz"

echo "Running the bounded fuzz (${TIME_BUDGET}s) over ${CORPUS} ..."
"${SCRATCH}/cbor-fuzz" -max_total_time="$TIME_BUDGET" -timeout=5 -print_final_stats=1 "$CORPUS"
