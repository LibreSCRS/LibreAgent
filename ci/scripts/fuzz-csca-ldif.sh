#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# fuzz-csca-ldif.sh — build and run the libFuzzer targets for the readers the
# CSCA anchor import walks over an imported file (src/trust/CscaAnchorImport.cpp).
#
# The input is an RFC 2849 directory export a person downloads from a public
# ICAO PKD mirror and hands to the agent. Every reader below runs BEFORE any
# signature has been verified: the LDIF line grammar, a base64 decoder, a
# hand-written BER length decoder, and the three small scalar parsers the same
# path uses for its state file. An untrusted-input surface that must never
# crash or invoke UB, and the only one in this repository with no fuzz cover.
#
# Six targets, all six in the anonymous namespace of that file:
#   ldif            signedObjectsInLdif   — line folding, record grammar
#   base64          decodeBase64          — RFC 4648, strict, padding rules
#   signed_object   isSignedObject        — its OWN short/long/indefinite BER
#                                           length decoder
#   integer         wholeInteger          — strtoll behind a digit filter
#   fingerprint     fingerprintFromHex    — fixed-width hex into a 32-byte array
#   comma_fields    commaFields           — substr walk over a state-file value
#
# Same technique as ci/scripts/fuzz-cbor.sh: a standalone
# `clang++ -fsanitize=fuzzer,address` build, NOT this repository's own CMake
# configuration — -fsanitize=fuzzer needs a fuzzer-capable clang and the
# default build compiler is whatever CMAKE_CXX_COMPILER resolves to, typically
# GCC. Same corpus-copy discipline, same shape of CI job.
#
# TRADE-OFF, deliberate and recorded rather than hidden: the driver #includes
# the implementation FILE. The six readers are in an anonymous namespace and
# are not part of any public surface; reaching them through a header would mean
# promoting them — changing shipped code for the benefit of a test tool. This
# script is not part of the shipped build, so the include lives here and
# src/trust/CscaAnchorImport.cpp is untouched.
#
# The link flags follow from that, and they are not a way of ignoring errors.
# Including the file also emits every non-anonymous function in it, and those
# call into LibreMiddleware, into this repo's logging and into ConfigStore,
# none of which is linked here. So the link is -ffunction-sections
# -fdata-sections -fuse-ld=lld -Wl,--gc-sections: lld drops the sections no
# path from LLVMFuzzerTestOneInput reaches. MEASURED, not assumed: a driver
# that does reach one of them still fails the link with `undefined symbol`, so
# an undefined symbol on the FUZZED path is a build failure, which is exactly
# what --unresolved-symbols=ignore-all would have thrown away.
#
# LibreMiddleware headers are needed to compile the file, but nothing of
# LibreMiddleware is linked — see above. Headers only, from a checkout or an
# install prefix; --lm-include, then $LM_INCLUDE, then $LM_PREFIX/include, then
# the side-by-side checkout next to this one. None of them carrying
# LibreSCRS/Trust/CscaMasterList.h is exit 2: could not measure, never a pass.
#
# Requires: a clang++ with the libFuzzer + ASan runtimes (libclang_rt.fuzzer*,
# libclang_rt.asan*) and lld — e.g. Arch's `clang`+`compiler-rt`+`lld`, or
# Debian/Ubuntu's `clang-21`+`libclang-rt-21-dev`+`lld-21` (matching the CI
# job). AppleClang ships neither runtime, so this does not run on macOS.
#
# Usage:
#   ci/scripts/fuzz-csca-ldif.sh [--time SECONDS] [--clang CLANGXX_BINARY]
#                                [--lm-include DIR] [--target NAME] [--keep]
#
# --time is the budget for the WHOLE run and is divided over the targets that
# will run, one second minimum each. Default 120 (matches the CI job).
# Default --clang: clang++ on PATH. --target may be repeated, or given once as
# a comma-separated list, and restricts the run to those targets. --keep
# preserves the scratch dir (objects, the six binaries, the corpus copies)
# instead of deleting it on exit; the path is printed.
#
# IMPORTANT: libFuzzer writes every new "interesting" input it discovers
# straight into the corpus directory given on its command line. The CI job
# could point it at the checked-out tests/corpus/csca_ldif/ directly because
# that whole checkout is thrown away after the job; this script runs against a
# real, persistent git working tree, so each target fuzzes its own scratch COPY
# of tests/corpus/csca_ldif/ — the tracked seed corpus is read-only input here,
# never a write target, and the six targets cannot contaminate each other's.
#
# The three tracked seeds are named for what they are, because two of them are
# the only reason two branches are reachable at all from a cold start:
#   empty.ldif                             — no records, no dn
#   definite-length-signed-object.ldif     — one userCertificate;binary:: value
#                                            that IS a short-form ContentInfo
#   indefinite-length-signed-object.ldif   — the same, in the BER indefinite
#                                            form isSignedObject has a branch
#                                            for; a real ICAO collection
#                                            carries one

set -euo pipefail

TIME_BUDGET=120
CLANGXX="clang++"
KEEP=0
LM_INCLUDE_ARG=""
SELECTED=()

ALL_TARGETS=(ldif base64 signed_object integer fingerprint comma_fields)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --time) TIME_BUDGET="$2"; shift 2 ;;
        --clang) CLANGXX="$2"; shift 2 ;;
        --lm-include) LM_INCLUDE_ARG="$2"; shift 2 ;;
        --target)
            # One flag may carry a list; the flag may also be repeated.
            IFS=',' read -r -a _picked <<< "$2"
            SELECTED+=("${_picked[@]}")
            shift 2
            ;;
        --keep) KEEP=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "ERROR: unrecognized argument '$1'" >&2; exit 2 ;;
    esac
done

if [[ ${#SELECTED[@]} -eq 0 ]]; then
    TARGETS=("${ALL_TARGETS[@]}")
else
    TARGETS=()
    for want in "${SELECTED[@]}"; do
        found=0
        for known in "${ALL_TARGETS[@]}"; do
            [[ "$want" == "$known" ]] && { TARGETS+=("$want"); found=1; break; }
        done
        if [[ $found -eq 0 ]]; then
            echo "ERROR: no such target '$want' (have: ${ALL_TARGETS[*]})" >&2
            exit 2
        fi
    done
fi

if ! [[ "$TIME_BUDGET" =~ ^[0-9]+$ ]] || [[ "$TIME_BUDGET" -lt 1 ]]; then
    echo "ERROR: --time takes a positive whole number of seconds" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/src/trust"
TRACKED_CORPUS="${REPO_ROOT}/tests/corpus/csca_ldif"

if [[ ! -f "${SOURCE_DIR}/CscaAnchorImport.cpp" ]]; then
    echo "ERROR: ${SOURCE_DIR}/CscaAnchorImport.cpp is not there — wrong root?" >&2
    exit 2
fi
if [[ ! -d "$TRACKED_CORPUS" ]]; then
    echo "ERROR: seed corpus ${TRACKED_CORPUS} is missing — a harness with no seed" >&2
    exit 2
fi

# Headers only. The order is deliberate: an explicit flag wins, then the
# environment the CI job already sets for LibreMiddleware, then the workspace
# of side-by-side checkouts a developer has.
LM_INCLUDE_ENV="${LM_INCLUDE:-}"
LM_INCLUDE=""
for candidate in \
    "$LM_INCLUDE_ARG" \
    "$LM_INCLUDE_ENV" \
    "${LM_PREFIX:+${LM_PREFIX}/include}" \
    "$(dirname "$REPO_ROOT")/LibreMiddleware/include" \
    "${REPO_ROOT}/../LibreMiddleware/include"
do
    [[ -n "$candidate" ]] || continue
    if [[ -f "${candidate}/LibreSCRS/Trust/CscaMasterList.h" ]]; then
        LM_INCLUDE="$(cd "$candidate" && pwd)"
        break
    fi
done
if [[ -z "$LM_INCLUDE" ]]; then
    echo "ERROR: no LibreMiddleware include tree carrying" \
         "LibreSCRS/Trust/CscaMasterList.h — pass --lm-include DIR." \
         "Cannot measure, which is not a pass." >&2
    exit 2
fi

# mktemp honours TMPDIR, and TMPDIR defaults to /tmp, which is a RAM-backed
# tmpfs on a good many desktops. Six ASan+libFuzzer binaries plus whatever
# libFuzzer adds to six corpus copies is real space, so the default here is
# /var/tmp; an explicit TMPDIR still wins.
SCRATCH="$(TMPDIR="${TMPDIR:-/var/tmp}" mktemp -d)"

# The scratch dir survives a failure whether or not --keep was given, and
# -artifact_prefix below puts the reproducer in it: libFuzzer writes
# `crash-<sha1>` into the CURRENT directory by default, which for a dev is the
# git working tree — a crash would leave two untracked files behind, and for a
# CI job it would leave the reproducer nowhere anyone can fetch it from.
cleanup() {
    local rc=$?
    if [[ "$KEEP" -eq 1 || "$rc" -ne 0 ]]; then
        echo "Scratch dir kept at: ${SCRATCH} (binaries, corpus copies," \
             "and any crash-* reproducer)"
    else
        rm -rf "$SCRATCH"
    fi
    return "$rc"
}
trap cleanup EXIT

DRIVER="${SCRATCH}/CscaLdifFuzzDriver.cpp"
cat > "$DRIVER" <<'DRIVER_EOF'
// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer driver for the CSCA anchor-import readers. Written out by
// ci/scripts/fuzz-csca-ldif.sh, which carries the whole rationale: the six
// targets, why the implementation FILE is included rather than a header, and
// why the link is lld + --gc-sections rather than an ignore-undefined flag.
//
// One target per binary, selected by -DFUZZ_TARGET_<NAME>. A single binary
// dispatching on the first input byte would hand libFuzzer one coverage map
// for six unrelated grammars and spend most of its budget deciding which
// parser to call.

#include "CscaAnchorImport.cpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace t = LibreSCRS::Agent::Trust;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    // libFuzzer always hands over a valid pointer, but data + 0 on a null
    // pointer is UB and this file is compiled with UB detection on, so the
    // guard is cheap honesty rather than defensiveness.
    if (data == nullptr) {
        return 0;
    }

    const auto* chars = reinterpret_cast<const char*>(data);

#if defined(FUZZ_TARGET_LDIF)
    const std::vector<std::uint8_t> bytes(data, data + size);
    const auto found = t::signedObjectsInLdif(bytes);
    // Spend the answer: an unused result is a result the optimiser may decide
    // not to compute, and then the harness fuzzes nothing.
    std::size_t total = 0;
    for (const auto& object : found) {
        total += object.size();
    }
    if (total == 0xFFFFFFFFu) {
        __builtin_trap(); // unreachable; keeps `total` live
    }
#elif defined(FUZZ_TARGET_BASE64)
    const auto decoded = t::decodeBase64(std::string_view{chars, size});
    if (decoded && decoded->size() == 0xFFFFFFFFu) {
        __builtin_trap();
    }
#elif defined(FUZZ_TARGET_SIGNED_OBJECT)
    const std::vector<std::uint8_t> bytes(data, data + size);
    if (t::isSignedObject(bytes) && bytes.empty()) {
        __builtin_trap();
    }
#elif defined(FUZZ_TARGET_INTEGER)
    const auto parsed = t::wholeInteger(std::string{chars, size});
    if (parsed && *parsed == 0x7FFFFFFFFFFFFFFFLL && size == 0) {
        __builtin_trap();
    }
#elif defined(FUZZ_TARGET_FINGERPRINT)
    const auto print = t::fingerprintFromHex(std::string_view{chars, size});
    if (print && (*print)[0] == 0xFF && size == 0) {
        __builtin_trap();
    }
#elif defined(FUZZ_TARGET_COMMA_FIELDS)
    const auto fields = t::commaFields(std::string{chars, size});
    if (fields.empty()) {
        __builtin_trap(); // commaFields always answers at least one field
    }
#else
#error "no FUZZ_TARGET_<NAME> defined -- the build would fuzz nothing"
#endif
    return 0;
}
DRIVER_EOF

declare -A MACRO=(
    [ldif]=FUZZ_TARGET_LDIF
    [base64]=FUZZ_TARGET_BASE64
    [signed_object]=FUZZ_TARGET_SIGNED_OBJECT
    [integer]=FUZZ_TARGET_INTEGER
    [fingerprint]=FUZZ_TARGET_FINGERPRINT
    [comma_fields]=FUZZ_TARGET_COMMA_FIELDS
)

PER_TARGET=$(( TIME_BUDGET / ${#TARGETS[@]} ))
[[ "$PER_TARGET" -lt 1 ]] && PER_TARGET=1

echo "LibreMiddleware headers: ${LM_INCLUDE}"
echo "Targets: ${TARGETS[*]} (${PER_TARGET}s each, ${TIME_BUDGET}s budget)"

for target in "${TARGETS[@]}"; do
    echo "Building ${target} (-fsanitize=fuzzer,address, lld --gc-sections) ..."
    "$CLANGXX" -std=c++23 -g -O1 -fsanitize=fuzzer,address \
        -ffunction-sections -fdata-sections -fuse-ld=lld -Wl,--gc-sections \
        -D"${MACRO[$target]}"=1 \
        -I"${REPO_ROOT}/include" -I"$LM_INCLUDE" -I"$SOURCE_DIR" \
        "$DRIVER" -o "${SCRATCH}/csca-ldif-fuzz-${target}"
done

for target in "${TARGETS[@]}"; do
    # See the IMPORTANT note in the header: a per-target scratch copy, so the
    # tracked seeds are never a write target and the targets cannot feed each
    # other inputs their own grammar never produced.
    corpus="${SCRATCH}/corpus-${target}"
    mkdir -p "$corpus"
    # `command cp -f`, not a bare cp: an interactive `cp -i` alias turns an
    # unattended run into a hang waiting on a prompt nobody will answer.
    command cp -f "${TRACKED_CORPUS}"/* "$corpus/"

    echo "Running ${target} for ${PER_TARGET}s over ${corpus} ..."
    "${SCRATCH}/csca-ldif-fuzz-${target}" \
        -max_total_time="$PER_TARGET" -timeout=5 -print_final_stats=1 \
        -artifact_prefix="${SCRATCH}/crash-${target}-" "$corpus"
done
