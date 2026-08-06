#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Assert that the Qt client library exports NO symbol from the vendored CBOR
# library it folds in.
#
# Why this is a correctness gate and not tidiness: ELF resolves an unmangled C
# name process-wide by first definition. A desktop session loads many plugins,
# several of which may carry their own copy of the same C library. If this
# library exports its copy's names, the two can cross-bind -- in whichever
# direction load order happens to decide -- and the calls being cross-bound
# decode data that came off a smart card. Hiding the names removes the
# possibility in both directions at once: nothing outside can bind to ours, and
# ours can no longer be preempted by anything outside.
#
# ELF-specific by nature. Mach-O records the defining library in each reference
# (two-level namespace), so the hazard does not exist there and this check is
# not run on it.
#
#   Usage: check-vendored-exports.sh <path-to-shared-library>
set -uo pipefail

LIB="${1:?path to the shared library required}"
[[ -f "$LIB" ]] || { echo "not a file: $LIB" >&2; exit 2; }

command -v nm >/dev/null 2>&1 || { echo "nm not found" >&2; exit 2; }

# Everything below asserts an ABSENCE, and an absence is exactly what a broken
# check also reports. So first prove the check can see anything at all: a path
# that is not an ELF shared object, or one whose dynamic symbol table reads
# empty, means this gate is not looking at what it thinks it is -- fail rather
# than report a clean surface.
symbols="$(nm --dynamic --defined-only "$LIB" 2>/dev/null | awk '{print $3}' | grep -c .)"
if [[ "$symbols" -lt 100 ]]; then
    echo "FAIL: $LIB yielded only $symbols dynamic symbols -- this is not the shared library" >&2
    echo "this check is meant to read, so its 'no leak' answer would be vacuous." >&2
    exit 2
fi

# ...and prove it is OUR library, not merely some library. Without this, the
# check reports a clean surface for any unrelated .so it is handed.
#
# Counted rather than `grep -q`: under `pipefail`, an early-exiting grep sends
# SIGPIPE upstream and the whole pipeline reports failure, so a `grep -q` here
# rejected the healthy library it was meant to accept.
own="$(nm --dynamic --defined-only "$LIB" 2>/dev/null | awk '{print $3}' | grep -c '11AgentClient')"
if [[ "$own" -eq 0 ]]; then
    echo "FAIL: $LIB exports no LibreSCRS::AgentClient symbol -- wrong artifact." >&2
    exit 2
fi

# The vendored library's exported name families. Anchored at the start of the
# symbol so a project symbol that merely mentions one cannot match.
PATTERN='^(QCBOR|UsefulBuf|UsefulInput|UsefulOutput|IEEE754)'

leaked="$(nm --dynamic --defined-only "$LIB" 2>/dev/null | awk '{print $3}' | grep -E "$PATTERN" | sort)"

if [[ -n "$leaked" ]]; then
    count="$(printf '%s\n' "$leaked" | wc -l)"
    echo "FAIL: $LIB exports $count symbol(s) from the vendored CBOR library." >&2
    echo "Any process loading this library alongside another copy of it can cross-bind the two." >&2
    printf '%s\n' "$leaked" | head -20 >&2
    [[ "$count" -gt 20 ]] && echo "  ... and $((count - 20)) more" >&2
    exit 1
fi

echo "OK: $LIB exports no vendored CBOR symbols."
