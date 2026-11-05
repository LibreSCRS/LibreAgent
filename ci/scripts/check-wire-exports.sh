#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Assert that the Qt client library exports nothing from this project's own wire
# namespace.
#
# Not the sibling check's hazard: these are mangled, namespaced C++ names, so
# nothing else in a process defines them and there is no cross-binding path.
# They are ABI surface -- a consumer can bind to any of them and no gate would
# report the breakage when one changes.
#
# Scope is names BEGINNING with the wire namespace (plus a type's vtable and
# typeinfo). std templates instantiated over wire types leak by the same cause
# but match no honest prefix rule, since a genuine client export names wire
# types in its signature too. They need no separate check: every family here is
# exported only when the wire target compiles with default visibility, so these
# names are a faithful sentinel for all of them.
#
#   Usage: check-wire-exports.sh <path-to-shared-library>
set -uo pipefail

LIB="${1:?path to the shared library required}"
[[ -f "$LIB" ]] || { echo "not a file: $LIB" >&2; exit 2; }

command -v nm >/dev/null 2>&1 || { echo "nm not found" >&2; exit 2; }
command -v c++filt >/dev/null 2>&1 || { echo "c++filt not found" >&2; exit 2; }

# This check asks about an absence, and an absence is what a broken check
# reports too -- so first prove it can see anything at all, then prove it is
# OUR library and not merely some library.
#
# Counted, not `grep -q`: under `pipefail` an early-exiting grep sends SIGPIPE
# upstream and the pipeline reports failure, which once rejected the healthy
# library it was meant to accept.
mangled="$(nm --dynamic --defined-only "$LIB" 2>/dev/null | awk '{print $3}')"
symbols="$(printf '%s\n' "$mangled" | grep -c .)"
if [[ "$symbols" -lt 100 ]]; then
    echo "FAIL: $LIB yielded only $symbols dynamic symbols -- this is not the shared library" >&2
    echo "this check is meant to read, so its 'no leak' answer would be vacuous." >&2
    exit 2
fi
own="$(printf '%s\n' "$mangled" | grep -c '11AgentClient')"
if [[ "$own" -eq 0 ]]; then
    echo "FAIL: $LIB exports no LibreSCRS::AgentClient symbol -- wrong artifact." >&2
    exit 2
fi

# Names beginning with the namespace, plus the "<kind> for <name>" spellings
# c++filt gives a type's vtable and typeinfo. No client export is spelled that
# way, so the arm costs nothing and removes a blind spot.
demangled="$(printf '%s\n' "$mangled" | c++filt)"
wire="$(printf '%s\n' "$demangled" \
    | grep -E '^(LibreSCRS::Agent::Wire::|(typeinfo|typeinfo name|typeinfo fn|vtable|VTT|guard variable|construction vtable) for LibreSCRS::Agent::Wire::)' \
    | sort -u)"

# Nothing from that namespace may be exported.
leaked="$wire"
if [[ -n "$leaked" ]]; then
    count="$(printf '%s\n' "$leaked" | grep -c .)"
    echo "FAIL: $LIB exports $count wire symbol(s); none is part of its API." >&2
    echo "Each is bindable by a consumer and tracked by nothing. Keep the wire" >&2
    echo "target's hidden visibility preset." >&2
    printf '%s\n' "$leaked" | head -20 >&2
    [[ "$count" -gt 20 ]] && echo "  ... and $((count - 20)) more" >&2
    exit 1
fi

echo "OK: $LIB exports no wire symbol."
