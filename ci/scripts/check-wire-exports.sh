#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Assert that the Qt client library exports nothing from this project's own wire
# namespace except the functions a public client header re-exports on purpose.
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

# The allowlist is READ FROM abi-snapshot.sh, which already carries the one list
# of wire symbols a public client header re-exports. A second hand-kept copy
# drifts in the direction nothing reports: this gate permitting a symbol the
# baseline does not record leaves it exported and ungated.
ABI_SCRIPT="$(cd "$(dirname "$0")" && pwd)/abi-snapshot.sh"
if [[ ! -f "$ABI_SCRIPT" ]]; then
    echo "FAIL: cannot find abi-snapshot.sh next to this script ($ABI_SCRIPT)." >&2
    echo "It holds the allowlist this check reads." >&2
    exit 2
fi

ALLOW_RE="$(sed -n "s/^CLIENTQT_WIRE_PUBLIC='\(.*\)'\$/\1/p" "$ABI_SCRIPT")"
if [[ -z "$ALLOW_RE" ]]; then
    echo "FAIL: no CLIENTQT_WIRE_PUBLIC='...' assignment found in $ABI_SCRIPT." >&2
    echo "Teach this script the new spelling rather than letting it fall back to" >&2
    echo "an empty allowlist, which would pass only a library missing the API." >&2
    exit 2
fi
# Exactly one, or the rest does not mean what it reads like: grep -E takes a
# pattern containing a newline as an ALTERNATION, so a second assignment would
# silently WIDEN the allowlist rather than conflict with it.
assignments="$(printf '%s\n' "$ALLOW_RE" | grep -c .)"
if [[ "$assignments" -ne 1 ]]; then
    echo "FAIL: $ABI_SCRIPT has $assignments CLIENTQT_WIRE_PUBLIC assignments; expected one." >&2
    exit 2
fi

# The names inside the regex's alternation, so their presence can be asserted
# below -- derived from the same string rather than listed a second time. The
# plausibility check is load-bearing twice over: it catches a regex this script
# misread, and it is what makes each name safe to interpolate into one.
_names_group="${ALLOW_RE#*(}"
_names_group="${_names_group%%)*}"
IFS='|' read -r -a ALLOW_NAMES <<< "$_names_group"
if [[ "${#ALLOW_NAMES[@]}" -eq 0 ]]; then
    echo "FAIL: could not read any function name out of the allowlist regex:" >&2
    echo "  $ALLOW_RE" >&2
    exit 2
fi
for _name in "${ALLOW_NAMES[@]}"; do
    if [[ ! "$_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        echo "FAIL: '$_name' is not a plausible function name -- the allowlist in" >&2
        echo "$ABI_SCRIPT parsed into something this script misread. Refusing to" >&2
        echo "check against it." >&2
        exit 2
    fi
done

# Names beginning with the namespace, plus the "<kind> for <name>" spellings
# c++filt gives a type's vtable and typeinfo. No client export is spelled that
# way, so the arm costs nothing and removes a blind spot.
demangled="$(printf '%s\n' "$mangled" | c++filt)"
wire="$(printf '%s\n' "$demangled" \
    | grep -E '^(LibreSCRS::Agent::Wire::|(typeinfo|typeinfo name|typeinfo fn|vtable|VTT|guard variable|construction vtable) for LibreSCRS::Agent::Wire::)' \
    | sort -u)"

# Half one, a PRESENCE. A hidden preset hides the API too unless each function
# is annotated, and the absence half below would then pass with nothing to
# report -- green, on a library whose documented surface had gone missing.
missing=()
for _name in "${ALLOW_NAMES[@]}"; do
    found="$(printf '%s\n' "$wire" | grep -c "^LibreSCRS::Agent::Wire::${_name}(")"
    if [[ "$found" -eq 0 ]]; then
        missing+=("$_name")
    fi
done
if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "FAIL: $LIB does NOT export ${#missing[@]} contractually public wire symbol(s):" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo "A public client header declares these, so give each one" >&2
    echo "LIBRESCRS_AGENTWIRE_EXPORT at its declaration." >&2
    exit 1
fi

# Half two, the ABSENCE: nothing else from that namespace.
leaked="$(printf '%s\n' "$wire" | { grep -Ev "$ALLOW_RE" || true; })"
if [[ -n "$leaked" ]]; then
    count="$(printf '%s\n' "$leaked" | grep -c .)"
    echo "FAIL: $LIB exports $count wire symbol(s) that are not part of its API." >&2
    echo "Each is bindable by a consumer and tracked by nothing. Keep the wire" >&2
    echo "target's hidden visibility preset, and annotate only what a public" >&2
    echo "client header genuinely re-exports." >&2
    printf '%s\n' "$leaked" | head -20 >&2
    [[ "$count" -gt 20 ]] && echo "  ... and $((count - 20)) more" >&2
    exit 1
fi

echo "OK: $LIB exports ${#ALLOW_NAMES[@]} wire symbol(s), all contractually public."
