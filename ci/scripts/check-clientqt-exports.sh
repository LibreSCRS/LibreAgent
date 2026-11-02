#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Assert that the Qt client library exports only what its public headers
# declare: names in the LibreSCRS namespace (and a type's vtable, typeinfo,
# thunks and guard variables), and none of a public class's private
# implementation.
#
# What this keeps out, measured on a build without client/qt/agentclient-qt.map:
#   * Qt and std template instantiations -- QMetaType::registerConverter and
#     registerMutableView with their GNU_UNIQUE guard variables, which keep the
#     library from ever being unloaded by dlclose; std::_Rb_tree over Qt types;
#   * the RTTI and vtable of AgentClient::Private and its three siblings, which
#     inherit default visibility from the exported class they are nested in.
# Each is bindable by a consumer and tracked by no gate.
#
#   Usage: check-clientqt-exports.sh <path-to-shared-library>
set -uo pipefail

LIB="${1:?path to the shared library required}"
[[ -f "$LIB" ]] || { echo "not a file: $LIB" >&2; exit 2; }

command -v nm >/dev/null 2>&1 || { echo "nm not found" >&2; exit 2; }

# An absence is also what a broken check reports, so first prove this reads
# the library it is meant to read. Counted, not `grep -q`: under pipefail an
# early-exiting grep fails the pipeline with SIGPIPE.
demangled="$(nm --dynamic --defined-only --demangle "$LIB" 2>/dev/null | cut -d' ' -f3-)"
symbols="$(printf '%s\n' "$demangled" | grep -c .)"
if [[ "$symbols" -lt 100 ]]; then
    echo "FAIL: $LIB yielded only $symbols dynamic symbols -- not the shared library this check reads." >&2
    exit 2
fi
own="$(printf '%s\n' "$demangled" | grep -c '^LibreSCRS::AgentClient::AgentClient::AgentClient(')"
if [[ "$own" -eq 0 ]]; then
    echo "FAIL: $LIB exports no AgentClient constructor -- wrong artifact, or the API is hidden." >&2
    exit 1
fi

api='^(((typeinfo|typeinfo name|vtable|VTT|construction vtable|guard variable) for )|((non-)?virtual thunk to ))?LibreSCRS::'
foreign="$(printf '%s\n' "$demangled" | grep -Ev "$api" || true)"
private="$(printf '%s\n' "$demangled" | grep -E '::Private(::|$| |\()' || true)"

status=0
if [[ -n "$foreign" ]]; then
    count="$(printf '%s\n' "$foreign" | grep -c .)"
    echo "FAIL: $LIB exports $count symbol(s) outside the LibreSCRS namespace:" >&2
    printf '%s\n' "$foreign" | head -20 >&2
    status=1
fi
if [[ -n "$private" ]]; then
    count="$(printf '%s\n' "$private" | grep -c .)"
    echo "FAIL: $LIB exports $count symbol(s) of a private implementation class:" >&2
    printf '%s\n' "$private" | head -20 >&2
    status=1
fi
[[ "$status" -eq 0 ]] && echo "OK: $LIB exports $symbols symbol(s), all LibreSCRS API."
exit "$status"
