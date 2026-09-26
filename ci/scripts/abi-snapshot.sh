#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.sh — capture / verify the ABI of the one shared library this
# repository ships: liblibrescrs-agentclient-qt.so (target LibreAgentClientQt,
# the LibreSCRS::AgentClient namespace; Wire + Qt6 only, no LibreMiddleware),
# which consumers link through LibreAgent::ClientQt and which distributions
# ship as a runtime package of its own.
#
# The static archives (libLibreAgentCore.a, libLibreAgentWire.a, ...) are not
# recorded. Nothing binds to them at run time: every consumer links them at
# build time from a source tree locked to a commit, so a change in them reaches
# a consumer only through a rebuild, never through an already-built binary.
# Recording them made every internal signature change a baseline edit and
# never once caught a defect.
#
# Two sections, one baseline file (ci/abi/5.x-baseline.txt):
#
#   == liblibrescrs-agentclient-qt.so ==
#       SONAME=<the library's DT_SONAME>, then one demangled T-binding symbol
#       of the dynamic table per line, filtered to LibreSCRS::AgentClient::
#       plus the shared-header functions in CLIENTQT_WIRE_PUBLIC below.
#   == layout: liblibrescrs-agentclient-qt.so ==
#       the output of the layout probe built beside the library: one line per
#       public value type (size, alignment, member count, per-member offsets).
#
# WHY THE LAYOUT SECTION. A demangled symbol diff is a statement about NAMES.
# This library's public surface is largely plain aggregates a consumer holds,
# copies and passes BY VALUE, so their size and member offsets are compiled
# into every already-built consumer. Measured, not theoretical: a member add to
# one such type changed its size by 56 bytes and the symbol diff reported 0
# added and 0 removed. So "0 added, 0 removed" must not be read as "no ABI
# impact"; the layout section is what makes that reading safe. The member
# COUNT is computed from the type itself rather than from the probe's printed
# list, which catches a member added into EXISTING PADDING. The layout section
# is not optional: a library without its probe is refused, because a
# silently-absent section is exactly how this baseline once went unguarded.
#
# REACHABLE IS NOT THE SAME AS SUPPORTED. CLIENTQT_WIRE_PUBLIC names functions
# declared in a shared header that this library's OWN public headers re-export
# (the same headers Doxyfile.publicapi's INPUT lists): a consumer that includes
# the public header sees the declaration and the .so exports the definition,
# so the symbol is bindable whether or not anyone intends it to be. Recording
# them is a statement about observability, never a promise of support
# (client/qt/include/LibreSCRS/AgentClient/SyncError.h says they are the wire
# library's API, not this one's). client/qt/CMakeLists.txt pins the set of
# re-exported shared headers and stops the configure when it changes, naming
# this list, so a new re-export cannot slip past it.
#
# What this does NOT see, on purpose:
#   - symbols outside the two namespaces above. What the library must NOT
#     export -- the vendored codec's C names, the other wire symbols -- is
#     proved by ctest cases that read its dynamic table
#     (check-vendored-exports.sh and check-wire-exports.sh beside this file);
#   - exported DATA and vague-linkage entries (vtables, typeinfo,
#     staticMetaObject): only T-binding functions are recorded;
#   - a function-template instantiation, which demangles with a return-type
#     prefix and would escape the leading-prefix match (fail-open; there is
#     none in the surface today -- extend the filter before adding one);
#   - the C1/C2 and D0/D1/D2 constructor/destructor variants, which demangle
#     to one spelling and are folded by `sort -u`. They are emitted from one
#     declaration and move together; the one-line-per-change review is worth
#     that trade.
#
# Why text and not abigail: the API is plain C++23 value types, interfaces and
# flows. A demangled T-symbol diff catches function added / removed /
# signature changed with a one-line review per change, and none of the
# cosmetic noise (typedef churn, unsigned-int vs size_t under different
# toolchains) an abidiff produces.
#
# Usage:
#   abi-snapshot.sh [--check|--update] [BUILD_DIR]
#
# Default action: --check. Default BUILD_DIR: build. --update is refused
# wherever --check could not judge, so a broken tree cannot become the
# baseline.
#
# Exit codes: 0 matches (or written), 1 drift, 2 cannot judge (no build dir,
# no library, no probe, an empty section, a missing tool, no baseline).

set -euo pipefail

# A deterministic, locale-independent sort, so the baseline lines up byte for
# byte across developer machines and runners (en_US and sr_RS collate `const&)`
# and `&&)` in opposite orders), and readelf's own strings stay in English.
export LC_ALL=C

# Tools before anything else. Every section is read through `nm | awk |
# c++filt`, and with c++filt absent the pipeline comes back empty: the empty
# section refusal would then blame the library where the truth is "this host
# cannot demangle". A missing tool is "I cannot measure", never a diagnosis.
for tool in nm c++filt readelf; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot measure the ABI surface" >&2; exit 2; }
done

ACTION="check"
BUILD_DIR="build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) ACTION="check"; shift ;;
        --update) ACTION="update"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) BUILD_DIR="$1"; shift ;;
    esac
done

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "ERROR: build dir '$BUILD_DIR' not found" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BASELINE="${REPO_ROOT}/ci/abi/5.x-baseline.txt"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

snapshot="${SCRATCH}/snapshot.txt"

LIB_SECTION="liblibrescrs-agentclient-qt.so"
LAYOUT_SECTION="layout: liblibrescrs-agentclient-qt.so"
LAYOUT_PROBE_NAME="librescrs-agentclient-qt-layout-probe"

# Shared-header symbols REACHABLE through a public client header (see
# "reachable is not the same as supported" above). Anchored and
# paren-terminated so a longer name that merely starts the same way cannot
# slip in. Extend by hand when a public header re-exports a new one.
#
#   syncErrorName / decodeSyncError
#       declared in include/LibreSCRS/Agent/wire/SyncError.h, which
#       client/qt/include/LibreSCRS/AgentClient/SyncError.h re-exports.
CLIENTQT_WIRE_PUBLIC='^LibreSCRS::Agent::Wire::(syncErrorName|decodeSyncError)\('

# --- the library -------------------------------------------------------------
# A SONAME-versioned build produces THREE paths for one real file:
# liblibrescrs-agentclient-qt.so (unversioned link), .so.5 (SONAME link) and
# .so.5.0.0 (the real file). -not -type l resolves to the one real file.
mapfile -t libs < <(find "$BUILD_DIR" -name "${LIB_SECTION}*" -not -type l | sort)
if [[ ${#libs[@]} -eq 0 ]]; then
    echo "ERROR: no ${LIB_SECTION}* under '$BUILD_DIR' -- build it first" >&2
    echo "       (LIBREAGENT_BUILD_CLIENT_QT=ON). Refusing to emit an empty snapshot." >&2
    exit 2
fi
if [[ ${#libs[@]} -gt 1 ]]; then
    echo "ERROR: multiple ${LIB_SECTION}* real files under '$BUILD_DIR':" >&2
    printf '       %s\n' "${libs[@]}" >&2
    echo "       Ambiguous snapshot source — remove the stale copies first." >&2
    exit 2
fi
lib="${libs[0]}"

# Mangled (nm -D, the dynamic table) -> T-binding filter -> demangle, in that
# order. Demangling first (`nm -DC`) emits names containing spaces, so the
# field split would truncate every symbol at its first argument, collapsing
# overloads into identical lines and hiding signature drift.
symbols="$(nm -D --defined-only "$lib" 2>/dev/null \
    | awk '$2 == "T" { print $3 }' \
    | c++filt 2>/dev/null \
    | { grep -E "^LibreSCRS::AgentClient::|${CLIENTQT_WIRE_PUBLIC}" || true; } \
    | sort -u)"
if [[ -z "$symbols" ]]; then
    echo "ERROR: no LibreSCRS::AgentClient:: T-binding symbols found in '$lib'" >&2
    echo "       (broken build, nm/c++filt failed, or a new public symbol is" >&2
    echo "       missing LIBRESCRS_AGENTCLIENT_EXPORT). Refusing to emit an empty" >&2
    echo "       snapshot." >&2
    exit 2
fi

soname="$(readelf -d "$lib" 2>/dev/null \
    | grep 'SONAME' \
    | sed -E 's/.*\[(.*)\]/\1/')"
if [[ -z "$soname" ]]; then
    echo "ERROR: no SONAME dynamic-section entry found in '$lib' (broken build?)." >&2
    exit 2
fi

# --- its layout probe (NOT optional once the library exists) -----------------
mapfile -t probes < <(find "$BUILD_DIR" -name "$LAYOUT_PROBE_NAME" -type f | sort)
if [[ ${#probes[@]} -eq 0 ]]; then
    echo "ERROR: '$lib' was found but its layout probe ('$LAYOUT_PROBE_NAME')" >&2
    echo "       was not, anywhere under '$BUILD_DIR'. The layout section is" >&2
    echo "       mandatory: a symbol diff cannot see a member added, removed or" >&2
    echo "       reordered on a public by-value type. Build the whole project (the" >&2
    echo "       probe is a top-level-build target beside the test suite)." >&2
    exit 2
fi
if [[ ${#probes[@]} -gt 1 ]]; then
    echo "ERROR: multiple '$LAYOUT_PROBE_NAME' binaries under '$BUILD_DIR':" >&2
    printf '       %s\n' "${probes[@]}" >&2
    echo "       Ambiguous snapshot source — remove the stale copies first." >&2
    exit 2
fi
layout="$("${probes[0]}")"
if [[ -z "$layout" ]]; then
    echo "ERROR: '${probes[0]}' produced no output (broken build?)." >&2
    echo "       Refusing to emit an empty layout section." >&2
    exit 2
fi

# --- assemble ----------------------------------------------------------------
sections=("$LIB_SECTION" "$LAYOUT_SECTION")
{
    echo "# LibreAgent shipped-library ABI snapshot"
    echo "# Generated by ci/scripts/abi-snapshot.sh"
    echo "# '== liblibrescrs-agentclient-qt.so ==': the SONAME, then one demangled"
    echo "# T-binding symbol of the dynamic table per line, sorted. The 'layout:'"
    echo "# section is NOT symbols: it records the SHAPE of the public value types"
    echo "# (size, alignment, member count, per-member byte offsets), because a"
    echo "# symbol diff is blind to a member added, removed or reordered on a type"
    echo "# consumers copy by value. A clean symbol diff alone therefore does NOT"
    echo "# mean 'no ABI impact' — read both. The script's header says what is"
    echo "# recorded and what is deliberately not."
    echo "# Re-generate with: ci/scripts/abi-snapshot.sh --update <build_dir>"
    echo "# Diff a fresh build against this baseline with: ci/scripts/abi-snapshot.sh --check"
    echo "== ${LIB_SECTION} =="
    echo "SONAME=${soname}"
    printf '%s\n' "$symbols"
    echo "== ${LAYOUT_SECTION} =="
    printf '%s\n' "$layout"
} > "$snapshot"

# extract_section FILE SECTION — the body of "== SECTION ==", up to (not
# including) the next "== ... ==" header or EOF.
extract_section() {
    local file="$1" name="$2"
    awk -v want="== ${name} ==" '
        /^== .* ==$/ { in_section = ($0 == want); next }
        in_section { print }
    ' "$file"
}

case "$ACTION" in
    update)
        mkdir -p "$(dirname "$BASELINE")"
        cp "$snapshot" "$BASELINE"
        echo "Wrote ABI baseline: $BASELINE"
        wc -l "$BASELINE"
        ;;
    check)
        if [[ ! -f "$BASELINE" ]]; then
            echo "ERROR: baseline not found at $BASELINE" >&2
            echo "       Run 'ci/scripts/abi-snapshot.sh --update <build_dir>' to capture." >&2
            exit 2
        fi
        drift=0
        checked_lines=0
        for section in "${sections[@]}"; do
            baseline_part="${SCRATCH}/baseline--${section}"
            snapshot_part="${SCRATCH}/snapshot--${section}"
            extract_section "$BASELINE" "$section" > "$baseline_part"
            extract_section "$snapshot" "$section" > "$snapshot_part"
            checked_lines=$((checked_lines + $(wc -l < "$snapshot_part")))

            # A section the baseline does not carry AT ALL is called out on its
            # own: against an absent section every line reads as an addition,
            # including a symbol that was really REMOVED or changed signature.
            if [[ ! -s "$baseline_part" ]]; then
                echo "ERROR: section '${section}' is ABSENT from $BASELINE." >&2
                echo "       Every line below reads as an addition -- including any" >&2
                echo "       symbol that was actually REMOVED or had its signature" >&2
                echo "       changed. Regenerate and review the result as a whole." >&2
            fi

            diff_out="${SCRATCH}/diff--${section}"
            if ! diff -u --label "baseline: ${section}" --label "current: ${section}" \
                    "$baseline_part" "$snapshot_part" > "$diff_out"; then
                drift=1
                added="$(grep -c '^+[^+]' "$diff_out" || true)"
                removed="$(grep -c '^-[^-]' "$diff_out" || true)"
                echo "ABI DRIFT detected in section '${section}' vs $BASELINE" >&2
                echo "  (${added} added, ${removed} removed):" >&2
                cat "$diff_out" >&2
                echo >&2
            fi
        done

        if [[ $drift -eq 0 ]]; then
            echo "ABI snapshot matches baseline for section(s): ${sections[*]} (${checked_lines} lines)."
            exit 0
        fi
        echo "If this drift is intentional (a new public API addition or" >&2
        echo "an explicit breaking change for a major bump):" >&2
        echo "   ci/scripts/abi-snapshot.sh --update $BUILD_DIR" >&2
        exit 1
        ;;
esac
