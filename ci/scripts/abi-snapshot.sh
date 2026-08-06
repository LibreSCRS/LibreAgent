#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.sh — capture / verify the LibreAgent public C++ API surface.
#
# LibreAgent's installable surface spans three independent artefacts — one
# per shipped CONFIG component — each its own section in one baseline file:
#   - libLibreAgentCore.a: the static archive exposing the platform-neutral
#     agent core behind the LibreSCRS::Agent namespace (LM-backed);
#     consumers link it through the installed LibreAgent::Core CONFIG
#     package.
#   - libLibreAgentWire.a: the static archive exposing the shared message
#     vocabulary behind LibreSCRS::Agent::Wire, linked through the
#     LibreAgent::Wire CONFIG component. It is a first-class installed
#     component with its own consumers, so it gets its own section for
#     exactly the reason Core does. (Its symbols ALSO appear inside the
#     ClientQt shared object, because that target folds this archive in
#     privately — but that is a different artefact with a different
#     filter, and a symbol being gated here says nothing about whether
#     the .so is allowed to export it.)
#   - liblibrescrs-agentclient-qt.so (target LibreAgentClientQt, OUTPUT_NAME
#     librescrs-agentclient-qt): the Qt client shared library exposing the
#     LibreSCRS::AgentClient namespace (Wire + Qt6 only, no LM); consumers
#     link it through LibreAgent::ClientQt.
# Each component is independently buildable (LIBREAGENT_BUILD_CORE /
# LIBREAGENT_BUILD_WIRE / LIBREAGENT_BUILD_CLIENT_QT), so any section may be
# legitimately absent from a given build's snapshot. --check is section-aware:
# it only compares
# the sections the CURRENT build actually produced against the matching
# section of the baseline, so a configuration missing a component (a
# Core-less ClientQt build, a packaging build, ...) is never reported as
# drift just because it never produced the other section. At least one
# section must be non-empty, or the run refuses to produce a snapshot at
# all — see the guard below.
#
# Unlike a shared object with visibility controls, a static archive also
# carries every internal TU-level helper as a T-binding symbol. The Core
# section is therefore filtered to the LibreSCRS::Agent:: prefix: that
# namespace is the public, frozen API; anything outside it is an
# implementation detail free to churn between releases.
#
# The ClientQt section IS a shared object with CXX_VISIBILITY_PRESET hidden,
# but is filtered by namespace anyway, for a different reason: hidden
# visibility on LibreAgentClientQt does not reach LibreAgentWire's objects —
# Wire is a STATIC archive linked PRIVATE and folded straight into the .so,
# and CMake's hidden-visibility default only governs symbols this target's
# OWN translation units define — so the shared library's dynamic symbol table
# also exports the entire LibreSCRS::Agent:: wire surface. That is a real,
# pre-existing leak; fixing it (re-exporting Wire hidden, or a version
# script) is a follow-up, not this snapshot's job. Recording the whole leak
# here would make it permanent, spurious drift — every unrelated churn inside
# Wire would land in this baseline as reviewable API movement, which it is
# not.
#
# MEASURED SIZE OF THAT LEAK, so nobody has to guess at it: of the 279
# T-binding symbols the .so exports (demangled, deduplicated), only 113 are
# this library's own LibreSCRS::AgentClient:: API. The other 166 break down as
# 49 LibreSCRS::Agent::Wire:: symbols and 117 vendored QCBOR C symbols
# (QCBOR*, UsefulBuf_*, UsefulInputBuf_*, UsefulOutBuf_*, IEEE754_*). Two of
# the 49 are deliberately reachable (below), so the ACCIDENTAL leak is 164
# symbols — not the wire namespace alone.
#
# The vendored-C half is the part with teeth, and it is a real hazard rather
# than untidiness: those are unversioned, unmangled C symbols in a shared
# library's dynamic table. ELF resolves by name across the whole process, so a
# consumer that also links QCBOR — directly, or through any other library that
# vendored it — can have ITS calls bound to this .so's copy, or vice versa,
# whichever the loader sees first. If the two copies are different QCBOR
# versions, the mismatch is silent and structural. Fixing it means giving
# these symbols hidden visibility or a version script; that is a larger change
# than this snapshot, and deliberately not attempted here. Recorded so that it
# is a known, sized hazard instead of a surprise.
#
# For what this script RECORDS, though, "exclude the whole LibreSCRS::Agent::
# namespace" is too blunt, because it lumps together two things that differ:
#
#   - ACCIDENTAL leak: exported only because an archive is statically folded
#     in. No public header of this library mentions it, nothing points a
#     consumer at it, and it is free to churn. Excluded, deliberately —
#     recording it would turn every unrelated churn inside Wire or QCBOR into
#     reviewable API movement, which it is not.
#   - REACHABLE THROUGH A PUBLIC HEADER: declared in a shared header that this
#     library's OWN public headers re-export (the same headers listed in
#     Doxyfile.publicapi's INPUT, for the same reason). A consumer that
#     includes the public header sees the declaration and the .so exports the
#     definition, so the symbol is bindable whether or not anyone intends it
#     to be.
#
# REACHABLE IS NOT THE SAME AS SUPPORTED, and this script takes no position on
# support. client/qt/include/LibreSCRS/AgentClient/SyncError.h is explicit
# that its two re-exported functions are the WIRE library's API, not this
# one's, and that a consumer linking only this library must not call them —
# that policy stands unchanged. They are gated here precisely BECAUSE the
# combination (declared by a public header, exported by the .so, unsupported)
# is the shape a consumer can bind to by accident: recording them means a
# removal or signature change is visible instead of silent. Gating a symbol
# here is a statement about observability, never a promise of support.
#
# The rule this script implements is therefore: the ClientQt section records
# every LibreSCRS::AgentClient:: symbol, PLUS the shared-header symbols named
# in CLIENTQT_WIRE_PUBLIC below — and nothing else from LibreSCRS::Agent::.
#
# CLIENTQT_WIRE_PUBLIC is an explicit list rather than something derived from
# the headers, because there is no reliable way to ask `nm` which header
# declared a symbol. It has to be extended by hand the moment a public client
# header starts re-exporting a shared header that declares FUNCTIONS. (Headers
# declaring only enums/constants — ErrorCode.h, OperationPhase.h,
# PreReadAuth.h — emit no symbols at all and need no entry.)
#
# That hand-editing is NOT left to memory: client/qt/CMakeLists.txt pins the
# set of shared headers the public client headers re-export and FATAL_ERRORs
# at configure time when it changes, naming this allowlist and
# Doxyfile.publicapi's INPUT as the two things to update. So a new re-export
# cannot reach a build without someone being told about this list — which is
# what turns a silent omission into a stopped build.
#
# A new public free function in the ClientQt surface must carry
# LIBRESCRS_AGENTCLIENT_EXPORT, or it never enters `nm -D`'s table at all;
# since this script keeps only T-binding entries, a missing export macro
# makes the symbol silently absent from the section rather than flagged —
# there is no way for this script to detect that omission after the fact.
# (`inline constexpr` constants are a different, expected case: they emit no
# symbol at all, exported or not, and their absence here is not a signal.)
#
# Known filter gaps (they apply to every symbol section):
#
#   - Every section is filtered to this project's own namespace, so a symbol
#     exported from a VENDORED dependency folded into one of these artifacts is
#     invisible here and always was. That is deliberate — this baseline tracks
#     the project's ABI, not its link closure — but it means this gate is not
#     the one watching for a vendored C library leaking its unmangled names
#     into a shared object's dynamic table. ClientQtVendoredExportsTest watches
#     that, by reading the built library's dynamic symbol table directly.
#     Corollary worth stating because it is counter-intuitive: hiding 111 such
#     symbols moved this baseline by ZERO lines.
#   - A function-template instantiation demangles with a return-type prefix
#     (e.g. "std::shared_ptr<T> LibreSCRS::Agent::f<..>(..)") and would escape
#     the leading-prefix match — fail-open. No surface contains such symbols
#     today; extend the filter before adding the first public function
#     template.
#   - Demangling COLLAPSES the C1/C2 and D0/D1/D2 constructor and destructor
#     ABI variants onto one spelling, and the `sort -u` then folds them into a
#     single line. Measured on the ClientQt surface: 131 demangled T-symbols
#     become 113 unique lines. 14 spellings account for that — 4 destructors
#     emitted in THREE variants each (D0/D1/D2) and 10 constructors/destructors
#     in two — so 32 mangled symbols are recorded as 14 lines, and 18 is the
#     SURPLUS that disappears, not the number of symbols involved. A change
#     that dropped, say, only the deleting destructor while keeping the
#     complete-object one would therefore not move this baseline. That is an
#     accepted trade: the alternative is recording mangled names, which makes
#     every line unreadable and the one-line-per-change review this file exists
#     for impossible. The variants are emitted by the compiler from one source
#     declaration, so they move together in practice — a source-level removal
#     still shows up.
#
# A FURTHER dimension, beside the symbol sections: LAYOUT.
#
# A demangled symbol diff is a statement about NAMES. It says nothing about
# the shape of the data those names carry, and this library's public surface
# is largely plain aggregates a consumer holds, copies and passes BY VALUE —
# so their size and member offsets are compiled into every already-built
# consumer. Add, remove or reorder a member and those consumers read the old
# offsets against the new object, silently, while the symbol surface does not
# move by a single line. Measured, not theoretical: a member add to one such
# type changed its size by 56 bytes and the symbol diff reported 0 added and
# 0 removed, because the type's NAME appears nowhere in an export table.
#
# So "0 added, 0 removed" must not be read as "no ABI impact". The layout
# section below is what makes that reading safe: a probe binary built beside
# the library prints one line per public value type (size, alignment, member
# count, per-member offsets) and this script records that output as its own
# section, diffed by --check exactly like the symbol sections. The member
# COUNT is computed from the type itself rather than from the probe's printed
# list, which is what catches the nastiest case — a member added into EXISTING
# PADDING, where size and every existing offset stay put.
#
# The layout section is NOT independently optional: when the ClientQt library
# is present but its probe binary is not, this script fails rather than
# quietly emitting a snapshot without it. A silently-absent section is exactly
# how the ClientQt symbol section came to be missing from the baseline while
# --check still reported success on the sections it did compare.
#
# This script generates a stable, sorted, human-readable text artefact
# checked into the tree at:
#   ci/abi/4.x-baseline.txt
#
# Use --check to compare a fresh build against the baseline; the script
# fails non-zero on any difference in a section the current build produced.
# Use --update to regenerate the baseline from the sections the current
# build produced — run it from a full build (every component ON) so a
# partial build's --update does not drop another component's section from
# the baseline.
#
# Why text not abigail/abicompat: the API is plain C++23 value types,
# interfaces and flows. A demangled T-symbol diff catches the cases that
# matter — function added / removed / signature changed — with a one-line
# review per change, and none of the cosmetic XML noise (typedef churn,
# unsigned-int vs size_t under different toolchains) an abidiff produces.
#
# Usage:
#   abi-snapshot.sh [--check|--update] [BUILD_DIR]
#
# Default action: --check. Default BUILD_DIR: build.

set -euo pipefail

# Force a deterministic, locale-independent sort so the baseline lines
# up byte-for-byte across developer machines and CI runners. Without
# LC_ALL=C, glibc's default UTF-8 collation interleaves alphabetic and
# punctuation differently than ASCII (e.g. en_US.UTF-8 sorts
# `…CancelSource const&)` before `…CancelSource&&)` while sr_RS sorts
# the other way), and any diff against the baseline is pure noise. This
# also keeps readelf's own diagnostic strings (e.g. the SONAME tag name)
# in English regardless of the runner's locale.
export LC_ALL=C

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
BASELINE="${REPO_ROOT}/ci/abi/4.x-baseline.txt"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

snapshot="${SCRATCH}/snapshot.txt"

CORE_SECTION="libLibreAgentCore.a"
WIRE_SECTION="libLibreAgentWire.a"
CLIENTQT_SECTION="liblibrescrs-agentclient-qt.so"
CLIENTQT_LAYOUT_SECTION="layout: liblibrescrs-agentclient-qt.so"
LAYOUT_PROBE_NAME="librescrs-agentclient-qt-layout-probe"

# Shared-header symbols REACHABLE through a public client header (not
# "supported" — see the reachable-is-not-supported paragraph in this file's
# header comment, and SyncError.h's own non-support warning, which stands).
# Anchored and paren-terminated so a longer name that merely starts the same way
# cannot slip in. Extend by hand when a public header re-exports a new one.
#
#   syncErrorName / decodeSyncError
#       declared in include/LibreSCRS/Agent/wire/SyncError.h, which
#       client/qt/include/LibreSCRS/AgentClient/SyncError.h re-exports.
CLIENTQT_WIRE_PUBLIC='^LibreSCRS::Agent::Wire::(syncErrorName|decodeSyncError)\('

# --- Core section (optional: LIBREAGENT_BUILD_CORE may be OFF) -------------

core_found=0
core_symbols=""
mapfile -t core_archives < <(find "$BUILD_DIR" -name 'libLibreAgentCore.a' | sort)
if [[ ${#core_archives[@]} -gt 1 ]]; then
    echo "ERROR: multiple libLibreAgentCore.a archives under '$BUILD_DIR':" >&2
    printf '       %s\n' "${core_archives[@]}" >&2
    echo "       Ambiguous snapshot source — remove the stale copies first." >&2
    exit 2
fi
if [[ ${#core_archives[@]} -eq 1 ]]; then
    core_found=1
    core_archive="${core_archives[0]}"

    # Mangled (nm -U) -> T-binding filter -> demangle (c++filt), in that
    # order. Demangling BEFORE the T-binding filter (e.g. `nm -UC`) emits
    # names containing spaces, so a naive `awk '{print $3}'` split would
    # truncate every symbol at its first paren argument, collapsing
    # overloads into identical lines and hiding signature drift — exactly
    # what this gate exists to catch.
    core_symbols="$(nm -U "$core_archive" 2>/dev/null \
        | awk '$2 == "T" { print $3 }' \
        | c++filt 2>/dev/null \
        | { grep '^LibreSCRS::Agent::' || true; } \
        | sort -u)"

    if [[ -z "$core_symbols" ]]; then
        echo "ERROR: no LibreSCRS::Agent:: T-binding symbols found in '$core_archive'" >&2
        echo "       (broken archive, or nm/c++filt failed). Refusing to emit an" >&2
        echo "       empty snapshot for this section." >&2
        exit 2
    fi
fi

# --- Wire section (optional: LIBREAGENT_BUILD_WIRE may be OFF) ------------
#
# Same static-archive treatment as Core, filtered to LibreSCRS::Agent::Wire::
# (the archive also carries the vendored QCBOR C symbols and every internal
# TU-level helper as T-bindings; neither is this component's API).

wire_found=0
wire_symbols=""
mapfile -t wire_archives < <(find "$BUILD_DIR" -name 'libLibreAgentWire.a' | sort)
if [[ ${#wire_archives[@]} -gt 1 ]]; then
    echo "ERROR: multiple libLibreAgentWire.a archives under '$BUILD_DIR':" >&2
    printf '       %s\n' "${wire_archives[@]}" >&2
    echo "       Ambiguous snapshot source — remove the stale copies first." >&2
    exit 2
fi
if [[ ${#wire_archives[@]} -eq 1 ]]; then
    wire_found=1
    wire_archive="${wire_archives[0]}"

    wire_symbols="$(nm -U "$wire_archive" 2>/dev/null \
        | awk '$2 == "T" { print $3 }' \
        | c++filt 2>/dev/null \
        | { grep '^LibreSCRS::Agent::Wire::' || true; } \
        | sort -u)"

    if [[ -z "$wire_symbols" ]]; then
        echo "ERROR: no LibreSCRS::Agent::Wire:: T-binding symbols found in" >&2
        echo "       '$wire_archive' (broken archive, or nm/c++filt failed)." >&2
        echo "       Refusing to emit an empty snapshot for this section." >&2
        exit 2
    fi
fi

# --- ClientQt section (optional: LIBREAGENT_BUILD_CLIENT_QT may be OFF) ----

clientqt_found=0
clientqt_symbols=""
clientqt_soname=""
clientqt_layout=""
# The SONAME-versioned build produces THREE paths for one real file:
# liblibrescrs-agentclient-qt.so (unversioned symlink),
# liblibrescrs-agentclient-qt.so.4 (SONAME symlink), and
# liblibrescrs-agentclient-qt.so.4.2.0 (the real file). -not -type l
# resolves to the one real file instead of reusing the archive section's
# single-match guard, which would trip on these three paths every time.
mapfile -t clientqt_libs < <(find "$BUILD_DIR" -name "${CLIENTQT_SECTION}*" -not -type l | sort)
if [[ ${#clientqt_libs[@]} -gt 1 ]]; then
    echo "ERROR: multiple ${CLIENTQT_SECTION}* real files under '$BUILD_DIR':" >&2
    printf '       %s\n' "${clientqt_libs[@]}" >&2
    echo "       Ambiguous snapshot source — remove the stale copies first." >&2
    exit 2
fi
if [[ ${#clientqt_libs[@]} -eq 1 ]]; then
    clientqt_found=1
    clientqt_lib="${clientqt_libs[0]}"

    # Same mangled -> T-binding filter -> demangle order as the Core
    # section above (nm -D --defined-only reads the dynamic symbol table
    # instead of nm -U's relocatable-object table, since this artefact is a
    # shared object, not a static archive).
    clientqt_symbols="$(nm -D --defined-only "$clientqt_lib" 2>/dev/null \
        | awk '$2 == "T" { print $3 }' \
        | c++filt 2>/dev/null \
        | { grep -E "^LibreSCRS::AgentClient::|${CLIENTQT_WIRE_PUBLIC}" || true; } \
        | sort -u)"

    if [[ -z "$clientqt_symbols" ]]; then
        echo "ERROR: no LibreSCRS::AgentClient:: T-binding symbols found in '$clientqt_lib'" >&2
        echo "       (broken build, nm/c++filt failed, or a new public symbol is" >&2
        echo "       missing LIBRESCRS_AGENTCLIENT_EXPORT). Refusing to emit an empty" >&2
        echo "       snapshot for this section." >&2
        exit 2
    fi

    clientqt_soname="$(readelf -d "$clientqt_lib" 2>/dev/null \
        | grep 'SONAME' \
        | sed -E 's/.*\[(.*)\]/\1/')"
    if [[ -z "$clientqt_soname" ]]; then
        echo "ERROR: no SONAME dynamic-section entry found in '$clientqt_lib'" >&2
        echo "       (broken build?)." >&2
        exit 2
    fi

    # --- ClientQt LAYOUT section (NOT optional once the library exists) ----
    #
    # Deliberately a hard failure rather than a skipped section: the layout
    # dimension is the only thing in this gate that can see a member added,
    # removed or reordered on a by-value public type, and a gate that loses a
    # dimension by silently not finding a file is the exact failure this
    # baseline has already suffered once.
    mapfile -t layout_probes < <(find "$BUILD_DIR" -name "$LAYOUT_PROBE_NAME" -type f | sort)
    if [[ ${#layout_probes[@]} -eq 0 ]]; then
        echo "ERROR: '$clientqt_lib' was found but its layout probe" >&2
        echo "       ('$LAYOUT_PROBE_NAME') was not, anywhere under '$BUILD_DIR'." >&2
        echo "       The layout section is mandatory whenever the ClientQt library is" >&2
        echo "       present — a symbol diff cannot see a member add/remove/reorder on" >&2
        echo "       a public by-value type. Build the whole project (the probe is a" >&2
        echo "       top-level-build target beside the test suite) and re-run." >&2
        exit 2
    fi
    if [[ ${#layout_probes[@]} -gt 1 ]]; then
        echo "ERROR: multiple '$LAYOUT_PROBE_NAME' binaries under '$BUILD_DIR':" >&2
        printf '       %s\n' "${layout_probes[@]}" >&2
        echo "       Ambiguous snapshot source — remove the stale copies first." >&2
        exit 2
    fi
    clientqt_layout="$("${layout_probes[0]}")"
    if [[ -z "$clientqt_layout" ]]; then
        echo "ERROR: '${layout_probes[0]}' produced no output (broken build?)." >&2
        echo "       Refusing to emit an empty layout section." >&2
        exit 2
    fi
fi

# --- Overall guard: refuse a header-only (every section absent) snapshot --
#
# The original single-archive script refused to write an empty snapshot at
# all; making each section independently optional would otherwise let a
# misconfigured build (no component ON, or all silently broken)
# produce a header-only file that --update writes as the baseline. Require
# at least one non-empty section instead.
if [[ $core_found -eq 0 && $wire_found -eq 0 && $clientqt_found -eq 0 ]]; then
    echo "ERROR: none of libLibreAgentCore.a, ${WIRE_SECTION} or" >&2
    echo "       ${CLIENTQT_SECTION}* was found under '$BUILD_DIR' — build first" >&2
    echo "       (LIBREAGENT_BUILD_CORE / LIBREAGENT_BUILD_WIRE /" >&2
    echo "       LIBREAGENT_BUILD_CLIENT_QT must be ON). Refusing to emit an" >&2
    echo "       empty snapshot." >&2
    exit 2
fi

# --- Assemble the snapshot --------------------------------------------------

sections=()
{
    echo "# LibreAgent public API snapshot"
    echo "# Generated by ci/scripts/abi-snapshot.sh"
    echo "# Format: one demangled T-binding symbol per line, sorted within each"
    echo "# section; section header line '== <component> =='. A component's"
    echo "# section is present only when that component was built for this"
    echo "# snapshot (LIBREAGENT_BUILD_CORE / LIBREAGENT_BUILD_WIRE /"
    echo "# LIBREAGENT_BUILD_CLIENT_QT) — see the file header comment in this"
    echo "# script for the full per-section rationale (why each is filtered the"
    echo "# way it is, and why the symbol sections are never merged into one)."
    echo "#"
    echo "# The 'layout:' section is NOT symbols: it records the SHAPE of the"
    echo "# public value types (size, alignment, member count, per-member byte"
    echo "# offsets), because a symbol diff is blind to a member added, removed"
    echo "# or reordered on a type consumers copy by value. A clean symbol diff"
    echo "# alone therefore does NOT mean 'no ABI impact' — read both."
    echo "# Re-generate with: ci/scripts/abi-snapshot.sh --update <build_dir>"
    echo "# Diff a fresh build against this baseline with: ci/scripts/abi-snapshot.sh --check"
    if [[ $core_found -eq 1 ]]; then
        echo "== ${CORE_SECTION} =="
        printf '%s\n' "$core_symbols"
        sections+=("$CORE_SECTION")
    fi
    if [[ $wire_found -eq 1 ]]; then
        echo "== ${WIRE_SECTION} =="
        printf '%s\n' "$wire_symbols"
        sections+=("$WIRE_SECTION")
    fi
    if [[ $clientqt_found -eq 1 ]]; then
        echo "== ${CLIENTQT_SECTION} =="
        echo "SONAME=${clientqt_soname}"
        printf '%s\n' "$clientqt_symbols"
        sections+=("$CLIENTQT_SECTION")

        echo "== ${CLIENTQT_LAYOUT_SECTION} =="
        printf '%s\n' "$clientqt_layout"
        sections+=("$CLIENTQT_LAYOUT_SECTION")
    fi
} > "$snapshot"

# extract_section FILE SECTION — print the body of section "== SECTION =="
# from FILE, up to (not including) the next "== ... ==" header or EOF.
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
        echo "Sections captured: ${sections[*]}"
        wc -l "$BASELINE"
        ;;
    check)
        if [[ ! -f "$BASELINE" ]]; then
            echo "ERROR: baseline not found at $BASELINE" >&2
            echo "       Run 'ci/scripts/abi-snapshot.sh --update <build_dir>' to capture." >&2
            exit 2
        fi

        # Section-aware: only the sections THIS build produced are compared,
        # each against its own matching section in the baseline. A build
        # missing a component (client-lm-less, a packaging build, ...) never
        # sees the section it didn't produce, so it is never penalised for
        # not producing it — comparing a partial snapshot against the full
        # baseline wholesale would otherwise fail on pure noise.
        drift=0
        checked_lines=0
        for section in "${sections[@]}"; do
            baseline_part="${SCRATCH}/baseline--${section}"
            snapshot_part="${SCRATCH}/snapshot--${section}"
            extract_section "$BASELINE" "$section" > "$baseline_part"
            extract_section "$snapshot" "$section" > "$snapshot_part"
            checked_lines=$((checked_lines + $(wc -l < "$snapshot_part")))

            # A section the current build produced but the baseline does not
            # carry AT ALL is called out on its own, before the diff. Left to
            # the plain diff it reads as a large, benign-looking pile of
            # additions — which is precisely how a genuine REMOVAL inside such
            # a section (a symbol replaced by a differently-signed one) once
            # went unnoticed: against an absent baseline section there is
            # nothing for a removal to be missing FROM, so the gate cannot see
            # one and the diff says "added" about everything.
            if [[ ! -s "$baseline_part" ]]; then
                echo "ERROR: section '${section}' is ABSENT from $BASELINE." >&2
                echo "       This build produced it, so every line below reads as an" >&2
                echo "       addition — including any symbol that was actually REMOVED or" >&2
                echo "       had its signature changed. Nothing in this section has been" >&2
                echo "       gated until the baseline records it. Regenerate from a FULL" >&2
                echo "       build and review the result as a whole, not as a diff." >&2
            fi

            diff_out="${SCRATCH}/diff--${section}"
            if ! diff -u --label "baseline: ${section}" --label "current: ${section}" \
                    "$baseline_part" "$snapshot_part" > "$diff_out"; then
                drift=1
                # Counted from the unified diff body, excluding its two header
                # lines, so the summary states what the diff actually contains
                # rather than leaving a reader to eyeball it.
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
        else
            echo "If this drift is intentional (a new public API addition or" >&2
            echo "an explicit breaking change for a major bump):" >&2
            echo "   ci/scripts/abi-snapshot.sh --update $BUILD_DIR" >&2
            exit 1
        fi
        ;;
esac
