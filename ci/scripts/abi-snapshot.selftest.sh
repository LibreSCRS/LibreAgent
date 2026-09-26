#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.selftest.sh — prove the ABI snapshot can fail, and can refuse.
#
# This gate is the last thing standing between a silently changed ABI of the
# shipped client library and a release tag. Every case builds a throwaway
# repository under /var/tmp (never /tmp, a RAM filesystem on the development
# host) holding a copy of the gate, a stub shared library named, versioned and
# SONAMEd the way CMake builds the real one, and a stub layout probe. The stubs
# are the point: a case that leaned on this repository's own build tree would
# measure whatever was last built there.
#
# Cases:
#   1  control: --update over the stub tree, then --check          -> 0
#   2  one symbol removed from the baseline                        -> 1
#   3  one exported symbol removed from the library                -> 1
#   4  an empty build tree, --check                                -> 2
#   5  an empty build tree, --update: refused, baseline untouched   -> 2
#   6  control: the same run under a PATH shim that HAS c++filt    -> 0
#   7  c++filt taken off PATH                                      -> 2
#   8  the SONAME moves                                            -> 1
#   9  the layout probe is missing                                 -> 2
#  10  one type's layout changes, the symbols do not               -> 1
#  11  the re-exported wire function is recorded, and its loss is drift -> 1
#  12  a symbol outside the recorded namespaces is not recorded    -> 0
#  13  two real library files in one tree                          -> 2
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SUBJECT:-$HERE/abi-snapshot.sh}"
[ -f "$SUBJECT" ] || { echo "FATAL: $SUBJECT is missing" >&2; exit 2; }

# A compiler is the only way to get a shared library whose dynamic table this
# file controls. Without one the answer is "I could not measure".
for tool in g++ nm c++filt readelf; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot build the fixture" >&2; exit 2; }
done

WORK="$(mktemp -d /var/tmp/abi-snapshot-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fails=0

check() {  # check <label> <want-rc> <got-rc>
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero over a
    # perturbed input.
    if [ "$2" != 0 ]; then red=$((red + 1)); fi
    if [ "$2" = "$3" ]; then
        printf 'ok    %-58s rc=%s\n' "$1" "$3"
    else
        printf 'FAIL  %-58s rc=%s want=%s\n' "$1" "$3" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

says() {  # says <label> <text>
    if grep -qF -- "$2" "$WORK/out"; then
        printf 'ok    %-58s says %s\n' "$1" "$2"
    else
        printf 'FAIL  %-58s does not say %s\n' "$1" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

LIB=liblibrescrs-agentclient-qt.so
PROBE=librescrs-agentclient-qt-layout-probe

# library <root> <soname> <source> -- compile a stub library into <root>/build
# the way CMake lays out the real one: the real file and its two links.
library() {
    local root="$1" soname="$2" src="$3"
    printf '%s\n' "$src" > "$root/stub.cpp"
    rm -f "$root/build/$LIB" "$root/build/$LIB".*
    g++ -std=c++20 -shared -fPIC -Wl,-soname,"$soname" \
        -o "$root/build/$LIB.5.0.0" "$root/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not compile the stub library" >&2; sed 's/^/        /' "$WORK/gcc.err" >&2; exit 2; }
    ln -sf "$LIB.5.0.0" "$root/build/$LIB.5"
    ln -sf "$LIB.5" "$root/build/$LIB"
}

# probe <root> <text> -- a stub layout probe printing <text>.
probe() {
    mkdir -p "$1/build/client/qt"
    printf '#!/bin/sh\ncat <<"EOF"\n%s\nEOF\n' "$2" > "$1/build/client/qt/$PROBE"
    chmod 0755 "$1/build/client/qt/$PROBE"
}

SRC_FULL='namespace LibreSCRS::AgentClient {
int selftestAlpha(int x) { return x + 1; }
int selftestBeta(int x) { return x + 2; }
int selftestGamma(int x) { return x + 3; }
}
namespace LibreSCRS::Agent::Wire {
int syncErrorName(int x) { return x; }
int notReExported(int x) { return x * 2; }
}
extern "C" int selftestVendoredCName(int x) { return x; }'
LAYOUT_GOOD='Alpha size=24 align=8 members=2 a@0 b@8
Beta size=16 align=8 members=1 c@0'

# stub <name> [source] [soname] -> prints the fixture root
stub() {
    local name="$1"
    local src="${2:-$SRC_FULL}"
    local soname="${3:-$LIB.5}"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/ci/abi" "$root/build"
    cp "$SUBJECT" "$root/ci/scripts/abi-snapshot.sh"
    chmod 0755 "$root/ci/scripts/abi-snapshot.sh"
    library "$root" "$soname" "$src"
    probe "$root" "$LAYOUT_GOOD"
    printf '%s' "$root"
}

run() {  # run <root> <args...> -> rc; output in $WORK/out
    local root="$1"; shift
    if ( cd "$root" && ./ci/scripts/abi-snapshot.sh "$@" ) > "$WORK/out" 2>&1; then
        echo 0
    else
        echo $?
    fi
}

# --- case 1: the control. Without it every refusal below could be an error path.
root="$(stub control)"
rc=$(run "$root" --update build)
check "control: --update over the stub tree" 0 "$rc"
# What --update wrote must carry each of the three things this gate records,
# or every drift case below could pass by comparing two copies of nothing.
for want in selftestBeta 'SONAME=liblibrescrs-agentclient-qt.so.5' 'Beta size=16'; do
    if grep -qF "$want" "$root/ci/abi/5.x-baseline.txt"; then
        printf 'ok    %-58s records %s\n' "control: the baseline" "$want"
    else
        printf 'FAIL  %-58s does not record %s\n' "control: the baseline" "$want"
        fails=$((fails + 1))
    fi
done
rc=$(run "$root" --check build)
check "control: --check against what --update wrote" 0 "$rc"
command cp -f "$root/ci/abi/5.x-baseline.txt" "$WORK/baseline.good"

# perturb <root> <sed-expr>: edit the fixture's baseline and prove it changed.
perturb() {
    sed "$2" "$WORK/baseline.good" > "$1/ci/abi/5.x-baseline.txt"
    if cmp -s "$WORK/baseline.good" "$1/ci/abi/5.x-baseline.txt"; then
        echo "FATAL: the perturbation '$2' changed nothing -- it would pass for the wrong reason" >&2
        exit 2
    fi
}

# --- case 2: the baseline loses a symbol -- drift from the recorded side.
root2="$(stub baseline-short)"
perturb "$root2" '/selftestBeta/d'
rc=$(run "$root2" --check build)
check "a symbol missing from the baseline is drift" 1 "$rc"
says "a symbol missing from the baseline is drift" "selftestBeta"

# --- case 3: the library loses a symbol -- drift from the measured side.
root3="$(stub library-short "${SRC_FULL/int selftestBeta(int x) \{ return x + 2; \}/}")"
if nm -D --defined-only "$root3/build/$LIB.5.0.0" | grep -q selftestBeta; then
    echo "FATAL: the short library still exports selftestBeta" >&2; exit 2
fi
command cp -f "$WORK/baseline.good" "$root3/ci/abi/5.x-baseline.txt"
rc=$(run "$root3" --check build)
check "a symbol missing from the library is drift" 1 "$rc"
says "a symbol missing from the library is drift" "selftestBeta"

# --- case 4/5: a tree that ships nothing. This is the one that could disarm the
#     gate for every later run, so --update must refuse and leave the baseline
#     byte-for-byte as it was.
root4="$(stub empty-tree)"
command cp -f "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"
rm -f "$root4/build/$LIB" "$root4/build/$LIB".*
rc=$(run "$root4" --check build)
check "an empty tree cannot be judged" 2 "$rc"
rc=$(run "$root4" --update build)
check "an empty tree is refused by --update" 2 "$rc"
if cmp -s "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-58s baseline untouched\n' "the refused --update wrote nothing"
else
    printf 'FAIL  %-58s the refused --update overwrote the baseline\n' "the refused --update wrote nothing"
    fails=$((fails + 1))
fi

# --- case 6/7: the tool that was silenced. The shim is proved to work with
#     c++filt present before c++filt is taken out of it, or a broken shim
#     would read as the finding.
SHIM="$WORK/shim"
mkdir -p "$SHIM"
for t in bash sh nm c++filt awk sort find wc basename dirname mktemp diff cat sed grep cp mkdir rm head tr env printf ls uname readelf; do
    p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$SHIM/$t"
done
root5="$(stub shim-tree)"
command cp -f "$WORK/baseline.good" "$root5/ci/abi/5.x-baseline.txt"
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "control: the PATH shim with c++filt still judges" 0 "$rc"
rm -f "$SHIM/c++filt"
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "c++filt off PATH is 'cannot measure'" 2 "$rc"
says "c++filt off PATH is 'cannot measure'" "c++filt not found on PATH"

# --- case 8: the SONAME moves, every symbol stays.
root8="$(stub soname-moved "$SRC_FULL" "$LIB.6")"
command cp -f "$WORK/baseline.good" "$root8/ci/abi/5.x-baseline.txt"
rc=$(run "$root8" --check build)
check "a moved SONAME is drift" 1 "$rc"
says "a moved SONAME is drift" "SONAME=$LIB.6"

# --- case 9: the probe is gone. The layout section must not silently vanish.
root9="$(stub no-probe)"
command cp -f "$WORK/baseline.good" "$root9/ci/abi/5.x-baseline.txt"
rm -f "$root9/build/client/qt/$PROBE"
rc=$(run "$root9" --check build)
check "a library without its layout probe cannot be judged" 2 "$rc"
says "a library without its layout probe cannot be judged" "layout probe"

# --- case 10: a member moves, the symbols do not.
root10="$(stub layout-moved)"
command cp -f "$WORK/baseline.good" "$root10/ci/abi/5.x-baseline.txt"
probe "$root10" "${LAYOUT_GOOD/b@8/b@16}"
rc=$(run "$root10" --check build)
check "a layout change with identical symbols is drift" 1 "$rc"
says "a layout change with identical symbols is drift" "b@16"

# --- case 11: the re-exported wire function is recorded, and only that one.
if ! grep -q 'LibreSCRS::Agent::Wire::syncErrorName(' "$WORK/baseline.good" \
        || grep -q 'notReExported\|selftestVendoredCName' "$WORK/baseline.good"; then
    printf 'FAIL  %-58s\n' "only the re-exported wire function is recorded"
    fails=$((fails + 1))
else
    printf 'ok    %-58s\n' "only the re-exported wire function is recorded"
fi
root11="$(stub wire-lost "${SRC_FULL/int syncErrorName(int x) \{ return x; \}/}")"
command cp -f "$WORK/baseline.good" "$root11/ci/abi/5.x-baseline.txt"
rc=$(run "$root11" --check build)
check "losing the re-exported wire function is drift" 1 "$rc"
says "losing the re-exported wire function is drift" "syncErrorName"

# --- case 12: churn outside the recorded namespaces is not drift.
root12="$(stub foreign-churn "${SRC_FULL/int notReExported(int x) \{ return x * 2; \}/int notReExported(long x) { return int(x); }}")"
command cp -f "$WORK/baseline.good" "$root12/ci/abi/5.x-baseline.txt"
rc=$(run "$root12" --check build)
check "churn outside the recorded namespaces is not drift" 0 "$rc"

# --- case 13: two real library files make the source of the snapshot ambiguous.
root13="$(stub two-libs)"
command cp -f "$WORK/baseline.good" "$root13/ci/abi/5.x-baseline.txt"
mkdir -p "$root13/build/stale"
command cp -f "$root13/build/$LIB.5.0.0" "$root13/build/stale/$LIB.5.0.0"
rc=$(run "$root13" --check build)
check "two real library files cannot be judged" 2 "$rc"
says "two real library files cannot be judged" "Ambiguous"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fails" = 0 ]
