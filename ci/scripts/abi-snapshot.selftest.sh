#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.selftest.sh — prove the ABI snapshot can fail, and can refuse.
#
# This gate is the last thing standing between a silently changed public API
# and a release tag, and until this file existed nobody had watched it go red.
# It already refuses an empty section, which is the strong half; what it could
# not see was a host without c++filt, where every pipeline comes back empty and
# the refusal names the archive as broken instead of naming the missing tool.
#
# Every case builds a throwaway repository under /var/tmp (never /tmp, a RAM
# filesystem on the development host) holding a copy of this gate and a stub
# archive named the way CMake names the real one. The stub is the point: a case
# that leaned on this repository's own build tree would measure whatever was
# last built there.
#
# Only the Core section is exercised. The snapshot is section-aware by design —
# a build without Wire or ClientQt is not drift — so one section is enough to
# drive --check, --update and every refusal, and using one keeps the fixture
# free of Qt.
#
# Cases:
#   1  control: --update over the stub tree, then --check          -> 0
#   2  one symbol removed from the baseline                        -> 1
#   3  one exported symbol removed from the archive                -> 1
#   4  an empty build tree, --check                                -> 2
#   5  an empty build tree, --update: refused, baseline untouched   -> 2
#   6  control: the same run under a PATH shim that HAS c++filt    -> 0
#   7  c++filt taken off PATH                                      -> 2
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SUBJECT:-$HERE/abi-snapshot.sh}"
[ -f "$SUBJECT" ] || { echo "FATAL: $SUBJECT is missing" >&2; exit 2; }

# A compiler and an archiver are the only way to get an archive whose exported
# set this file controls. Without them the answer is "I could not measure".
for tool in g++ ar nm c++filt; do
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
        printf 'ok    %-52s rc=%s\n' "$1" "$3"
    else
        printf 'FAIL  %-52s rc=%s want=%s\n' "$1" "$3" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

says() {  # says <label> <text>
    if grep -qF -- "$2" "$WORK/out"; then
        printf 'ok    %-52s says %s\n' "$1" "$2"
    else
        printf 'FAIL  %-52s does not say %s\n' "$1" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

# stub <name> [--without-beta] -> prints the fixture root
stub() {
    # One `local` per name: bash 5.3 does not let the second assignment in a
    # single `local` see the first, and under `set -u` that is an unbound
    # variable rather than an empty one.
    local name="$1"
    local omit="${2:-}"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/ci/abi" "$root/build"
    cp "$SUBJECT" "$root/ci/scripts/abi-snapshot.sh"
    chmod 0755 "$root/ci/scripts/abi-snapshot.sh"
    {
        printf 'namespace LibreSCRS::Agent {\n'
        printf 'int selftestAlpha(int x) { return x + 1; }\n'
        [ -n "$omit" ] || printf 'int selftestBeta(int x) { return x + 2; }\n'
        printf 'int selftestGamma(int x) { return x + 3; }\n'
        printf '}\n'
    } > "$root/stub.cpp"
    g++ -std=c++20 -c -fPIC -o "$root/stub.o" "$root/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not compile the stub" >&2; sed 's/^/        /' "$WORK/gcc.err" >&2; exit 2; }
    ar rcs "$root/build/libLibreAgentCore.a" "$root/stub.o" 2>>"$WORK/gcc.err" \
        || { echo "FATAL: could not archive the stub" >&2; exit 2; }
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
if ! grep -q 'selftestBeta' "$root/ci/abi/5.x-baseline.txt"; then
    echo "FATAL: the fixture's own baseline does not carry the stub symbols" >&2
    exit 2
fi
rc=$(run "$root" --check build)
check "control: --check against what --update wrote" 0 "$rc"
command cp -f "$root/ci/abi/5.x-baseline.txt" "$WORK/baseline.good"

# --- case 2: the baseline loses a symbol -- drift from the recorded side.
root2="$(stub baseline-short)"
run "$root2" --update build >/dev/null
grep -v 'selftestBeta' "$WORK/baseline.good" > "$root2/ci/abi/5.x-baseline.txt"
if cmp -s "$WORK/baseline.good" "$root2/ci/abi/5.x-baseline.txt"; then
    echo "FATAL: the perturbation changed nothing -- it would pass for the wrong reason" >&2
    exit 2
fi
rc=$(run "$root2" --check build)
check "a symbol missing from the baseline is drift" 1 "$rc"
says "a symbol missing from the baseline is drift" "selftestBeta"

# --- case 3: the tree loses a symbol -- drift from the measured side.
root3="$(stub tree-short --without-beta)"
command cp -f "$WORK/baseline.good" "$root3/ci/abi/5.x-baseline.txt"
rc=$(run "$root3" --check build)
check "a symbol missing from the archive is drift" 1 "$rc"
says "a symbol missing from the archive is drift" "selftestBeta"

# --- case 4/5: a tree that exports nothing. This is the one that could disarm
#     the gate for every later run, so --update must refuse and leave the
#     baseline byte-for-byte as it was.
root4="$(stub empty-tree)"
run "$root4" --update build >/dev/null
command cp -f "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"
rm -f "$root4/build/libLibreAgentCore.a"
rc=$(run "$root4" --check build)
check "an empty tree cannot be judged" 2 "$rc"
rc=$(run "$root4" --update build)
check "an empty tree is refused by --update" 2 "$rc"
if cmp -s "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-52s baseline untouched\n' "the refused --update wrote nothing"
else
    printf 'FAIL  %-52s the refused --update overwrote the baseline\n' "the refused --update wrote nothing"
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
run "$root5" --update build >/dev/null
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "control: the PATH shim with c++filt still judges" 0 "$rc"
rm -f "$SHIM/c++filt"
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "c++filt off PATH is 'cannot measure'" 2 "$rc"
says "c++filt off PATH is 'cannot measure'" "c++filt not found on PATH"

# --- a binding class the snapshot has no rule for ---------------------------
# The snapshot records T-binding symbols and declares which classes it
# deliberately does not, because vague-linkage entries are how the object model
# emits a vtable or an inline member and not what the policy calls the public
# API. What that must not do is discard something that IS the ABI: an exported
# data symbol. The plain T-binding clause dropped it without a word.
rootd="$(stub data-symbol)"
run "$rootd" --update build >/dev/null
{
    printf 'namespace LibreSCRS::Agent {\n'
    printf 'int selftestAlpha(int x) { return x + 1; }\n'
    printf 'int selftestBeta(int x) { return x + 2; }\n'
    printf 'int selftestGamma(int x) { return x + 3; }\n'
    printf 'int selftestExportedGlobal = 7;\n'
    printf '}\n'
} > "$rootd/stub.cpp"
g++ -std=c++20 -c -fPIC -o "$rootd/stub.o" "$rootd/stub.cpp" 2>"$WORK/gcc.err" \
    || { echo "FATAL: could not compile the data-symbol stub" >&2; exit 2; }
rm -f "$rootd/build/libLibreAgentCore.a"
ar rcs "$rootd/build/libLibreAgentCore.a" "$rootd/stub.o" 2>>"$WORK/gcc.err" \
    || { echo "FATAL: could not archive the data-symbol stub" >&2; exit 2; }
# The fixture really does carry one, or the case would pass for another reason.
if ! nm -U "$rootd/build/libLibreAgentCore.a" \
        | awk '$2 == "D" || $2 == "B" { found = 1 } END { exit !found }'; then
    echo "FATAL: the fixture carries no data symbol -- nothing to detect" >&2
    exit 2
fi
rc=$(run "$rootd" --check build)
check "an exported data symbol is not dropped in silence" 2 "$rc"
says "an exported data symbol is not dropped in silence" "no rule for"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fails" = 0 ]
