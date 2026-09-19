#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Prove check-pkcs11-facade.sh still fails when it should.
#
# Five synthetic build trees, five asserted exit codes. Five and not four,
# because exporting NOTHING and exporting TOO MUCH are different failures with
# different causes: too much is a version script that stopped applying, nothing
# at all is a static archive linked by bare name so no member was ever pulled
# in. A check that only knew "not exactly one" would still be right here, but
# the two messages it has to print are what a reader acts on, and only driving
# both proves both exist.
#
# The trees are built with the compiler, not faked with text: the check reads
# a dynamic symbol table and a NEEDED list, and neither can be simulated by a
# file that is not an ELF shared object. The forbidden dependency is a stub
# library built in the scratch tree, so this test needs no sdbus-c++ installed
# and cannot pass merely because one happens to be present.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/check-pkcs11-facade.sh"
[[ -x "$GATE" ]] || { echo "FATAL: $GATE not executable" >&2; exit 2; }

command -v cc >/dev/null 2>&1 || { echo "FATAL: cc not found" >&2; exit 2; }
command -v ar >/dev/null 2>&1 || { echo "FATAL: ar not found" >&2; exit 2; }
command -v ctest >/dev/null 2>&1 || { echo "FATAL: ctest not found" >&2; exit 2; }

# The expected-suite list is read OUT OF THE GATE, never restated here: a
# second copy would drift and this test would then certify a list nobody uses.
mapfile -t WANT < <(awk '/^EXPECTED_TESTS=\(/{f=1;next} f&&/^\)/{exit} f{gsub(/[ \t]/,"");if($0!="")print}' "$GATE")
[[ ${#WANT[@]} -gt 0 ]] || { echo "FATAL: could not read EXPECTED_TESTS from the gate" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-facade-selftest.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fails=0
cases=0
red=0
check() { # <label> <expected-rc> <build-dir>
    local label="$1" want="$2" dir="$3" got
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [[ "$want" != 0 ]]; then red=$((red + 1)); fi
    "$GATE" "$dir" >"$TMP/out.$$" 2>&1
    got=$?
    if [[ "$got" == "$want" ]]; then
        echo "ok    $label (rc=$got)"
    else
        echo "FAIL  $label: expected rc=$want, got rc=$got" >&2
        sed 's/^/        /' "$TMP/out.$$" >&2
        fails=$((fails + 1))
    fi
}

# --- shared scaffolding ----------------------------------------------------

# A test registry listing exactly the suites the gate demands.
write_ctestfile() { # <dir>
    : > "$1/CTestTestfile.cmake"
    local t
    for t in "${WANT[@]}"; do
        printf 'add_test(%s "/bin/true")\n' "$t" >> "$1/CTestTestfile.cmake"
    done
}

# An archive standing in for the facade. Its contents are irrelevant to every
# claim the gate makes -- what matters is that the file is where a build put it.
write_archive() { # <dir>
    echo 'int libreagent_pkcs11_facade_marker(void) { return 0; }' > "$TMP/facade.c"
    cc -c -fPIC -o "$TMP/facade.o" "$TMP/facade.c"
    ar rcs "$1/libLibreAgentPkcs11Facade.a" "$TMP/facade.o"
}

# A module whose exported C_* set is dictated by the caller.
write_module() { # <dir> <extra-link-args...> ; reads $SYMS
    local dir="$1"; shift
    : > "$TMP/mod.c"
    local s
    for s in $SYMS; do
        printf 'int %s(void) { return 0; }\n' "$s" >> "$TMP/mod.c"
    done
    printf 'int internal_helper(void) { return 0; }\n' >> "$TMP/mod.c"
    : > "$TMP/exports.map"
    {
        echo '{'
        echo '  global:'
        for s in $SYMS; do printf '    %s;\n' "$s"; done
        echo '  local: *;'
        echo '};'
    } > "$TMP/exports.map"
    cc -shared -fPIC -o "$dir/librescrs-pkcs11-agent.so" "$TMP/mod.c" \
       -Wl,--version-script="$TMP/exports.map" "$@"
}

# --- 1. an empty tree: absence, not breakage -------------------------------
mkdir -p "$TMP/empty"
write_ctestfile "$TMP/empty"
check "empty tree carries neither archive nor module" 2 "$TMP/empty"

# --- 2. two entry points ---------------------------------------------------
mkdir -p "$TMP/two"
write_ctestfile "$TMP/two"
write_archive "$TMP/two"
SYMS="C_GetFunctionList C_Initialize" write_module "$TMP/two"
check "module exports C_Initialize besides C_GetFunctionList" 1 "$TMP/two"

# --- 3. no entry point at all ----------------------------------------------
mkdir -p "$TMP/none"
write_ctestfile "$TMP/none"
write_archive "$TMP/none"
SYMS="module_local_entry" write_module "$TMP/none"
check "module exports zero C_* symbols (archive never pulled in)" 1 "$TMP/none"

# --- 4. a forbidden dependency ---------------------------------------------
mkdir -p "$TMP/bus"
write_ctestfile "$TMP/bus"
write_archive "$TMP/bus"
echo 'int sdbus_stub(void) { return 0; }' > "$TMP/bus.c"
cc -shared -fPIC -o "$TMP/bus/libsdbus-c++.so.2" "$TMP/bus.c" \
   -Wl,-soname,libsdbus-c++.so.2
SYMS="C_GetFunctionList" write_module "$TMP/bus" \
   -L"$TMP/bus" -l:libsdbus-c++.so.2 -Wl,--no-as-needed
check "module needs libsdbus-c++" 1 "$TMP/bus"

# --- 5. the shape the module is supposed to have ---------------------------
mkdir -p "$TMP/good"
write_ctestfile "$TMP/good"
write_archive "$TMP/good"
SYMS="C_GetFunctionList" write_module "$TMP/good"
check "one entry point, clean NEEDED, every suite registered" 0 "$TMP/good"

# --- 6. the same module with one suite unregistered ------------------------
# Not a sixth "state" of the module: the same healthy module, measured by a
# tree that stopped configuring one of its suites. Without it, claim 4 could be
# deleted from the gate and every case above would still pass.
mkdir -p "$TMP/nosuite"
write_ctestfile "$TMP/nosuite"
sed -i "/${WANT[0]}/d" "$TMP/nosuite/CTestTestfile.cmake"
write_archive "$TMP/nosuite"
SYMS="C_GetFunctionList" write_module "$TMP/nosuite"
check "healthy module, suite ${WANT[0]} not registered" 1 "$TMP/nosuite"

echo "----"
if [[ "$fails" -eq 0 ]]; then
    echo "check-pkcs11-facade selftest: 6/6 ok"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-pkcs11-facade selftest: $fails case(s) FAILED" >&2
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1
