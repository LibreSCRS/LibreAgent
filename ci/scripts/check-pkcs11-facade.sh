#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-pkcs11-facade.sh -- the PKCS#11 facade is one exported symbol and
# nothing else's dependency.
#
# A module a browser dlopens has exactly two properties worth holding
# mechanically: what a loader can see in it, and what a loader has to find
# before it can open it. Both are properties of the BUILT FILE, so this reads
# the file rather than the CMake rules that produced it.
#
# Four claims, over a build directory:
#   1. the facade archive and the module both exist in that tree;
#   2. the module exports exactly one C_* symbol and it is C_GetFunctionList;
#   3. the module's NEEDED list carries no bus, no crypto, no Qt, no card stack;
#   4. every suite this module is supposed to be measured by is registered.
#
# Claim 4 asks what ctest would RUN, not what its entries are called. Each
# googletest case is its own ctest entry, named after the case, so a binary's
# name is not the name of any entry; what every entry of that binary shares is
# the executable in its command. A suite binary counts as registered when some
# entry's command runs a file of that name -- directly, behind an emulator, or
# as CMake's TEST_EXECUTABLE for its launcher script. An entry that is a script
# rather than a googletest binary is held by its entry name instead.
#
# Claim 2 is a claim about a MECHANISM, not only about visibility. The facade
# is a static archive whose entry point resolves no undefined symbol of the
# module's own objects -- the module defines the client factory, and it is the
# archive that calls it, not the other way round. Without whole-archive
# semantics the linker therefore contributes no member at all, the module
# builds, installs and dlopens, and C_GetFunctionList is simply not in it.
# Exporting nothing and exporting too much are two different failures and both
# have to be caught: zero is as wrong as two.
#
# Exit codes, and the difference between them is the point:
#   0  every claim holds
#   1  the facade is present and broke a claim
#   2  the facade is ABSENT from this build tree, or a tool is missing --
#      nothing was measured. A check that cannot tell absence from health
#      reports success on a build that never happened.
#
#   Usage: check-pkcs11-facade.sh <build-dir>
set -uo pipefail

BUILD="${1:?usage: check-pkcs11-facade.sh <build-dir>}"

# The suites that must exist wherever this module is built. A module whose
# tests silently stopped being registered still passes every symbol claim
# above, so the registry is part of the surface.
#
# EXPECTED_TESTS are googletest binaries, found by the executable their entries
# run; EXPECTED_ENTRIES are ctest entries registered by name with add_test.
EXPECTED_ENTRIES=(
    Pkcs11ToolRpcSocketTest
)
EXPECTED_TESTS=(
    FakeSocketAgentTest
    LoadModuleTest
    ModuleAbiTest
    ObjectModelTest
    RealCardCryptoVerifyTest
    RealCardSmokeTest
    SecurityTest
    SnapshotParityTest
    SocketAgentClientTest
    SocketAgentClientContractTest
)

[[ -d "$BUILD" ]] || { echo "FATAL: not a directory: $BUILD" >&2; exit 2; }

for tool in nm readelf ctest; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FATAL: $tool not found -- nothing measured" >&2; exit 2; }
done

MOD="$(find "$BUILD" -name 'librescrs-pkcs11-agent*.so' -print -quit)"
LIB="$(find "$BUILD" -name 'libLibreAgentPkcs11Facade.a' -print -quit)"
if [[ -z "$MOD" || -z "$LIB" ]]; then
    echo "FATAL: no PKCS#11 facade in $BUILD" >&2
    echo "       want libLibreAgentPkcs11Facade.a + librescrs-pkcs11-agent*.so" >&2
    echo "       (configure with -DLIBREAGENT_BUILD_PKCS11_FACADE=ON)" >&2
    exit 2
fi

rc=0

# --- 1. one entry point, and it is the right one ---------------------------
#
# `nm --dynamic --defined-only` and not the static table: what a loader can
# bind to is the dynamic table, and the static one carries every hidden name
# the version script was supposed to have taken away.
exported="$(nm --dynamic --defined-only "$MOD" 2>/dev/null | awk '{print $3}' | grep '^C_' | sort)"
count="$(printf '%s\n' "$exported" | grep -c . )"
if [[ "$count" -eq 0 ]]; then
    echo "FAIL: $MOD exports NO C_* symbol at all." >&2
    echo "      The module has no entry point: dlopen will succeed and" >&2
    echo "      C_GetFunctionList will not be in it. The facade archive was" >&2
    echo "      almost certainly linked by bare name instead of whole." >&2
    rc=1
elif [[ "$count" -ne 1 ]]; then
    echo "FAIL: $MOD exports $count C_* symbols; exactly one is allowed:" >&2
    printf '        %s\n' $exported >&2
    rc=1
elif [[ "$exported" != "C_GetFunctionList" ]]; then
    echo "FAIL: $MOD exports one C_* symbol but it is '$exported'," >&2
    echo "      not C_GetFunctionList." >&2
    rc=1
fi

# --- 2. nothing a browser would rather not load ----------------------------
needed="$(readelf -d "$MOD" 2>/dev/null | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p')"
if [[ -z "$needed" ]]; then
    echo "FATAL: readelf reported no NEEDED entries for $MOD -- not an ELF" >&2
    echo "       shared object, so nothing was measured." >&2
    exit 2
fi
forbidden=0
while IFS= read -r lib; do
    case "$lib" in
        libsdbus-c++*|libLibreSCRS_*|libcrypto*|libssl*|libQt6*|libQt5*)
            echo "FAIL: $MOD needs $lib" >&2
            forbidden=1
            ;;
    esac
done <<< "$needed"
if [[ "$forbidden" -ne 0 ]]; then
    echo "      The facade is Qt-free, LM-free, OpenSSL-free and bus-free by" >&2
    echo "      contract: a transport backend belongs in the host that links" >&2
    echo "      the module, never in the shared core." >&2
    rc=1
fi

# --- 3. the suites that measure it are registered --------------------------
#
# Redirected, not piped: `$?` after a pipe is the last member's status, and the
# last member here would be `sort`.
ctest --test-dir "$BUILD" -N -V > "$BUILD/.check-pkcs11-facade-tests.txt" 2>&1
if [[ $? -ne 0 ]]; then
    echo "FATAL: ctest -N failed in $BUILD -- the test registry could not be" >&2
    echo "       read, so claim 4 was not measured." >&2
    exit 2
fi
registered="$(sed -nE 's/^ *Test +#[0-9]+: +//p' "$BUILD/.check-pkcs11-facade-tests.txt" | sort)"
# The basename of every token of every test command, with a leading VAR=
# stripped, so `-D TEST_EXECUTABLE=/x/FooTest` yields FooTest. ctest prints the
# program it resolved unquoted and every argument quoted; a program it could
# not find is printed as nothing, so an unbuilt binary is never counted.
executables="$(awk '
    function base(t,    n, parts) { n = split(t, parts, "/"); return parts[n] }
    /^[0-9]+: Test command: / {
        line = $0
        sub(/^[0-9]+: Test command: /, "", line)
        prog = line
        sub(/ ".*$/, "", prog)
        if (prog != "" && prog !~ /^"/) print base(prog)
        while (match(line, /"[^"]*"/)) {
            tok = substr(line, RSTART + 1, RLENGTH - 2)
            line = substr(line, RSTART + RLENGTH)
            sub(/^[A-Z_]+=/, "", tok)
            print base(tok)
        }
    }' "$BUILD/.check-pkcs11-facade-tests.txt" | sort -u)"
if [[ -n "$registered" && -z "$executables" ]]; then
    echo "FATAL: ctest listed tests in $BUILD but no test command could be" >&2
    echo "       read from its verbose listing, so claim 4 was not measured." >&2
    exit 2
fi
missing=0
for want in "${EXPECTED_TESTS[@]}"; do
    printf '%s\n' "$executables" | grep -qxF "$want" || {
        echo "FAIL: suite $want is not registered in $BUILD (no test runs it)" >&2
        missing=1
    }
done
for want in "${EXPECTED_ENTRIES[@]}"; do
    printf '%s\n' "$registered" | grep -qxF "$want" || {
        echo "FAIL: test $want is not registered in $BUILD" >&2
        missing=1
    }
done
if [[ "$missing" -ne 0 ]]; then
    echo "      A module whose suites stopped being configured passes every" >&2
    echo "      symbol claim above and is measured by nothing." >&2
    rc=1
fi

if [[ "$rc" -eq 0 ]]; then
    echo "ok  $(basename "$MOD"): one entry point (C_GetFunctionList), clean NEEDED, $(( ${#EXPECTED_TESTS[@]} + ${#EXPECTED_ENTRIES[@]} )) suites registered"
fi
exit "$rc"
