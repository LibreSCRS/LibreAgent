#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# RPC integration smoke: drive the EXTERNAL consumer pkcs11-tool against the
# real module built here, with the socket agent double as the card backend.
# End to end: pkcs11-tool -> dlopen(module) -> AF_UNIX + CBOR -> the double.
#
# The twin of the bus backend's script, and it asserts the same three things,
# because they are claims about the MODULE and the module is now one shared
# core: that a real consumer can enumerate it at all, that the token advertises
# a protected authentication path (the agent prompter is the PIN sink, and
# pkcs11-tool must not collect one itself), and that a private key and a
# certificate are visible.
#
# Args:
#   $1 = path to FakeSocketAgentMain
#   $2 = path to the built module
set -euo pipefail

FAKE_AGENT="$1"
MODULE="$2"

# Self-skip under AddressSanitizer: a stock pkcs11-tool that dlopens an
# ASan-instrumented module aborts with "ASan runtime does not come first in
# initial library list", which no dlopen by an uninstrumented host can satisfy.
# That is a property of this harness, not of the module.
if command -v ldd >/dev/null 2>&1 && ldd "${MODULE}" 2>/dev/null | grep -qiE 'libasan|libclang_rt\.asan'; then
    echo "module is ASan-instrumented; stock pkcs11-tool cannot dlopen it (ASan-not-first); skipping" >&2
    exit 77 # ctest SKIP
fi

PKCS11_TOOL="$(command -v pkcs11-tool || true)"
if [[ -z "${PKCS11_TOOL}" ]]; then
    echo "pkcs11-tool not found; skipping RPC integration smoke" >&2
    exit 77 # ctest SKIP
fi

# Short, and chosen here rather than read back, because the path has to be
# handed to two processes. sun_path is 104 bytes on Darwin, and a path built
# from a build directory plus a test name has overrun it before.
SOCK="${TMPDIR:-/tmp}/lp11-$$.sock"
rm -f "${SOCK}"
export LIBRESCRS_AGENT_SOCK="${SOCK}"

"${FAKE_AGENT}" "${SOCK}" 1 None &
FAKE_PID=$!
cleanup() {
    kill "${FAKE_PID}" 2>/dev/null || true
    wait "${FAKE_PID}" 2>/dev/null || true
    rm -f "${SOCK}"
}
trap cleanup EXIT

# Wait (bounded) for the module to enumerate a token, rather than sleeping a
# guess: a fixed sleep is a race that only shows up on a loaded runner.
ready=0
for _ in $(seq 1 50); do
    if "${PKCS11_TOOL}" --module "${MODULE}" -T 2>/dev/null | grep -qi 'token'; then
        ready=1; break
    fi
    sleep 0.1
done
if [[ "${ready}" -ne 1 ]]; then
    echo "module never enumerated a token via pkcs11-tool" >&2
    exit 1
fi

echo "== pkcs11-tool -L (slots) =="
"${PKCS11_TOOL}" --module "${MODULE}" -L

echo "== pkcs11-tool -T (token info) =="
TINFO="$("${PKCS11_TOOL}" --module "${MODULE}" -T)"
echo "${TINFO}"
echo "${TINFO}" | grep -qiE 'PIN pad present|protected authentication path' \
    || { echo "token did not advertise the protected authentication path flag" >&2; exit 1; }

echo "== pkcs11-tool -O (objects) =="
OBJS="$("${PKCS11_TOOL}" --module "${MODULE}" -O)"
echo "${OBJS}"
echo "${OBJS}" | grep -qi 'Private Key' || { echo "no private key object enumerated" >&2; exit 1; }
echo "${OBJS}" | grep -qiE 'Certificate' || { echo "no certificate object enumerated" >&2; exit 1; }

echo "RPC integration smoke OK"
