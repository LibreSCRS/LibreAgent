#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-cleansing-deleters.selftest.sh — prove the deleter gate can fail, one
# clause at a time, and prove it never reads "cannot judge" as clean.
#
# A minimal green tree is built under /var/tmp and committed to a throwaway git
# repository: the gate reads git ls-files and refuses to run outside a work
# tree, so an uncommitted tree would make every case below exit 2 and a
# selftest asserting only "not 0" would pass having measured nothing. The green
# baseline is asserted as exit 0 exactly. Each perturbation is checked to have
# changed its file before the gate runs, and the file is put back from a copy,
# never through git.
#
# Cases:
#   0  green tree                                          -> 0
#   1  the mirrored deleter back to plain BN_free          -> 1  (clause 1)
#   2  the marker naming its canonical removed             -> 1  (clause 2)
#   3  a function-pointer deleter back to plain BN_free    -> 1  (clause 4)
#   4  a lambda deleter back to plain BN_free              -> 1  (clause 4)
#   5  bare BN_free on public values outside any deleter   -> 0  (not too wide)
#   6  a deleter with plain BN_free in an UNTRACKED file   -> 0  (only git ls-files counts)
#   7  no 'struct BnDeleter' in the mirror at all          -> 2  (cannot judge is not clean)
#   8  the gate run outside any git work tree              -> 2  (never 0)
#   9  a struct deleter whose pointer star is spaced       -> 1  (clause 3, either spelling)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-cleansing-deleters.sh"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /var/tmp/cleansing-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

expect_text() {
    local label="$1" needle="$2" haystack="$3"
    case "$haystack" in
        *"$needle"*) ;;
        *) echo "  case $label: FAIL — output did not say '$needle'"; fail=$((fail + 1)) ;;
    esac
}

# The gate is copied into the fixture so $0-relative resolution lands there.
run() { bash "$1/ci/scripts/check-cleansing-deleters.sh" 2>&1; }

MIRROR_REL="tests/SyntheticMasterList.cpp"
SHAPES_REL="tests/deleter_shapes.cpp"
PUBLIC_REL="tests/RsaPublicKeyTest.cpp"

ROOT="$WORK/green"
mkdir -p "$ROOT/ci/scripts" "$ROOT/$(dirname "$MIRROR_REL")" "$ROOT/$(dirname "$SHAPES_REL")" \
    "$ROOT/$(dirname "$PUBLIC_REL")"
cp "$CHECK" "$ROOT/ci/scripts/check-cleansing-deleters.sh"
chmod +x "$ROOT/ci/scripts/check-cleansing-deleters.sh"

cat > "$ROOT/$MIRROR_REL" <<'MIR'
#include <openssl/bn.h>
#include <memory>
// MIRROR-OF: LibreMiddleware/lib/LibreSCRS/include/LibreSCRS_internal/Crypto/OpenSslPtr.h - this repository is
// middleware-free by design, so the fixture writes its own.
struct BnDeleter
{
    void operator()(BIGNUM* p) const noexcept
    {
        BN_clear_free(p);
    }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
MIR

# The two shapes clause 4 reads, both cleansing here. Without them in the tree,
# clause 4 would be measured by nothing but the absence of a complaint.
cat > "$ROOT/$SHAPES_REL" <<'SHP'
#include <openssl/bn.h>
#include <memory>
std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> adopt(BIGNUM* p)
{
    return {p, &BN_clear_free};
}

auto releaseBignum = [](BIGNUM* q) { BN_clear_free(q); };

// The struct shape with the pointer star spaced the other way. Case 9 flips
// it: without this, clause 3's reach is whatever the formatter happens to
// produce, and a security gate must not rest on another gate's setting.
struct SpacedDeleter
{
    void operator()(BIGNUM *s) const
    {
        BN_clear_free(s);
    }
};
SHP

# Case 5's material: the real test with bare BN_free on a public modulus and
# exponent when this selftest runs beside it, a stand-in of the same shape
# otherwise. Either way the tree must carry a bare BN_free outside a deleter,
# or "stays green" proves nothing about the gate's width.
if [ -f "$REPO_ROOT/$PUBLIC_REL" ]; then
    cp "$REPO_ROOT/$PUBLIC_REL" "$ROOT/$PUBLIC_REL"
else
    cat > "$ROOT/$PUBLIC_REL" <<'PUB'
#include <openssl/bn.h>
void release(BIGNUM* n, BIGNUM* e)
{
    BN_free(n);
    BN_free(e);
}
PUB
fi
bare_public="$(grep -c 'BN_free[[:space:]]*(' "$ROOT/$PUBLIC_REL" || true)"
if [ "${bare_public:-0}" -lt 1 ]; then
    echo "case 5: FAIL — $PUBLIC_REL carries no bare BN_free, so the width case cannot measure"
    fail=$((fail + 1))
fi

git -C "$ROOT" init -q
git -C "$ROOT" config user.email t@t
git -C "$ROOT" config user.name t
git -C "$ROOT" add -A
git -C "$ROOT" -c commit.gpgsign=false commit -qm x

# Keep pristine copies for restoring; restoring goes through cp, never git.
cp "$ROOT/$MIRROR_REL" "$WORK/mirror.bak"
cp "$ROOT/$SHAPES_REL" "$WORK/shapes.bak"

# --- case 0: the green baseline is exit 0 exactly -------------------------
out="$(run "$ROOT")"; rc=$?; check 0 0 $rc
expect_text 0 "check-cleansing-deleters: OK" "$out"

# perturb FILE with a sed expression, and refuse to continue if nothing changed
perturb() {
    local label="$1" file="$2" expr="$3"
    cp "$file" "$WORK/pre.tmp"
    sed -i -e "$expr" "$file"
    if cmp -s "$WORK/pre.tmp" "$file"; then
        echo "case $label: FAIL — perturbation changed nothing in ${file#"$ROOT"/}"
        fail=$((fail + 1))
        return 1
    fi
    return 0
}

# --- case 1: the mirrored deleter back to plain BN_free -------------------
if perturb 1 "$ROOT/$MIRROR_REL" 's/BN_clear_free(p);/BN_free(p);/'; then
    out="$(run "$ROOT")"; rc=$?; check 1 1 $rc
    expect_text 1 "BnDeleter does not call BN_clear_free" "$out"
    expect_text 1 "${MIRROR_REL}-" "$out"     # clause 3 names the file too
fi
cp "$WORK/mirror.bak" "$ROOT/$MIRROR_REL"
out="$(run "$ROOT")"; rc=$?; check "1-restored" 0 $rc

# --- case 2: the marker removed, the body kept ----------------------------
if perturb 2 "$ROOT/$MIRROR_REL" 's/MIRROR-OF/Copied from/'; then
    out="$(run "$ROOT")"; rc=$?; check 2 1 $rc
    expect_text 2 "no longer names" "$out"
fi
cp "$WORK/mirror.bak" "$ROOT/$MIRROR_REL"
out="$(run "$ROOT")"; rc=$?; check "2-restored" 0 $rc

# --- case 3: a function-pointer deleter back to plain BN_free -------------
if perturb 3 "$ROOT/$SHAPES_REL" 's/decltype(&BN_clear_free)/decltype(\&BN_free)/'; then
    out="$(run "$ROOT")"; rc=$?; check 3 1 $rc
    expect_text 3 "released through a plain BN_free deleter" "$out"
    expect_text 3 "${SHAPES_REL}:" "$out"
fi
cp "$WORK/shapes.bak" "$ROOT/$SHAPES_REL"
out="$(run "$ROOT")"; rc=$?; check "3-restored" 0 $rc

# --- case 4: a lambda deleter back to plain BN_free -----------------------
if perturb 4 "$ROOT/$SHAPES_REL" 's/BN_clear_free(q);/BN_free(q);/'; then
    out="$(run "$ROOT")"; rc=$?; check 4 1 $rc
    expect_text 4 "released through a plain BN_free deleter" "$out"
fi
cp "$WORK/shapes.bak" "$ROOT/$SHAPES_REL"
out="$(run "$ROOT")"; rc=$?; check "4-restored" 0 $rc

# --- case 5: bare BN_free outside any deleter stays green -----------------
# The file was committed with the tree, so the gate has seen it in every case
# above; this names the property and asserts it on its own.
out="$(run "$ROOT")"; rc=$?; check 5 0 $rc
case "$out" in
    *"$PUBLIC_REL"*) echo "  case 5: FAIL — the gate named $PUBLIC_REL ($bare_public bare BN_free on public values)"; fail=$((fail + 1)) ;;
esac

# --- case 6: an untracked file is invisible to the gate -------------------
cat > "$ROOT/tests/untracked_deleter.cpp" <<'UNT'
#include <openssl/bn.h>
struct Loose
{
    void operator()(BIGNUM* p) const
    {
        BN_free(p);
    }
};
UNT
out="$(run "$ROOT")"; rc=$?; check 6 0 $rc
rm -f "$ROOT/tests/untracked_deleter.cpp"

# --- case 7: no declaration to judge is exit 2, never 0 -------------------
if perturb 7 "$ROOT/$MIRROR_REL" 's/^struct BnDeleter$/struct BnRelease/'; then
    out="$(run "$ROOT")"; rc=$?; check 7 2 $rc
    expect_text 7 "FATAL" "$out"
fi
cp "$WORK/mirror.bak" "$ROOT/$MIRROR_REL"
out="$(run "$ROOT")"; rc=$?; check "7-restored" 0 $rc

# --- case 8: outside any git work tree is exit 2, never 0 -----------------
NOGIT="$WORK/nogit"
mkdir -p "$NOGIT/ci/scripts" "$NOGIT/$(dirname "$MIRROR_REL")"
cp "$CHECK" "$NOGIT/ci/scripts/check-cleansing-deleters.sh"
cp "$WORK/mirror.bak" "$NOGIT/$MIRROR_REL"
if git -C "$NOGIT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "case 8: FAIL — $NOGIT sits inside a git work tree, so the case cannot measure"
    fail=$((fail + 1))
else
    out="$(run "$NOGIT")"; rc=$?; check 8 2 $rc
    expect_text 8 "not a git work tree" "$out"
fi

# --- case 9: a struct deleter written with a spaced pointer star ----------
if perturb 9 "$ROOT/$SHAPES_REL" 's/BN_clear_free(s);/BN_free(s);/'; then
    out="$(run "$ROOT")"; rc=$?; check 9 1 $rc
    expect_text 9 "released through a plain BN_free deleter" "$out"
    expect_text 9 "${SHAPES_REL}-" "$out"
fi
cp "$WORK/shapes.bak" "$ROOT/$SHAPES_REL"
out="$(run "$ROOT")"; rc=$?; check "9-restored" 0 $rc

echo "selftest: $pass passed, $fail failed"
[ "$fail" = 0 ]
