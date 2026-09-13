#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-cleansing-deleters.sh — the BIGNUM deleters in this repository cleanse.
#
# The master-list fixture carries a marked mirror of the middleware's internal
# BnDeleter, because this repository is middleware-free by design and cannot
# include that header. The canonical one zeroes the limb buffer before handing
# it back: the secrets that made it do so live over there, and the failure this
# gate exists for is a mirror whose body drifts back to a plain BN_free -- two
# deleters agreeing on their name while disagreeing on whether they cleanse,
# with the comment that explained the difference gone.
#
# The registry that knows about the mirror compares declaration names and
# sites, never bodies, so nothing it reports changes when the bodies disagree.
# This gate is the missing half, and it lives here rather than in the
# middleware because the middleware's copy reads its own checkout and cannot
# see this file.
#
# Clauses:
#   1  the mirror calls BN_clear_free
#   2  the marker naming its canonical is still above it
#   3  no deleter written as a struct calls plain BN_free
#   4  nor one written as a function pointer or a lambda
#
# Clauses 3 and 4 are split because a deleter has three shapes and a search for
# one sees neither of the others. Both are scoped to deleters on purpose: a
# bare BN_free on a public value in a test is not this bug, and a gate that
# flagged it would be argued away within a release.
#
# There is no exception file here, because nothing in this repository releases
# a BIGNUM through plain BN_free on purpose. The middleware's copy has one, and
# the shape to copy if that ever changes.
#
# Usage:  ci/scripts/check-cleansing-deleters.sh
# Exit:   0 clean · 1 violation · 2 refusing to judge (never read as a pass)
set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || { echo "FATAL: not a git work tree — this gate reads git ls-files, nothing else" >&2; exit 2; }

MIRROR="tests/SyntheticMasterList.cpp"
CANONICAL="OpenSslPtr.h"
[[ -f "$MIRROR" ]] || { echo "FATAL: $MIRROR not found; nothing was measured" >&2; exit 2; }

fail=0

# --- 1. the mirrored deleter cleanses -------------------------------------
decl="$(grep -n '^struct BnDeleter$' "$MIRROR" | head -n1 | cut -d: -f1)"
[[ -n "$decl" ]] || { echo "FATAL: no 'struct BnDeleter' in $MIRROR; nothing was measured" >&2; exit 2; }

body="$(awk '/^struct BnDeleter$/,/^};$/' "$MIRROR")"
if ! printf '%s\n' "$body" | grep -q 'BN_clear_free'; then
    echo "ERROR: $MIRROR:$decl BnDeleter does not call BN_clear_free." >&2
    echo "       It mirrors the middleware's, which cleanses because PACE key" >&2
    echo "       material exists only as a BIGNUM. A mirror that drifts is what" >&2
    echo "       nothing reported last time." >&2
    fail=1
fi

# --- 2. the marker naming its canonical is still there --------------------
# Looked for in the 10 comment lines directly above the declaration. The call
# and the marker go missing separately: a body that matches by accident, with
# nothing saying which file it must follow, is a mirror only until someone
# tidies it.
start=$(( decl > 10 ? decl - 10 : 1 ))
if ! sed -n "${start},$((decl - 1))p" "$MIRROR" | grep -E '^[[:space:]]*//' \
        | grep -q "MIRROR-OF.*$CANONICAL"; then
    echo "ERROR: $MIRROR:$decl the comment above BnDeleter no longer names" >&2
    echo "       $CANONICAL as its canonical. Without the marker the registry" >&2
    echo "       cannot pair the two, and the next reader has no way to know" >&2
    echo "       this body is not free." >&2
    fail=1
fi

SCRATCH="$(mktemp -d /var/tmp/check-cleansing-deleters.XXXXXX)" || exit 2
trap 'rm -rf "$SCRATCH"' EXIT
git ls-files -z -- '*.c' '*.cc' '*.cpp' '*.cxx' '*.h' '*.hh' '*.hpp' '*.m' '*.mm' > "$SCRATCH/files.z" || exit 2
if [[ ! -s "$SCRATCH/files.z" ]]; then
    echo "FATAL: git ls-files listed no sources at all; nothing was measured" >&2
    exit 2
fi

# --- 3. no BIGNUM deleter written as a member calls plain BN_free ---------
# Six lines after the signature is the whole body of a deleter written in this
# repository's style. The space before the star is tolerated because the
# formatter, not this gate, is what settles it: a security gate that only sees
# the shape another gate happens to enforce is one .clang-format edit away from
# measuring nothing. -H so a batch xargs hands grep a single file still carries
# the path.
hits="$(xargs -0 -r grep -H -n -A6 'operator()(BIGNUM[[:space:]]*\*' < "$SCRATCH/files.z" \
        | grep -E '(^|[^_[:alnum:]])BN_free[[:space:]]*\(' || true)"

# --- 4. nor one written as a function pointer or a lambda -----------------
more="$( { xargs -0 -r grep -H -n -A2 -E 'unique_ptr[[:space:]]*<[[:space:]]*BIGNUM' < "$SCRATCH/files.z" \
              | grep -E '(decltype[[:space:]]*\([[:space:]]*&[[:space:]]*BN_free[[:space:]]*\)|&[[:space:]]*BN_free|,[[:space:]]*BN_free[[:space:]]*[)}])'
            xargs -0 -r grep -H -n -A6 -E '\[[^]]*\][[:space:]]*\([[:space:]]*BIGNUM[[:space:]]*\*' < "$SCRATCH/files.z" \
              | grep -E '(^|[^_[:alnum:]])BN_free[[:space:]]*\('
          } | sort -u)"
if [[ -n "$hits" && -n "$more" ]]; then
    hits="$hits"$'\n'"$more"
elif [[ -n "$more" ]]; then
    hits="$more"
fi

if [[ -n "$hits" ]]; then
    echo "ERROR: a BIGNUM is released through a plain BN_free deleter. One policy" >&2
    echo "       in this tree: a BIGNUM released through a deleter is cleansed" >&2
    echo "       first, whether the deleter is a struct, a function pointer or a" >&2
    echo "       lambda." >&2
    printf '%s\n' "$hits" >&2
    fail=1
fi

[[ "$fail" -eq 0 ]] || exit 1
echo "check-cleansing-deleters: OK (the mirrored BnDeleter cleanses, still names its canonical, and no deleter here releases a BIGNUM through plain BN_free)"
