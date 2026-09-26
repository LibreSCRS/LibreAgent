#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-recipe.sh. The shapes the recipe (or the tree around it)
# gets wrong, plus the real recipe as a control. One case only applies to a
# repository whose recipe carries a FetchContent pin; where it does not, the
# file says so out loud and counts one case fewer, because a silently dropped
# case is indistinguishable from one that passed.
#
# Each case asserts three things, because two of them are not enough:
#   * the fixture actually differs from the control (a perturbation that
#     changed nothing passes for the wrong reason);
#   * the exit code is non-zero;
#   * the named arm appears in the output. An exit code alone cannot tell a
#     refusal that worked from a refusal that fired on something else.
#
# Every fixture is a throwaway git repository under /var/tmp -- never the
# working tree, and never /tmp, which is RAM on this machine. The fixture's top
# directory carries the name the committed recipe fetches from: arm 1 compares
# that owner segment against the directory it runs in, so a fixture named
# anything else would fail every case for a reason the case is not about.
#
# The commit is made with signing turned off for the invocation: a maintainer
# with commit.gpgSign=true set globally would otherwise be asked for a
# passphrase, and the case would hang on the prompt.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-recipe.sh"
control_recipe="$here/PKGBUILD"
root=$(CDPATH= cd -- "$here/../.." && pwd)
rname=$(sed -nE 's#.*git\+https://github.com/LibreSCRS/([A-Za-z0-9_-]+)\.git.*#\1#p' "$control_recipe" | head -1)
[ -n "$rname" ] || { echo "FATAL: the committed recipe fetches no LibreSCRS repository by git -- nothing to name the fixtures after" >&2; exit 2; }
command -v gpg >/dev/null 2>&1 || { echo "FATAL: gpg is not on PATH -- arm 4 cannot be judged" >&2; exit 2; }

work="${TMPDIR_SELFTEST:-/var/tmp/check-recipe-selftest.$$}"
rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

fails=0
cases=0
red=0

fx() { printf '%s/%s/%s\n' "$work" "$1" "$rname"; }

# fixture <name> -> builds $(fx <name>) as a minimal repository
fixture() {
    local c="$1" d
    d=$(fx "$c")
    mkdir -p "$d/packaging/arch" "$d/ci/scripts"
    cp "$control_recipe" "$d/packaging/arch/PKGBUILD"
    cp "$subject"        "$d/packaging/arch/check-recipe.sh"
    chmod +x "$d/packaging/arch/check-recipe.sh"
    cp "$root/VERSION"   "$d/VERSION"
    cp "$root/KEYS"      "$d/KEYS"
    mkdir -p "$d/packaging/rpm"
    cp "$root/packaging/rpm/"*.spec "$d/packaging/rpm/"
    [ -f "$root/cmake/FetchQCBOR.cmake" ] && {
        mkdir -p "$d/cmake"
        cp "$root/cmake/FetchQCBOR.cmake" "$d/cmake/"
    }
    git -C "$d" init --quiet
    git -C "$d" add -A >/dev/null 2>&1
    git -C "$d" -c user.name=selftest -c user.email=selftest@invalid \
        -c commit.gpgsign=false \
        commit --quiet -m fixture >/dev/null 2>&1
}

run() {  # run <name> ; sets $out and $rc
    out=$(cd "$(fx "$1")" && bash packaging/arch/check-recipe.sh 2>&1)
    rc=$?
}

expect_red() {  # expect_red <name> <substring>
    local c="$1" want="$2" d
    d=$(fx "$c")
    cases=$((cases + 1))
    # every case here is a perturbation: a red one is the proof.
    red=$((red + 1))
    if cmp -s "$d/packaging/arch/PKGBUILD" "$control_recipe" \
       && cmp -s "$d/VERSION" "$root/VERSION" 2>/dev/null; then
        echo "CASE $c: the fixture is identical to the control -- the perturbation changed nothing"
        fails=$((fails + 1)); return
    fi
    run "$c"
    if [ "$rc" -eq 0 ]; then
        echo "CASE $c: expected a non-zero exit, got 0"; fails=$((fails + 1)); return
    fi
    case "$out" in
        *"$want"*) : ;;
        *) echo "CASE $c: exit was non-zero but no line mentions '$want'"
           printf '%s\n' "$out" | sed 's/^/    /'
           fails=$((fails + 1)) ;;
    esac
}

expect_red_out() {  # expect_red_out <name> <substring> -- for perturbations
                    # that touch the tree rather than the recipe text
    local c="$1" want="$2"
    cases=$((cases + 1))
    red=$((red + 1))
    run "$c"
    if [ "$rc" -eq 0 ]; then
        echo "CASE $c: expected a non-zero exit, got 0"
        printf '%s\n' "$out" | sed 's/^/    /'
        fails=$((fails + 1)); return
    fi
    case "$out" in
        *"$want"*) : ;;
        *) echo "CASE $c: exit was non-zero but no line mentions '$want'"
           printf '%s\n' "$out" | sed 's/^/    /'
           fails=$((fails + 1)) ;;
    esac
}


# 1 -- the v-prefixed tag: the shape every recipe carried before the stack
#      settled on unprefixed tags.
fixture v_prefixed_tag
sed -i 's|#tag=\$pkgver?signed|#tag=v$pkgver?signed|' "$(fx v_prefixed_tag)/packaging/arch/PKGBUILD"
expect_red v_prefixed_tag "v-prefixed"

# 2 -- GitHub's auto-generated archive, the shape before the signed tag: it
#      resolves once a tag exists, so nothing at build time would complain;
#      only the gate can say nothing signs those bytes.
fixture auto_archive
sed -i "s|git+https://github.com/LibreSCRS/$rname.git#tag=\$pkgver?signed|https://github.com/LibreSCRS/$rname/archive/refs/tags/\$pkgver.tar.gz|" \
    "$(fx auto_archive)/packaging/arch/PKGBUILD"
expect_red auto_archive "auto-generated archive"

# 3 -- pkgver disagrees with VERSION.
fixture pkgver_drift
sed -i 's/^pkgver=.*/pkgver=4.2.0/' "$(fx pkgver_drift)/packaging/arch/PKGBUILD"
expect_red pkgver_drift "arm2"

# 4 -- VERSION missing entirely. A missing input is a failure, not a skip.
fixture no_version
rm -f "$(fx no_version)/VERSION"
expect_red no_version "arm2"

# 5 -- the vacuum: source=() renamed so the pattern matches nothing.
fixture vacuum_source
sed -i 's/^source=(/sources=(/' "$(fx vacuum_source)/packaging/arch/PKGBUILD"
expect_red vacuum_source "vacuum"

# 6 -- the signature check switched off: the same tag, fetched without
#      ?signed, builds whatever that name points at on the day.
fixture unsigned_tag
sed -i 's|#tag=\$pkgver?signed|#tag=$pkgver|' "$(fx unsigned_tag)/packaging/arch/PKGBUILD"
expect_red unsigned_tag "without ?signed"

# 7 -- the recipe fetches a SIBLING repository. The recipes are near-copies of
#      one another, so this is what a careless copy produces.
fixture sibling_repo
sed -i "s#github.com/LibreSCRS/$rname.git#github.com/LibreSCRS/NotThisRepo.git#" \
    "$(fx sibling_repo)/packaging/arch/PKGBUILD"
expect_red sibling_repo "while this repository is"

# 7b -- a branch instead of the tag.
fixture branch_source
sed -i 's|#tag=\$pkgver?signed|#branch=main|' "$(fx branch_source)/packaging/arch/PKGBUILD"
expect_red branch_source "not the release tag"

# 8 -- a submodule gitlink the recipe does not pin. This is the drift that
#      actually ships a package built from the wrong upstream tree, and it is
#      invisible in the recipe text: the perturbation is in the INDEX.
fixture gitlink_drift
git -C "$(fx gitlink_drift)" update-index --add \
    --cacheinfo 160000,1111111111111111111111111111111111111111,thirdparty/not-pinned \
    >/dev/null 2>&1
if [ -z "$(git -C "$(fx gitlink_drift)" ls-files -s -- thirdparty/not-pinned)" ]; then
    echo "CASE gitlink_drift: the gitlink was not written -- the perturbation changed nothing"
    cases=$((cases + 1)); fails=$((fails + 1))
else
    expect_red_out gitlink_drift "arm3: submodule"
fi

# 9 -- the FetchContent pin drifts from the cmake module the build fetches
#      with. Only applies where the recipe carries one.
if grep -q '^_qcbor_commit=' "$control_recipe"; then
    fixture fetchcontent_drift
    sed -i -E 's/^([[:space:]]*GIT_TAG[[:space:]]+)[0-9a-f]{40}/\12222222222222222222222222222222222222222/' \
        "$(fx fetchcontent_drift)/cmake/FetchQCBOR.cmake"
    if cmp -s "$(fx fetchcontent_drift)/cmake/FetchQCBOR.cmake" "$root/cmake/FetchQCBOR.cmake"; then
        echo "CASE fetchcontent_drift: the pin was not rewritten -- the perturbation changed nothing"
        cases=$((cases + 1)); fails=$((fails + 1))
    else
        expect_red_out fetchcontent_drift "arm3b: QCBOR pin drift"
    fi
else
    echo "CASE fetchcontent_drift: not applicable -- this recipe carries no _qcbor_commit"
fi

# 10 -- the trust anchor drifts: validpgpkeys names a key KEYS does not hold.
fixture foreign_key
sed -i -E "/^validpgpkeys=\(/s/[0-9A-F]{40}/0123456789ABCDEF0123456789ABCDEF01234567/" \
    "$(fx foreign_key)/packaging/arch/PKGBUILD"
expect_red foreign_key "is not the primary key of KEYS"

# 11 -- no validpgpkeys at all: makepkg would accept a tag signed by any key
#       the builder happens to have.
fixture no_validpgpkeys
sed -i '/^validpgpkeys=(/d' "$(fx no_validpgpkeys)/packaging/arch/PKGBUILD"
expect_red no_validpgpkeys "declares no validpgpkeys"

# 12 -- an upstream archive at a fixed commit left at SKIP: its bytes exist,
#       so a missing sum is a missing check, before and after any tag.
fixture archive_skip
sed -i "/^sha256sums=(/,/)/s/'[0-9a-f]\{64\}'/'SKIP'/g" "$(fx archive_skip)/packaging/arch/PKGBUILD"
expect_red archive_skip "not a sha256"

# 13 -- the signed tag given a checksum: makepkg refuses one on a VCS source.
fixture vcs_sum
sed -i "/^sha256sums=(/,/)/s/'SKIP'/'0000000000000000000000000000000000000000000000000000000000000000'/" \
    "$(fx vcs_sum)/packaging/arch/PKGBUILD"
expect_red vcs_sum "requires to be SKIP"

# 14 -- one sum missing: makepkg pairs sums with sources by position.
fixture sum_count
sed -i "/^sha256sums=(/,/)/{/'SKIP'/d}" "$(fx sum_count)/packaging/arch/PKGBUILD"
expect_red sum_count "pairs them by position"

# 15 -- the RPM spec's Version drifts from VERSION.
fixture spec_drift
sed -i -E 's/^(Version:[[:space:]]+).*/\14.2.0/' "$(fx spec_drift)"/packaging/rpm/*.spec
cases=$((cases + 1)); red=$((red + 1))
run spec_drift
case "$rc:$out" in
    0:*) echo "CASE spec_drift: expected a non-zero exit, got 0"; fails=$((fails + 1)) ;;
    *"arm2c: version drift"*) : ;;
    *) echo "CASE spec_drift: exit was non-zero but no line mentions 'arm2c: version drift'"
       printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1)) ;;
esac

# 16 -- control: the real recipe, untouched, must pass, and arm 4 must SAY what
#       it measured. A silent arm is the failure mode this whole file exists for.
fixture control
cases=$((cases + 1))
run control
if [ "$rc" -ne 0 ]; then
    echo "CASE control: the committed recipe does not pass its own gate (rc=$rc)"
    printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1))
fi
case "$out" in
    *"arm4: validpgpkeys is the primary key of KEYS"*"SKIP only for the signed tag"*) : ;;
    *) echo "CASE control: arm 4 said nothing about itself -- a silent arm is a vacuum"
       printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1)) ;;
esac

if [ "$fails" -eq 0 ]; then
    echo "check-recipe selftest: all $cases cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-recipe selftest: $fails of $cases case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1
