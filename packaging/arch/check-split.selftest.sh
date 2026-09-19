#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-split.sh. Three shapes the split gets wrong by hand, plus
# the well-formed case so a check that fails everything cannot pass this.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-split.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fails=0

# Each case gets its own copy of the script next to its own payload dir, so the
# subject reads THAT case's lists rather than the repository's.
setup() {   # setup <case> ; echo the arch dir
    local c=$1
    mkdir -p "$work/$c/packaging/arch" "$work/$c/packaging/payload" "$work/$c/stage"
    cp "$subject" "$work/$c/packaging/arch/check-split.sh"
    chmod +x "$work/$c/packaging/arch/check-split.sh"
}

run() {  # run <name> <expected-rc> <case>
    local name=$1 want=$2 c=$3
    bash "$work/$c/packaging/arch/check-split.sh" "$work/$c/stage" > "$work/$c.out" 2>&1
    local got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-56s rc=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/$c.out"
        fails=$((fails + 1))
    fi
}

stage_files() {  # stage_files <case> <path...>
    local c=$1; shift
    local p
    for p in "$@"; do install -Dm644 /dev/null "$work/$c/stage/$p"; done
}

# case_1 -- a per-configuration export file nobody claims. The main targets
# file picks these up with a glob where an empty match is not an error, so the
# omission is invisible until a consumer links.
c=case_1; setup $c
stage_files $c lib/liba.so lib/cmake/X/XTargets.cmake lib/cmake/X/XTargets-relwithdebinfo.cmake
printf 'lib/liba.so\nlib/cmake/X/XTargets.cmake\n' > "$work/$c/packaging/payload/one.files"
run "case_1 per-configuration export file left uncovered" 1 $c
grep -q 'UNCOVERED lib/cmake/X/XTargets-relwithdebinfo.cmake' "$work/$c.out" \
    && printf '  ok    %-56s\n' "case_1 names the uncovered path" \
    || { printf '  FAIL  %-56s\n' "case_1 names the uncovered path"; fails=$((fails+1)); }

# case_2 -- one path claimed by two packages. pacman reports this as "exists in
# filesystem" and refuses, but only once both are installed together.
c=case_2; setup $c
stage_files $c lib/liba.so include/x.h
printf 'lib/liba.so\ninclude/x.h\n' > "$work/$c/packaging/payload/one.files"
printf 'include/x.h\n'              > "$work/$c/packaging/payload/two.files"
run "case_2 a path claimed by two packages" 1 $c
grep -q 'SHARED    include/x.h' "$work/$c.out" \
    && printf '  ok    %-56s\n' "case_2 names the shared path" \
    || { printf '  FAIL  %-56s\n' "case_2 names the shared path"; fails=$((fails+1)); }

# case_3 -- a pattern that matches nothing. A rename must fail loudly rather
# than leave a satisfied-looking line behind.
c=case_3; setup $c
stage_files $c lib/liba.so
printf 'lib/liba.so\nshare/locale/*/LC_MESSAGES/renamed.mo\n' > "$work/$c/packaging/payload/one.files"
run "case_3 pattern matching nothing" 1 $c
grep -q "MISSING   one.files: 'share/locale/\*/LC_MESSAGES/renamed.mo'" "$work/$c.out" \
    && printf '  ok    %-56s\n' "case_3 names the empty pattern" \
    || { printf '  FAIL  %-56s\n' "case_3 names the empty pattern"; fails=$((fails+1)); }

# case_4 -- licences are installed by the recipe from source, not from the
# staged tree, so they must not count as uncovered.
c=case_4; setup $c
stage_files $c lib/liba.so share/licenses/pkg/LICENSE
printf 'lib/liba.so\n' > "$work/$c/packaging/payload/one.files"
run "case_4 licences are excluded from the comparison" 0 $c

# case_5 -- the well-formed split: three lists, complete and disjoint.
c=case_5; setup $c
stage_files $c lib/cmake/X/XConfig.cmake lib/liba.so include/x.h lib/libqt.so
printf 'lib/cmake/X/XConfig.cmake\n' > "$work/$c/packaging/payload/common.files"
printf 'lib/liba.so\ninclude/x.h\n'  > "$work/$c/packaging/payload/core.files"
printf 'lib/libqt.so\n'              > "$work/$c/packaging/payload/client-qt.files"
run "case_5 complete and disjoint" 0 $c
grep -q 'staged 4 / claimed 4 / uncovered 0 / shared 0' "$work/$c.out" \
    && printf '  ok    %-56s\n' "case_5 census is 4/4/0/0" \
    || { printf '  FAIL  %-56s\n' "case_5 census is 4/4/0/0"; fails=$((fails+1)); }

# case_6 -- no payload lists at all is an error, not a pass.
c=case_6; setup $c
stage_files $c lib/liba.so
run "case_6 no payload lists is an error, not a pass" 2 $c

if [ "$fails" -eq 0 ]; then echo "check-split selftest: all cases passed"; exit 0; fi
echo "check-split selftest: $fails case(s) failed"; exit 1
