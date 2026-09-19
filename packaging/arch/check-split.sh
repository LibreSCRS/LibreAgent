#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-split.sh <staged-usr-dir>
#
# The three packages built from this recipe must, between them, cover the
# staged install tree exactly once: everything installed is claimed, nothing is
# claimed twice, and nothing is claimed that is not installed.
#
# Coverage matters because two of the things easiest to leave out fail only at
# the CONSUMER, one release later:
#
#   * the per-configuration export files (…Targets-relwithdebinfo.cmake). The
#     main targets file picks them up with a file(GLOB), where an empty match
#     is not an error, so a package missing them installs cleanly and then
#     hands the consumer IMPORTED_LOCATION not set for imported target.
#   * the vendored codec's licence, whose objects are linked into both the core
#     archive and the client library, so it has to travel with both.
#
# Disjointness matters because pacman reports a shared path as "exists in
# filesystem" and refuses the transaction — but only once both packages are
# built and installed together, which is the last place anyone looks.
#
# A pattern that expands to nothing is an error in its own right. Otherwise a
# rename that a glob stops matching passes vacuously, which is exactly how a
# sibling recipe shipped without two of its message catalogues.
#
# Symlinks count as installed files. A shared library ships as three entries —
# libfoo.so.X.Y.Z and the two symlinks that make it linkable and loadable — and
# `find -type f` sees only the first, so a package could ship the real file, no
# SONAME link, and pass a check that never looked.
#
# usr/share/licenses/<pkg>/** is installed by the recipe from source trees
# rather than from the staged install, so it is excluded from the comparison.
set -u

usage() { echo "usage: check-split.sh <staged-usr-dir>" >&2; exit 2; }

[ "$#" -eq 1 ] || usage
stage=$1
[ -d "$stage" ] || { echo "not a directory: $stage" >&2; exit 2; }

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lists_dir="$here/../payload"
shopt -s nullglob
lists=("$lists_dir"/*.files)
shopt -u nullglob
[ "${#lists[@]}" -gt 0 ] || { echo "no *.files under $lists_dir — nothing to compare, and that is not a pass" >&2; exit 2; }

claimed=$(mktemp); installed=$(mktemp); claimed_s=$(mktemp); installed_s=$(mktemp)
trap 'rm -f "$claimed" "$installed" "$claimed_s" "$installed_s"' EXIT
rc=0

for list in "${lists[@]}"; do
    name=$(basename "$list" .files)
    n_list=0
    while IFS= read -r pattern || [ -n "$pattern" ]; do
        case "$pattern" in ''|'#'*) continue;; esac
        n=0
        while IFS= read -r hit; do
            [ -e "$hit" ] || [ -L "$hit" ] || continue
            printf '%s\n' "${hit#"$stage"/}" >> "$claimed"
            n=$((n + 1)); n_list=$((n_list + 1))
        done < <(compgen -G "$stage/$pattern" || true)
        if [ "$n" -eq 0 ]; then
            echo "MISSING   $name.files: '$pattern' matches nothing under $stage"
            rc=1
        fi
    done < "$list"
    printf '  %-28s %s file(s)\n' "$name" "$n_list"
done

find "$stage" \( -type f -o -type l \) | sed "s|^$stage/||" | grep -v '^share/licenses/' > "$installed"
sort -u "$claimed"   > "$claimed_s"
sort -u "$installed" > "$installed_s"

# Coverage: installed but claimed by nobody.
while IFS= read -r orphan; do
    echo "UNCOVERED $orphan  — installed, but no payload list claims it"
    rc=1
done < <(comm -13 "$claimed_s" "$installed_s")

# Disjointness: claimed by more than one package.
while IFS= read -r dup; do
    echo "SHARED    $dup  — claimed by more than one package; pacman would refuse the transaction"
    rc=1
done < <(sort "$claimed" | uniq -d)

printf '  staged %s / claimed %s / uncovered %s / shared %s\n' \
    "$(wc -l < "$installed_s")" "$(wc -l < "$claimed_s")" \
    "$(comm -13 "$claimed_s" "$installed_s" | wc -l)" \
    "$(sort "$claimed" | uniq -d | wc -l)"
exit "$rc"
